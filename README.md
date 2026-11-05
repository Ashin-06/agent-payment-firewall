# Agent Payment Firewall

[![ci](https://github.com/Ashin-06/agent-payment-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashin-06/agent-payment-firewall/actions/workflows/ci.yml)

A security layer between an LLM banking assistant and the tools that move money. It assumes the assistant will be prompt-injected at some point, and makes sure that when it is, money still can't go anywhere the customer didn't ask for.

A payment can't be undone. A refusal after the money has left is worth nothing, so the decision can't be left to the model. Every tool call goes through a gateway that decides using only what the model can't influence: where each value came from, what the customer actually said, and hard limits. The firewall works the same if the model is fully compromised, and it's tested that way.

![The console: a held payment shows the real recipient and why it was held](docs/console.jpg)

## How it decides

Checking where a value came from isn't enough. A customer who asks "did Rohan get the ₹5,000?" has typed a payee and an amount, but hasn't asked for anything. So a payment needs two answers:

```mermaid
flowchart LR
    A[Assistant asks to pay] --> B{Valid arguments?}
    B -- no --> X[Refused]
    B -- yes --> C{"Where did the account come from?<br/>(provenance)"}
    C -- "a document, or nowhere" --> X
    C -- the customer --> D{"Did the customer ask for this payment?<br/>(mandate)"}
    D -- "no, already used, cancelled, conditional" --> H[Held for the customer]
    D -- yes --> E{Within limits?}
    E -- over a hard limit --> X
    E -- above a threshold --> H
    E -- yes --> F[Logged, then paid]
    H -- "approved, limits rechecked" --> F
```

| Layer | What it does |
|---|---|
| Mandates | Reads each customer message with fixed rules, no model involved, and turns plain requests into single-use authority: this payee, this amount, this many times. Questions, "don't pay", "cancel that", conditions and later dates grant nothing. |
| Provenance | Labels all text as typed by the customer, from bank systems, or from third parties. A new payee's account number must have been typed by the customer. This is a refusal, not a hold, so it survives a customer who approves everything. |
| Limits | Per-payment and daily ceilings, payments per hour, splitting under thresholds, cooling-off for new payees, quiet hours. Rechecked when an approval runs. |
| Approvals | A held call is bound to a hash of its exact arguments and can be used once. The approver sees the resolved recipient, not a payee ID. |
| Fail-safe | Bad arguments are refused. No audit record means no payment. If the bank fails with the outcome unknown, money freezes until a person checks, because the assistant's next move would be a retry. After 5 refusals the assistant is stopped until the customer speaks. |
| Third-party text | Hidden characters revealed, images and data-carrying URLs removed, statement memos and sender names screened, and the text fenced with an unguessable tag. Replies get the same URL filter. This is a second line of defence. |
| Audit | Every read, decision and payment in an HMAC-chained log that shows any edit or deletion. |

Limits and thresholds live in [`agentfw/policy.toml`](agentfw/policy.toml).

## Quick start

Needs Python 3.12 or newer; CI runs it on Linux, Windows and macOS. No API key is needed for anything here except a live assistant.

```bash
pip install -r requirements.txt
python -m agentfw demo              # five attacks side by side, in seconds
python -m pytest -q                 # 137 tests
python -m agentfw bench             # 28 attacks and 22 normal tasks
python -m agentfw redteam --sessions 2000   # exploits, randomized sessions, each layer removed in turn
python -m agentfw serve             # console on http://127.0.0.1:8004; type "replay A16" to watch an attack
```

With `GOOGLE_API_KEY` or `ANTHROPIC_API_KEY` set, `python -m agentfw chat "..."` and the console use a real assistant, and `python -m agentfw bench --live` runs the scenarios through it. To run in a container, see [docs/runbook.md](docs/runbook.md).

## Results

All from a fully compromised assistant, the worst case, unless stated otherwise. Details and how to reproduce them: [docs/evaluation.md](docs/evaluation.md).

| Test | Without firewall | With firewall |
|---|---|---|
| Built-in attacks | 28 of 28 succeed | 0 of 28 (13 refused, 14 held, 1 defused) |
| AgentDojo banking attacks, every task with every attack | not applicable | 0 of 144 pairs executed (136 refused, 8 held) |
| Exploits found by attacking earlier versions | 34 of 35 worked on 1.0, 21 of 30 more on 1.1 | 0 of 84 work |
| 20,000 randomized attack sessions, 25% with injected faults | not applicable | 0 oracle violations, 6,290 authorised payments still made |
| Customer who approves every held request, 2,000 sessions | not applicable | 0 payments reached the attacker |

The randomized sessions are checked by an oracle that shares no code with the policy or the parser: the generator records what each conversation really authorised, and the ledger is compared with that. Removing the mandate layer gives violations in 108 of 300 sessions, which shows the oracle can catch a broken firewall.

With a real model, the assistant was tricked for real. `gemini-3.1-flash-lite` with a plain system prompt carried out 15 of the 28 attacks without the firewall and 0 of 28 with it, and all 22 normal tasks behaved as expected. That is one run on a free-tier quota, made on version 1.1: it shows the attacks work on a current model, not a measured rate.

What it costs: 5,000 of 5,000 plainly worded small requests go through with no friction, and 15 of 20 harder phrasings do. The other 5 wait for a confirmation; none paid the wrong payee or amount. On AgentDojo's normal tasks, the 4 that only read go through. Of the 10 that move money, 8 wait for one confirmation and 2 are refused, and the 2 that change account settings aren't offered. That suite relies on the assistant working out amounts and following documents, which is exactly what this firewall holds back.

## Using it with your own assistant

```python
from agentfw.bank import Bank          # replace with an adapter over your banking APIs
from agentfw.gateway import Gateway

gw = Gateway(Bank.demo())
gw.user_message(customer_text)          # what the customer actually typed: the source of all authority
outcome = gw.call(tool_name, tool_args) # every tool call the model makes
# outcome.status: executed, held, denied, error or unknown. outcome.output goes back to the model.
if gw.halted:
    ...                                 # stop the loop and hand back to the customer
```

To connect real systems, implement the nine bank methods (`get_balance`, `list_payees`, `list_billers`, `get_statement`, `list_documents`, `read_document`, `add_payee`, `transfer`, `pay_bill`) over your APIs.

## Limitations

- If an attacker gets the customer to type their account number, for example during a phone call, the firewall can't tell. Text pasted into the chat is only recognised when it looks pasted: forwarded-mail headers or injection phrasing.
- Held payments are only as good as the person approving them. A customer who approves everything is safe from new accounts, but can still send up to the daily ceiling to saved payees.
- An amount from a bill the customer asked to pay is accepted up to ₹10,000, so a poisoned bill can inflate a payment within that limit.
- The mandate rules read English. Anything else waits for a confirmation, and so does unusual wording. They are hand-written patterns: the second attack round found 21 sentences the first version misread, and there may be more.
- The console runs one demo account on a sandbox bank. A real deployment needs a session per signed-in customer, the bank's own APIs with idempotency keys, and approvals confirmed in the bank's app.
- The red team and the oracle were written by the same author as the firewall, and nobody independent has reviewed it. Zero violations means none were found in those tests, not that none exist.

See [docs/case-study.md](docs/case-study.md), [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See [LICENSE](LICENSE).
