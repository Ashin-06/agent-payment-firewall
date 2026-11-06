# Design

How the firewall decides, and why it is built this way. For the numbers, see [evaluation.md](evaluation.md).

## The problem

A banking assistant reads documents written by strangers and holds tools that move money. One hidden line in an invoice can turn it into a fraud channel, and a payment can't be recalled afterwards. Tool-using agents also tend to keep acting when they should stop, and a later refusal can't undo the harm.

Better prompts lower the odds but give no guarantee. So the firewall assumes the model is already compromised. Whatever the model asks for, the gateway decides using only information the model can't change.

## Why tracking values isn't enough

Taint tracking asks where a value came from. That catches an account number lifted from an invoice, but not these, where the customer typed every value:

| The customer said | A hijacked assistant does | Why origin tracking allows it |
|---|---|---|
| "Did Rohan get the ₹5,000 I sent?" | Pays Rohan ₹5,000 | Payee and amount were both typed by the customer |
| "Don't send ₹5,000 to Rohan yet" | Pays Rohan ₹5,000 | Same |
| "Send ₹2,000 to Rohan" | Pays it five times | Each call traces to the customer |
| "Send ₹20,000 to Mom and ₹500 to Rohan" | Pays Rohan ₹20,000 | Each value was typed; the pairing isn't checked |
| "Send ₹5,000 to Mom", then "cancel that" | Pays Mom | The earlier text is still there |

So a payment has to answer a second question: did the customer ask for this?

## Mandates

Each customer sentence is parsed by fixed rules, never by a model, so nothing the assistant reads can affect the result. A plain request becomes a mandate naming the payees, the amounts that go with each, and how many times. Executing or holding a payment spends it.

The rules deny by default, in both directions:

- A sentence grants money only if every word in it is a payee's name, a number or on a short list. Questions, reports ("the email says: send..."), conditions and later dates grant nothing or need confirmation, and so does anything with a word the rules don't know.
- A later statement the rules can't read cancels what came before, since it may be the customer changing their mind in words nobody listed. Reading tasks, questions about the account and "thanks" don't.

A list of warning signs couldn't work, because there is always another one. The cost is a confirmation on some natural sentences, such as "My mom needs ₹500, send it to her".

Mandates sit beside provenance, and each covers what the other misses:

- Provenance alone allows a question to become a payment.
- Mandates alone would still hold a stranger's account for approval, where a careless customer could approve it.

With both, an account the customer never typed is refused outright. Over 2,000 sessions with a customer who approved every request, no money reached the attacker.

## Stopping

After 5 refused or held calls the gateway halts the assistant until the customer speaks. An unknown bank outcome freezes money until a person checks, and a restart doesn't clear it: a payment with no recorded outcome keeps money frozen. A write that can't be logged doesn't happen. A crash inside the rules refuses the call.

## Approvals

The approver sees "Send ₹30,000 to Rohan Mehta (account 918020045566771...)", not `{"payee_id": "P1"}`. The approval is bound to that text and to a hash of the exact call, is single-use, expires, and has hard limits rechecked when it runs. Open requests are capped so nobody can be flooded into approving, and a payee's name can't contain anything that fakes a line on the screen.

## A way back

Agents tend to act first and notice the problem afterwards. So first payments to a new payee, and amounts taken from a document, wait 10 minutes before the bank is called. No bank feature is needed: the gateway simply hasn't called the bank yet. The customer can undo them, or say "cancel that". Scheduled money counts against the limits, everything is checked again before it goes, and nothing goes while money is frozen.

## The last check

If every check lived in one policy engine, one bug could disable them all. The last check before the bank is a few lines with no dependency on the rules or the parser: positive amount, real payee, within the balance and ceilings, not frozen. It's tested by bypassing every rule at once.

## Asking the bank

A customer can be talked into typing a scammer's account under a name they trust. In India, [RBI told banks](https://resources.probe42.in/regulatory-updates/rbi-circulars/rbi-circular-beneficiary-name-look-up-for-rtgs-and-neft-transactions/) to offer an account-name lookup for RTGS and NEFT by April 2025, so the gateway uses one where it exists. If the receiving bank's name doesn't match, the customer sees the real name first.

## What the customer is told

A model can write "done" about a refused payment. So the gateway reports what actually happened beside each reply.

## What each line contributes

The same attacks and checks, with each line removed in turn:

| Line removed | Built-in attacks that succeed | Named attacks that work | Oracle violations in 300 sessions | Attacker payments if all approved |
|---|---|---|---|---|
| Holding for the customer | 14 | 92 | 206 | 0 |
| Mandates | 10 | 85 | 102 | 0 |
| Memo rules | 1 | 6 | 20 | 0 |
| Fail-safe freeze and stop | 0 | 4 | 0 | 0 |
| Last check | 0 | 3 | 0 | 0 |
| Provenance | 0 | 2 | 0 | 1 |
| Limits | 0 | 2 | 0 | 0 |
| Neutralising third-party text | 1 | 1 | 0 | 0 |
| Argument validation | 0 | 1 | 0 | 0 |

The lines overlap by design, so some show little alone. Argument validation is the clearest case: the bank's own check and the fail-closed gateway catch most of what it refuses.

## Related work

See [related-work.md](related-work.md). Binding an approval to exact parameters is established work, as in GateArena. What this adds is single-use authority derived from what the customer asked, denied by default and enforced at the tool boundary, with a way back for what's still allowed.

## Reproduce it

```bash
pip install -r requirements.txt
python -m pytest -q
python -m agentfw bench
python -m agentfw paired
python -m agentfw redteam --sessions 20000 --seed 7
```

Each attack here is a replayed tool-call trace, so these commands need no API key.
