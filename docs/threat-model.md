# Threat model

What the firewall protects, from whom, and what is still open. Written for the 1.3.0 code; it
has not been reviewed by anyone independent.

## What it protects

| Asset | Where it lives |
|---|---|
| The customer's money: transfers, bill payments, new payees | executed only through `Gateway.call()` |
| Held payments waiting for the customer | `approvals` table, bound to a SHA-256 of the exact call |
| Audit trail of every read, decision, approval and execution | `audit_log` table, HMAC chain |
| Audit key | environment / secret store (`AGENTFW_AUDIT_KEY`) |
| Console API keys | callers hold the key; the service holds only SHA-256 hashes |
| Provider credentials | `GOOGLE_API_KEY` or `ANTHROPIC_API_KEY` on the service host only; sent in a header, never a URL |
| What the customer typed (the provenance source of truth) | conversation context in memory; customer messages also in the audit trail |

## Trust boundaries

```
customer ──(TLS at your ingress)──► console API ──► assistant (model provider) ──tool calls──► gateway ──► bank APIs
                                                         ▲                                        │
documents, emails, statement memos (third parties) ──────┘                                        └──► database (approvals, audit)
```

1. **Third-party content → assistant.** Untrusted by design. Anything a stranger wrote can
   steer the model; the gateway assumes the model may be fully compromised.
2. **Assistant → gateway.** Every tool call crosses here. The gateway, not the model, decides
   whether money moves, using where each value came from.
3. **Customer → approvals.** Only an API caller with the `approve` permission can release a held
   call, and only the exact call that was held.
4. **Service → database.** Approvals hold tool arguments (payee ids, amounts, memos); the audit
   trail holds customer messages and results. Treat both as customer data.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| Injected instruction redirects a payment to the attacker | Provenance rule: a new payee's account must have been typed by the customer, otherwise refused outright, with no approval possible | Social engineering of the customer (they type the attacker's account themselves) defeats it. Pasted text is only caught when it looks pasted |
| A mention, question, refusal or old request turned into a payment | Mandates: a payment must match a plain request for this payee at this amount, not yet used, not cancelled, under 30 minutes old | A customer's plain request for a saved payee is honoured once, even if an attacker prompted them to make it |
| One request spent many times, or amounts swapped between payees | Mandates are single-use and pair amounts with payees within a sentence | Unusual sentence structures can pair wrongly within one sentence; the amount and payee were both still typed there |
| Injected or inflated amount | Amounts must be asked for, or come from a bill the customer asked to pay for that payee up to ₹10,000; otherwise held | A poisoned bill can inflate within ₹10,000. The customer may approve a held payment without reading it |
| Data exfiltration through memos or beacons | Memo rule on canonical text (OTPs, PINs, account and card numbers, long numbers, encoded text the customer didn't type); images, active HTML and URL queries removed from what the model reads and writes | Short secrets in plain words, and the amount field as a covert channel |
| Malformed or hostile arguments | Strict schema check before any rule; digits and text made canonical; failures refused | — |
| Bank timeout followed by a retry | Unknown outcome freezes money until a person reconciles | With several replicas, only the one that saw the failure freezes until it restarts. A real adapter should also pass idempotency keys |
| Payment with no record | Audit written before the bank is called; if that fails nothing is sent; if the record after fails, money freezes | A crash between the bank call and the second record leaves an `executing` entry with no result, which freezes money on the next start |
| Assistant keeps trying after being refused | Stops after 5 refused or held calls until the customer speaks; at most 5 open approvals | Per conversation, in memory |
| Approving something other than what is shown | The approver sees the resolved recipient, bound to the approval and compared again at execution; hard limits rechecked | A careless approver can still pay saved payees up to the daily ceiling |
| Look-alike payees | Confusable skeletons compared with saved payees | Only names the skeleton table covers |
| Approval reused or swapped | Approval bound to tool + canonical arguments, single use, 15-minute expiry; conditional UPDATEs so two replicas can't both approve or execute | A stolen `customer` key can approve anything held |
| Structuring and velocity abuse | Per-payment, daily, per-hour and just-under-threshold limits | Limits are computed on the demo account's ledger; the real ledger must back them |
| Firewall switched off | The reset/enforce toggle needs the `reset` permission and is refused in production | An admin key in development can turn it off (by design, for the demo) |
| Audit trail edited | HMAC chain; editing, deleting in the middle or reordering fails verification | Truncating the newest entries is only caught if the chain head is exported elsewhere |
| Stolen API key | Per-client keys, roles, rate limit per key, the approver's user recorded in the audit | Works until removed from the key list and the service restarts |
| One customer acting on another's account | — | **Not handled**: the console drives one shared demo account. Per-customer sessions from the bank's identity provider are required |
| Oversized or flooding requests | 64 KB body cap, 4,000-character messages, per-client token bucket, at most 12 model turns per message | Per process; put a shared limiter at the ingress |
| Errors leak data | Validation errors carry no input; unhandled errors return only a request ID; SDK errors are logged, not returned | — |
| Misconfigured production start | `AGENTFW_ENV=production` refuses to start without keys, audit key, database and provider credentials; no public bind without keys | Production mode can't check that keys are *good*, only present |

## Not covered

- TLS. Terminate it at your ingress; the service speaks plain HTTP.
- The model provider's handling of what the assistant sends it (customer messages, documents).
- Strong customer authentication for approvals (device binding, an additional factor); the
  console's approve button stands in for the bank app's confirmation screen.
- Durable conversation state: provenance labels and mandates are per process, so a restart forgets what the
  customer asked for (the safe direction: more calls are held or refused).
- Languages other than English: the mandate rules don't read them, so every such payment waits for a confirmation.
- A sentence made entirely of listed words but meaning something else. The word list is short to keep this rare, and a test keeps it short.
