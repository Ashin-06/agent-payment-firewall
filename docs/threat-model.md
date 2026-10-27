# Threat model

What the firewall protects, from whom, and what is still open. Written for the 1.0.0 code; it
has not been reviewed by anyone independent.

## What it protects

| Asset | Where it lives |
|---|---|
| The customer's money: transfers, bill payments, new payees | executed only through `Gateway.call()` |
| Held payments waiting for the customer | `approvals` table, bound to a SHA-256 of the exact call |
| Audit trail of every read, decision, approval and execution | `audit_log` table, HMAC chain |
| Audit key | environment / secret store (`AGENTFW_AUDIT_KEY`) |
| Console API keys | callers hold the key; the service holds only SHA-256 hashes |
| Anthropic credentials | `ANTHROPIC_API_KEY` on the service host only |
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
| Injected instruction redirects a payment to the attacker | Provenance rule: a new payee's account must come from the customer; values from hostile content are refused | Social engineering of the customer (they type the attacker's account themselves) defeats it, as does a pasted account in their own message |
| Injected or inflated amount | Amounts must come from the customer, or from a bill they asked to pay up to a limit; otherwise held | The customer may approve a held payment without reading it |
| Data exfiltration through memos or markdown beacons | Memo rule (OTPs, PINs, account and card numbers), beacons defused before the model sees them | Other side channels in free text the model writes back to the customer |
| Look-alike payees | Confusable skeletons compared with saved payees | Only names the skeleton table covers |
| Approval reused or swapped | Approval bound to tool + canonical arguments, single use, 15-minute expiry; conditional UPDATEs so two replicas can't both approve or execute | A stolen `customer` key can approve anything held |
| Structuring and velocity abuse | Per-payment, daily, per-hour and just-under-threshold limits | Limits are computed on the demo account's ledger; the real ledger must back them |
| Firewall switched off | The reset/enforce toggle needs the `reset` permission and is refused in production | An admin key in development can turn it off (by design, for the demo) |
| Audit trail edited | HMAC chain; editing, deleting in the middle or reordering fails verification | Truncating the newest entries is only caught if the chain head is exported elsewhere |
| Stolen API key | Per-client keys, roles, rate limit per key, the approver's user recorded in the audit | Works until removed from the key list and the service restarts |
| One customer acting on another's account | — | **Not handled**: the console drives one shared demo account. Per-customer sessions from the bank's identity provider are required |
| Oversized or flooding requests | 64 KB body cap, 4,000-character messages, per-client token bucket, at most 12 model turns per message | Per process; put a shared limiter at the ingress |
| Errors leak data | Validation errors carry no input; unhandled errors return only a request ID; SDK errors are logged, not returned | — |
| Misconfigured production start | `AGENTFW_ENV=production` refuses to start without keys, audit key, database and Anthropic credentials; no public bind without keys | Production mode can't check that keys are *good*, only present |

## Not covered

- TLS. Terminate it at your ingress; the service speaks plain HTTP.
- The model provider's handling of what the assistant sends it (customer messages, documents).
- Strong customer authentication for approvals (device binding, an additional factor); the
  console's approve button stands in for the bank app's confirmation screen.
- Durable conversation state: provenance labels are per process, so a restart forgets what the
  customer typed earlier in a conversation (the safe direction: more calls are held or refused).
