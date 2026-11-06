# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.5.0 — 2026-11-06

### Added
- A later statement the rules can't read cancels an earlier request. Reading tasks, questions about the account and "thanks" don't.
- Ruling out one payee withdraws what is held or scheduled for them.
- Size caps on text, and one decision at a time per gateway.
- `agentfw/attacks.py`: further attacks, run by `python -m agentfw redteam`.

### Changed
- All links are removed from what the model reads and writes.
- Memos the assistant writes itself are held if long, encoded or carrying a link.
- A payee whose name is an ordinary word isn't matched on that word. A payee sharing a word with a biller is ambiguous.
- Amounts with symbols, ranges or unusual grouping grant nothing.
- Payee names may contain only letters, numbers and ordinary name punctuation.
- The open demo refuses requests naming another host or origin.
- The audit log always has a key.

## 1.4.0 — 2026-11-06

### Added
- Undo window: first payments to a new payee and amounts from a document wait 10 minutes before the bank is called, and can be undone or cancelled in chat.
- An independent last check before the bank.
- Account-name check against the receiving bank's record, where the bank can answer.
- Holds for a payment over half the balance or far above what a payee has been paid, and a limit of 2 new payees a day.
- A receipt from the firewall beside each reply.
- MCP server (`python -m agentfw mcp`). Customer messages and approvals are host-only methods.
- `python -m agentfw paired`: should-act and should-abstain pairs.
- An adaptive attacker in the red team.

## 1.3.0 — 2026-11-06

### Changed
- The mandate parser denies by default: a sentence grants money only if every word is a payee's name, a number or on a short list.

## 1.2.0 — 2026-11-06

### Added
- `python -m agentfw demo`.
- CI on Linux, Windows and macOS, with Python 3.12 and 3.13.

### Changed
- A correction ("actually send ₹600") replaces what came before and withdraws held requests.
- A freeze survives a restart.

## 1.1.0 — 2026-11-05

### Added
- Mandates: single-use authority parsed from what the customer asked for.
- `python -m agentfw redteam`: named attacks, randomized sessions checked by an independent oracle, and each line removed in turn.
- Every AgentDojo task evaluated with every attack.
- Fail-safe behaviour: a freeze on unknown bank outcomes, the audit record written before the bank call, and a stop after repeated refusals.
- A Gemini assistant and `list_billers`.

### Changed
- A new payee's account the customer never typed is refused, not held.
- Approvals show the resolved recipient, and hard limits are rechecked when an approval runs.
- `policy.toml` and the console moved inside the package.

## 1.0.0 — 2026-10-27

First release: the gateway, provenance tracking, policy engine, approvals, audit chain, console, benchmark and container image.
