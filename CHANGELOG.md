# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.2.0 — 2026-11-06

A second attack round, aimed at the 1.1.0 parser: 21 of 30 new sentences were wrongly read as requests to pay.

### Fixed
- Documents aren't money: "send the ₹5,000 receipt to Mom", "give me the details of..." and "add Rohan to my list" grant no payment.
- A number with no currency sign counts only where an amount can stand, so not "the 5000 word essay" or "flat 9000". Percentages and other currencies don't count.
- A payee after "instead of", "rather than" or "except" isn't authorised.
- A correction ("actually send ₹600") replaces what came before and withdraws held requests.
- A restart no longer clears a freeze. An unreconciled unknown outcome, or a payment with no recorded end, freezes money on start.

### Added
- `python -m agentfw demo`: five attacks side by side, in seconds.
- CI runs the tests on Linux, Windows and macOS, with Python 3.12 and 3.13.

## 1.1.0 — 2026-11-05

Version 1.0.0 stopped all of its own attacks, but 34 of 35 new exploits written against it worked.
Details in [docs/case-study.md](docs/case-study.md).

### Added
- Mandates (`agentfw/mandate.py`): customer messages are parsed by fixed rules into single-use authority
  for a payee, an amount and a number of times. Questions, reports, refusals, cancellations, conditions
  and later dates grant nothing, or need a confirmation.
- `python -m agentfw redteam`: named exploits, randomized attack sessions checked by an independent oracle
  with injected faults, an honest-assistant friction measure, a customer who approves everything, and each
  layer removed in turn. It also runs in CI.
- 13 more attacks and 12 more normal tasks in the benchmark. It now says how each attack was stopped.
- AgentDojo evaluated on every task with every attack (144 pairs).
- Fail-safe behaviour: an unknown bank outcome freezes money until `POST /api/reconcile`; the audit record is
  written before the bank is called; any internal failure refuses the call; the assistant is stopped after 5
  refused or held calls; at most 5 open approvals.
- A Gemini assistant, `list_billers`, `bench --plain-prompt`, and a live benchmark run in `results/`.

### Changed
- A new payee's account the customer never typed is refused, not held, so no approval can reach it.
- The IFSC and the payee's name must also come from the customer's request, or the call is held.
- Approvals show the resolved recipient and are compared with it again at execution. Hard limits are rechecked
  when an approval runs. Expired requests are no longer offered. Saying "cancel that" withdraws held requests.
- Payment amounts, statement sender names and every statement memo are now screened or fenced. The fence uses an
  unguessable tag. Active HTML and URL queries are removed from what the model reads and from its replies.
- `policy.toml` and the console moved inside the package, so a normal `pip install` works.

### Fixed
- `NaN`, strings, booleans, fractions of a paisa and malformed arguments reached the rules or the bank; some crashed the gateway.
- OTPs hidden with zero-width or Cyrillic letters or spaced out, spaced card numbers and encoded account numbers passed the memo check.
- Quiet hours used the server's timezone, so results differed by where they ran.
- Invoice numbers such as `INV-2291` counted as amounts; account numbers followed by another number weren't recognised.
- Two non-Latin payee names were treated as the same name.
- A failed connection to the assistant would have counted as a stopped attack in `bench --live`.

## 1.0.0 — 2026-10-27

### Added
- `pyproject.toml` with an `agentfw` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`).
- Container image: slim Python 3.12 base, non-root user, health check on `/healthz`.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `AGENTFW_*` environment variables, checked at startup. `AGENTFW_ENV=production`
  refuses to start without hashed API keys, `AGENTFW_AUDIT_KEY`, `AGENTFW_DATABASE_URL` and
  `ANTHROPIC_API_KEY`. No built-in secrets in any mode.
- Roles on API keys: `customer` chats and approves held payments, `auditor` reads the audit trail,
  `monitor` scrapes metrics, `admin` does all of it and may reset the demo account. Keys can be
  stored as `sha256:<hex>`; `python -m agentfw.ops keygen` makes new ones.
- Per-client rate limit, request body cap, security headers, CORS only for listed origins.
- JSON logs with request IDs; `/healthz`, `/readyz` and Prometheus `/metrics` with an
  `agentfw_decisions_total` counter.
- Approvals and the audit chain in a database: SQLite by default, Postgres through
  `AGENTFW_DATABASE_URL`, numbered SQL migrations (`python -m agentfw migrate`).
- Audit-key rotation: `AGENTFW_AUDIT_KEY_PREVIOUS` keeps older entries verifiable.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

### Changed
- Held approvals moved from process memory to the `approvals` table. They survive restarts, and
  approving and executing are conditional updates, so two replicas cannot both approve or both
  execute the same request.
- The audit chain moved from memory (or a JSONL file) to the `audit_log` table and is always
  HMAC-keyed. `AGENTFW_AUDIT_KEY` is now base64 of at least 32 bytes.
- The approver recorded on an approval and in the audit trail is the API key's user.
- `/api/reset` needs the `reset` permission and is refused in production (it replaces the account
  and can switch the firewall off). A reset expires approvals that were still pending.
- An unknown approval id returns 404; SDK errors are logged instead of returned to the caller.
- The console sends an API key when the service has keys.
- Without API keys the console refuses to listen on anything but loopback.

### Unchanged
- Policy, provenance, detector and gateway decision logic. `python -m agentfw bench` gives the same
  result as the README (attack success 100% → 0%, no benign task blocked). The AgentDojo and
  injection-detector numbers in `results/real_data.json` were not re-run (the datasets are not on
  this machine) and are unchanged.
