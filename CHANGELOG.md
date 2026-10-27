# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

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
