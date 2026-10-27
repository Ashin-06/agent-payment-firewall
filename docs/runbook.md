# Runbook

How to deploy, configure and operate the firewall console. Commands assume the repository root.

## Deploy

```bash
docker build -t agent-payment-firewall:1.0.0 .
python -m agentfw.ops keygen          # one API key per client, plus the audit key
docker run -d --name agentfw -p 8004:8004 -v agentfw-data:/data \
  -e AGENTFW_KEYS_FILE=/run/secrets/agentfw-keys.json \
  -e AGENTFW_AUDIT_KEY=... -e ANTHROPIC_API_KEY=... \
  agent-payment-firewall:1.0.0
curl -fsS http://127.0.0.1:8004/readyz
```

The image runs in production mode as a non-root user and keeps its SQLite database (approvals
and the audit chain) in the `/data` volume. It refuses to start, and logs why, when anything
required is missing. Terminate TLS in front of it.

For more than one replica, use Postgres (`AGENTFW_DATABASE_URL=postgresql://user:pass@host/db`)
and give every replica the same audit key. Note that each replica has its own demo account and
conversation in memory: until per-customer sessions exist, run one replica.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `agentfw serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `AGENTFW_ENV` | — | `development` (default) or `production` |
| `AGENTFW_API_KEYS` / `AGENTFW_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `customer` (chat, state, approvals), `auditor` (`/api/audit`), `monitor` (`/metrics`), `admin` (all, plus reset outside production) |
| `AGENTFW_AUDIT_KEY` | yes | base64, at least 32 bytes; HMAC key for the audit chain |
| `AGENTFW_DATABASE_URL` | yes | `sqlite:////data/agentfw.db` or `postgresql://...` (default in development: in memory) |
| `ANTHROPIC_API_KEY` | yes | the assistant's credentials; without it (development only) the console can only replay benchmark scenarios |
| `AGENTFW_MODEL` | — | default `claude-opus-5-5` |
| `AGENTFW_HOST`, `AGENTFW_PORT` | — | default `127.0.0.1:8004`; any non-loopback address needs API keys |
| `AGENTFW_RATE_LIMIT` | — | requests per minute per client (default 120) |
| `AGENTFW_MAX_BODY_BYTES` | — | default 64,000 |
| `AGENTFW_CORS_ORIGINS` | — | comma-separated origins allowed to call from a browser; none by default |
| `AGENTFW_LOG_LEVEL` | — | default `INFO` |
| `FORWARDED_ALLOW_IPS` | — | addresses of proxies whose `X-Forwarded-For` is trusted (uvicorn) |

Policy limits live in `policy.toml` (copied into the image); change them there and rebuild.

## Watch

- `GET /healthz`: the process is up (used by the container health check).
- `GET /readyz`: database reachable; 503 otherwise.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `agentfw_decisions_total{decision="executed|held|denied|error|read|user_message|approval_decision"}`.
- Logs are one JSON object per line on stdout, each with a `request_id` that is also returned in
  the `X-Request-ID` response header.
- `GET /api/audit` (role `auditor`): the last 200 entries and whether the whole chain verifies.

Suggested alerts: `/readyz` failing for 2 minutes; `errors_total{kind="unhandled"}` increasing;
5xx share above 1% for 10 minutes; a jump in `decision="denied"` (an attack campaign, or a policy
change that blocks normal customers); `/api/audit` returning `verified: false`.

## Rotate keys

**API keys.** Add the new hash to the key file, restart, give the client the new key, then remove
the old hash and restart again.

**Audit key.** Set `AGENTFW_AUDIT_KEY_PREVIOUS` to the current key and `AGENTFW_AUDIT_KEY` to a
new one, then restart. New entries are signed with the new key; old entries still verify. Keep
old audit keys for as long as you keep the entries they signed.

**Anthropic key.** Replace `ANTHROPIC_API_KEY` and restart.

## Back up and restore

SQLite (in the `/data` volume):

```bash
docker exec agentfw python -c "import sqlite3; s=sqlite3.connect('/data/agentfw.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp agentfw:/data/backup.db ./agentfw-$(date +%F).db
```

Restore: stop the container, copy the backup to `/data/agentfw.db` in the volume, start it, check
`/readyz` and `GET /api/audit` (`verified: true`). Approvals held after the backup are lost; the
customer asks again.

Postgres: `pg_dump` / `pg_restore` as usual. Migrations are applied automatically on start, or with
`python -m agentfw migrate`.

## Incidents

1. **Money moved that the customer didn't intend.** Find the `executed` entry in `/api/audit`
   and the `held` / `approval_decision` entries before it (they carry the approval id and the
   approver). Pull the conversation from the logs by `request_id`. Reverse the payment through
   the bank's normal process, then add the scenario to `agentfw/bench.py` and fix the rule.
2. **Leaked API key.** Remove its hash from the key file and restart. Search the audit trail for
   approvals by that user. Issue a new key.
3. **Leaked audit key.** Entries signed with it can be forged from then on. Rotate without
   `_PREVIOUS` only after exporting a verified copy of the chain; keep the old key with a
   separate custodian to verify that copy.
4. **Audit verification fails.** Stop writes if you can, take a copy of the database, and compare
   with the latest backup to find the first broken entry. Treat it as possible tampering.
5. **Model provider outage.** Chat returns a short "assistant unavailable" reply; held approvals
   can still be decided. Nothing is queued; customers retry.
