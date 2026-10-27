"""Settings, auth, limits, headers, metrics, health, persistence and migrations."""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from agentfw import db, ops
from agentfw.approval import ApprovalQueue
from agentfw.audit import AuditLog

A32 = base64.b64encode(b"a" * 32).decode()
KEY = "agentfw_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "meera", "role": "customer"}}


def prod_env(**over):
    env = {"AGENTFW_ENV": "production", "AGENTFW_API_KEYS": json.dumps(HASHED), "AGENTFW_AUDIT_KEY": A32,
           "AGENTFW_DATABASE_URL": "sqlite://"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("AGENTFW_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"AGENTFW_{k}", v)
    import agentfw.server as server

    return importlib.reload(server)


def test_production_settings_accepted():
    s = ops.load_settings(prod_env())
    assert s.production and not s.demo and s.secret["AUDIT_KEY"] == b"a" * 32 and not s.ephemeral


@pytest.mark.parametrize("change, message", [
    ({"AGENTFW_API_KEYS": None}, "API keys"),
    ({"AGENTFW_AUDIT_KEY": None}, "AUDIT_KEY"),
    ({"AGENTFW_DATABASE_URL": None}, "DATABASE_URL"),
    ({"AGENTFW_API_KEYS": json.dumps({KEY: {"user": "meera", "role": "customer"}})}, "sha256"),
    ({"AGENTFW_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"AGENTFW_AUDIT_KEY": base64.b64encode(b"short").decode()}, "at least 32"),
    ({"AGENTFW_AUDIT_KEY": "not base64!"}, "base64"),
    ({"AGENTFW_CORS_ORIGINS": "*"}, "CORS"),
    ({"AGENTFW_ENV": "prod"}, "development or production"),
    ({"AGENTFW_DATABASE_URL": "mysql://x"}, "postgresql"),
])
def test_production_refuses_to_start(change, message):
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings(prod_env(**change))


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"AGENTFW_HOST": "0.0.0.0"})
    assert ops.load_settings({"AGENTFW_HOST": "0.0.0.0", "AGENTFW_API_KEYS": json.dumps(HASHED)}).host == "0.0.0.0"
    dev = ops.load_settings({})
    assert dev.demo and dev.ephemeral == ("AUDIT_KEY",) and dev.database_url == "sqlite://"


def test_production_needs_anthropic_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ops.ConfigError, match="ANTHROPIC_API_KEY"):
        boot(monkeypatch, **{k.removeprefix("AGENTFW_"): v for k, v in prod_env().items()})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert boot(monkeypatch, **{k.removeprefix("AGENTFW_"): v for k, v in prod_env().items()}).settings.production
    boot(monkeypatch)


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTFW_")}
    r = subprocess.run([sys.executable, "-m", "agentfw", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_roles_decide_what_a_key_may_do(monkeypatch):
    keys = {"k-cust": {"user": "meera", "role": "customer"}, "k-aud": {"user": "asha", "role": "auditor"},
            "k-mon": {"user": "prom", "role": "monitor"}, "k-adm": {"user": "root", "role": "admin"}}
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(keys)).app)
    assert c.get("/api/state").status_code == 401
    assert c.get("/api/state", headers={"x-api-key": "wrong"}).status_code == 401
    assert c.get("/api/state", headers={"x-api-key": "k-cust"}).status_code == 200
    assert c.get("/api/state", headers={"authorization": "Bearer k-aud"}).status_code == 403
    assert c.get("/api/audit", headers={"x-api-key": "k-cust"}).status_code == 403
    assert c.get("/api/audit", headers={"x-api-key": "k-aud"}).json()["verified"]
    assert c.post("/api/reset", json={"enforce": False}, headers={"x-api-key": "k-cust"}).status_code == 403
    assert c.post("/api/reset", json={"enforce": True}, headers={"x-api-key": "k-adm"}).status_code == 200
    assert c.get("/metrics", headers={"x-api-key": "k-cust"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'http_requests_total{method="GET",route="/api/state",status="200"}' in m.text
    assert "http_request_duration_seconds_bucket" in m.text and "errors_total" in m.text


def test_approver_is_the_key_holder(monkeypatch):
    server = boot(monkeypatch, API_KEYS=json.dumps({"k-cust": {"user": "meera", "role": "customer"}}))
    c = TestClient(server.app)
    gw = server.state["gw"]
    gw.user_message("Pay ₹28,000 rent to my landlord.")
    assert gw.call("transfer", {"payee_id": "P3", "amount": 28000, "memo": "rent"}).status == "held"
    pid = c.get("/api/state", headers={"x-api-key": "k-cust"}).json()["pending"][0]["id"]
    assert c.post(f"/api/approvals/{pid}", json={"approve": True}, headers={"x-api-key": "k-cust"}).json()["status"] == "executed"
    assert server.approvals.get(pid).decided_by == "meera"
    assert server.audit_log.tail(5)[-1]["event"] == "executed"
    assert c.post("/api/approvals/APR-NOPE", json={"approve": True}, headers={"x-api-key": "k-cust"}).status_code == 404


def test_reset_is_refused_in_production(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    keys = json.dumps({f"sha256:{hashlib.sha256(b'k-adm').hexdigest()}": {"user": "root", "role": "admin"}})
    server = boot(monkeypatch, **{k.removeprefix("AGENTFW_"): v for k, v in prod_env(AGENTFW_API_KEYS=keys).items()})
    r = TestClient(server.app).post("/api/reset", json={"enforce": False}, headers={"x-api-key": "k-adm"})
    assert r.status_code == 403 and server.state["enforce"] is True


def test_rate_limit(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.get("/api/state").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    assert int(c.get("/api/state").headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200  # probes are never limited


def test_body_size_cap(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)  # offline replay, no network
    c = TestClient(boot(monkeypatch, MAX_BODY_BYTES="1000").app)
    assert c.post("/api/chat", json={"message": "a" * 2000}).status_code == 413

    def chunks():  # no content-length: the cap still holds
        for _ in range(20):
            yield b"a" * 100

    assert c.post("/api/chat", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    assert c.post("/api/chat", json={"message": "replay a01"}).status_code == 200


def test_headers_and_request_ids(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    r = c.get("/api/state", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == ops.API_CSP and r.headers["cache-control"] == "no-store"
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert len(c.get("/healthz", headers={"x-request-id": "bad id\n"}).headers["x-request-id"]) == 32
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_cors_only_for_listed_origins(monkeypatch):
    c = TestClient(boot(monkeypatch, CORS_ORIGINS="https://app.bank.example").app)
    ok = c.get("/healthz", headers={"origin": "https://app.bank.example"})
    assert ok.headers["access-control-allow-origin"] == "https://app.bank.example"
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_errors_do_not_leak(monkeypatch):
    server = boot(monkeypatch)

    @server.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: account 777700001111222")

    c = TestClient(server.app)
    r = c.get("/boom")
    assert r.status_code == 500 and "7777" not in r.text and r.json()["request_id"] == r.headers["x-request-id"]
    bad = c.post("/api/chat", json={"message": ["777700001111222"]})
    assert bad.status_code == 422 and "7777" not in bad.text


def test_health_and_readiness(monkeypatch):
    server = boot(monkeypatch)
    c = TestClient(server.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": True}
    server.store.dispose()
    monkeypatch.setattr(server.store, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["database"] is False and "db down" not in r.text


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello", extra={"fields": {"n": 1}})
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["n"] == 1 and line["level"] == "INFO"


def _url(tmp_path):
    return os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'state.db'}"


def test_approvals_and_audit_survive_a_restart(tmp_path):
    url, key = _url(tmp_path), b"k" * 32
    q = ApprovalQueue(db.connect(url))
    held = q.submit("transfer", {"payee_id": "P1", "amount": 30000, "memo": "rent"}, ["above approval limit"])
    a = AuditLog(db.connect(url), key=key)
    n = len(a.tail(10_000))
    a.append("held", approval_id=held.id)

    q2 = ApprovalQueue(db.connect(url))  # a new process or replica, same database
    assert held.id in {p.id for p in q2.pending()}
    q2.decide(held.id, True, "meera")
    with pytest.raises(ValueError, match="already approved"):
        ApprovalQueue(db.connect(url)).decide(held.id, False, "ravi")  # the other replica lost the race
    assert q2.consume(held.id, "transfer", {"payee_id": "P1", "amount": 30000, "memo": "rent"}).status == "executed"
    with pytest.raises(PermissionError):
        ApprovalQueue(db.connect(url)).consume(held.id, "transfer", {"payee_id": "P1", "amount": 30000, "memo": "rent"})

    a2 = AuditLog(db.connect(url), key=key)
    assert len(a2.tail(10_000)) == n + 1 and a2.verify()[0]
    assert AuditLog(db.connect(url), key=b"n" * 32, previous_keys=(key,)).verify()[0]  # rotation keeps old entries readable
    assert not AuditLog(db.connect(url), key=b"n" * 32).verify()[0]


def test_expired_approvals_cannot_be_approved(tmp_path):
    q = ApprovalQueue(db.connect(f"sqlite:///{tmp_path / 'ttl.db'}"), ttl=-1)
    p = q.submit("transfer", {"payee_id": "P1", "amount": 30000}, ["big"])
    with pytest.raises(ValueError, match="expired"):
        q.decide(p.id, True, "meera")
    assert q.get(p.id).status == "expired" and not q.pending()


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"]
    assert db.migrate(eng) == []
    with eng.connect() as c:
        assert [r[0] for r in c.execute(text("SELECT version FROM schema_migrations"))] == [1]
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"approvals", "audit_log"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("AGENTFW_")}, "AGENTFW_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "agentfw", "migrate"], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "up to date" in out.stdout
