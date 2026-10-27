"""Demo console: chat with the assistant, approve held payments, inspect the audit chain.

    python -m agentfw serve            # settings: AGENTFW_* environment variables

The console drives one demo account (`Bank.demo()`). Approvals and the audit chain are in
the database; the account itself and the conversation's provenance labels are in memory.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import db, ops
from .agent import ClaudeAgent
from .approval import ApprovalQueue
from .audit import AuditLog
from .bank import Bank
from .bench import SCENARIOS
from .gateway import Gateway

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("agentfw.server")

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
if settings.production and not os.environ.get("ANTHROPIC_API_KEY"):
    raise ops.ConfigError("production needs ANTHROPIC_API_KEY for the assistant")
store = db.connect(settings.database_url)
audit_log = AuditLog(store, key=settings.secret["AUDIT_KEY"], previous_keys=settings.previous["AUDIT_KEY"])
approvals = ApprovalQueue(store)
app = FastAPI(title="Agent Payment Firewall", version="1.0.0")
ops.install(app, settings, {"database": lambda: store.connect().close()})
_lock = threading.Lock()
state: dict = {}


def reset(enforce: bool = True) -> None:
    bank = Bank.demo()
    # make every scenario's documents available to try live; attack versions load last so a
    # shared id (inv-2291) shows the poisoned invoice the console hint refers to
    for sc in sorted(SCENARIOS, key=lambda s: s.kind != "benign"):
        bank.documents.update(sc.docs)
    gw = Gateway(bank, audit=audit_log, approvals=approvals, enforce=enforce)
    state.update(bank=bank, gw=gw, agent=None, enforce=enforce)


reset()


class ChatIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


class DecisionIn(BaseModel):
    approve: bool


class ResetIn(BaseModel):
    enforce: bool = True


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "console.html")


SCENARIO_ID = re.compile(r"\b([AB]\d{2})\b", re.I)


def offline_reply(message: str) -> dict:
    """Without an API key there is no assistant. The console can still replay one of the
    benchmark scenarios when the message names it explicitly ("replay A01")."""
    from .agent import TraceAgent

    m = SCENARIO_ID.search(message)
    scenario = next((sc for sc in SCENARIOS if m and sc.id == m.group(1).upper()), None)
    if scenario is None:
        ids = ", ".join(sc.id for sc in SCENARIOS)
        raise HTTPException(503, "No ANTHROPIC_API_KEY is set, so the assistant is offline. "
                                 f"Type 'replay <id>' to replay a benchmark scenario instead ({ids}).")
    state["bank"].documents.update(scenario.docs)
    res = TraceAgent(state["gw"]).run(" ".join(scenario.user), scenario.trace)
    return {"reply": f"Replayed scenario {scenario.id} ({scenario.title}) as a compromised assistant would run it. "
                     "See each tool call's decision above.",
            "steps": [s.__dict__ for s in res.steps]}


@app.post("/api/chat")
def chat(body: ChatIn, ident: dict = Depends(ops.require("chat"))):
    with _lock:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return offline_reply(body.message)
        if state["agent"] is None:
            try:
                state["agent"] = ClaudeAgent(state["gw"])
            except Exception as e:  # missing credentials, SDK not installed
                log.warning("assistant unavailable", exc_info=True)
                raise HTTPException(503, "assistant unavailable") from e
        try:
            res = state["agent"].run(body.message)
        except TypeError as e:  # the SDK raises this when no API key / auth token is configured
            state["agent"] = None
            raise HTTPException(503, "assistant unavailable: no Anthropic credentials found (set ANTHROPIC_API_KEY)") from e
    return {"reply": res.text, "steps": [s.__dict__ for s in res.steps]}


@app.get("/api/state")
def get_state(ident: dict = Depends(ops.require("chat"))):
    b, gw = state["bank"], state["gw"]
    return {
        "enforce": state["enforce"],
        "balance": b.get_balance(),
        "payees": b.list_payees(),
        "ledger": b.get_statement(15),
        "documents": b.list_documents(),
        "pending": [{"id": p.id, "tool": p.tool, "args": p.args, "reasons": p.reasons} for p in gw.approvals.pending()],
    }


@app.post("/api/approvals/{pid}")
def decide(pid: str, body: DecisionIn, ident: dict = Depends(ops.require("approve"))):
    gw = state["gw"]
    who = ident["user"] or "customer (console)"
    with _lock:
        try:
            gw.approvals.decide(pid, body.approve, who)
        except KeyError:
            raise HTTPException(404, "no such approval request") from None
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        gw.audit.append("approval_decision", approval_id=pid, approved=body.approve, by=who)
        if not body.approve:
            return {"status": "denied"}
        out = gw.execute_approved(pid)
    return {"status": out.status, "output": out.output}


@app.get("/api/audit")
def audit(ident: dict = Depends(ops.require("audit"))):
    ok, msg = audit_log.verify()
    return {"verified": ok, "message": msg, "entries": audit_log.tail(200)}


@app.post("/api/reset")
def do_reset(body: ResetIn, ident: dict = Depends(ops.require("reset"))):
    if settings.production:  # it replaces the account and can switch the firewall off
        raise HTTPException(403, "reset is disabled in production")
    with _lock:
        approvals.expire_pending()  # holds against the previous demo account can no longer run
        reset(body.enforce)
    return {"ok": True, "enforce": body.enforce}
