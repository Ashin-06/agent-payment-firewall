"""Demo console: chat with the assistant, approve held payments, inspect the audit chain.

    uvicorn agentfw.server:app --port 8004
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .agent import ClaudeAgent
from .audit import AuditLog
from .bank import Bank
from .bench import SCENARIOS
from .gateway import Gateway

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="Agent Payment Firewall", version="1.0")
_lock = threading.Lock()
state: dict = {}


def reset(enforce: bool = True) -> None:
    bank = Bank.demo()
    for sc in SCENARIOS:  # make every scenario's documents available to try live
        bank.documents.update(sc.docs)
    key = os.environ.get("AGENTFW_AUDIT_KEY")
    gw = Gateway(bank, audit=AuditLog(key=key.encode() if key else None), enforce=enforce)
    state.update(bank=bank, gw=gw, agent=None, enforce=enforce)


reset()


class ChatIn(BaseModel):
    message: str


class DecisionIn(BaseModel):
    approve: bool


class ResetIn(BaseModel):
    enforce: bool = True


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "console.html")


@app.post("/api/chat")
def chat(body: ChatIn):
    with _lock:
        if state["agent"] is None:
            try:
                state["agent"] = ClaudeAgent(state["gw"])
            except Exception as e:  # missing credentials, SDK not installed
                raise HTTPException(503, f"assistant unavailable: {e}") from e
        try:
            res = state["agent"].run(body.message)
        except TypeError as e:  # the SDK raises this when no API key / auth token is configured
            state["agent"] = None
            raise HTTPException(503, "assistant unavailable: no Anthropic credentials found (set ANTHROPIC_API_KEY)") from e
    return {"reply": res.text, "steps": [s.__dict__ for s in res.steps]}


@app.get("/api/state")
def get_state():
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
def decide(pid: str, body: DecisionIn):
    gw = state["gw"]
    with _lock:
        try:
            p = gw.approvals.decide(pid, body.approve, "customer (console)")
        except (KeyError, ValueError) as e:
            raise HTTPException(400, str(e)) from e
        gw.audit.append("approval_decision", approval_id=pid, approved=body.approve)
        if not body.approve:
            return {"status": "denied"}
        out = gw.execute_approved(pid)
    return {"status": out.status, "output": out.output}


@app.get("/api/audit")
def audit():
    ok, msg = state["gw"].audit.verify()
    return {"verified": ok, "message": msg, "entries": state["gw"].audit.entries[-200:]}


@app.post("/api/reset")
def do_reset(body: ResetIn):
    with _lock:
        reset(body.enforce)
    return {"ok": True, "enforce": body.enforce}
