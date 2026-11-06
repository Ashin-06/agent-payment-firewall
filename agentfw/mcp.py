"""The firewall as an MCP server, so any MCP-capable assistant can be put behind it.

    python -m agentfw mcp        # JSON-RPC over stdin and stdout, one message per line

The model's only route in is `tools/call`. What the customer says, and their approvals, must not be
reachable that way, or an injected model could authorise itself. So they are separate methods that
only the host program can send, down the pipe it holds:

    agentfw/customer_message {"text": ...}         what the customer actually typed
    agentfw/approve          {"id": ..., "approve": true, "by": ...}
    agentfw/undo             {"id": ...}
    agentfw/reconcile        {"by": ...}

They are not listed as tools, and calling one as a tool is refused. The host must send these itself
and must never let the model choose a method name.

`AGENTFW_BANK=package.module:factory` swaps the sandbox bank for your adapter.
"""
from __future__ import annotations

import importlib
import json
import logging
import os
import sys
import time

from . import db, ops
from .approval import ApprovalQueue
from .audit import AuditLog
from .bank import TOOL_SPECS, Bank
from .gateway import Gateway

VERSION = "2025-06-18"
TOOLS = [{"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]} for t in TOOL_SPECS]


def _bank() -> Bank:
    target = os.environ.get("AGENTFW_BANK")
    if not target:
        return Bank.demo()
    module, _, factory = target.partition(":")
    return getattr(importlib.import_module(module), factory)()


def handle(gw: Gateway, method: str, params: dict) -> dict:
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", VERSION), "capabilities": {"tools": {}},
                "serverInfo": {"name": "agent-payment-firewall", "version": "1.5.0"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        out = gw.call(params.get("name"), params.get("arguments") or {})
        return {"content": [{"type": "text", "text": out.output}], "isError": out.status in ("denied", "error", "unknown"),
                "structuredContent": {"status": out.status, "request": out.approval_id, "halted": gw.halted}}
    if method == "agentfw/customer_message":
        gw.user_message(str(params["text"]))
        return {"ok": True}
    if method == "agentfw/approve":
        gw.approvals.decide(str(params["id"]), bool(params["approve"]), str(params.get("by", "customer")))
        if not params["approve"]:
            return {"status": "denied"}
        out = gw.execute_approved(str(params["id"]))
        return {"status": out.status, "output": out.output}
    if method == "agentfw/undo":
        return {"undone": gw.undo(str(params["id"]), str(params.get("by", "customer")))}
    if method == "agentfw/reconcile":
        gw.reconcile(str(params.get("by", "customer")))
        return {"frozen": None}
    raise LookupError("no such method")


def keep_time(gw: Gateway, started: float, at: float) -> None:
    """A bank object's clock doesn't run by itself, and undo windows and lapsed requests depend on it."""
    gw.bank.now = at + time.time() - started
    gw.settle_due()


def serve(gw: Gateway, lines, write) -> None:
    started, at = time.time(), gw.bank.now
    for line in lines:
        keep_time(gw, started, at)
        try:
            msg = json.loads(line)
        except (ValueError, RecursionError):
            write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        if not isinstance(msg, dict) or "id" not in msg:
            continue  # notifications need no reply
        reply = {"jsonrpc": "2.0", "id": msg["id"]}
        params = msg.get("params") or {}
        try:
            if not isinstance(params, dict):
                raise TypeError("params must be an object")
            reply["result"] = handle(gw, str(msg.get("method")), params)
        except KeyError as e:
            reply["error"] = {"code": -32602, "message": f"missing or unknown: {str(e)[:100]}"}
        except LookupError:
            reply["error"] = {"code": -32601, "message": "method not found"}
        except (ValueError, TypeError, PermissionError) as e:
            reply["error"] = {"code": -32602, "message": str(e)[:200]}
        except Exception:  # one bad message must not take the firewall down
            logging.getLogger("agentfw.mcp").exception("request failed")
            reply["error"] = {"code": -32603, "message": "internal error"}
        write(reply)


def main() -> None:
    settings = ops.load_settings()
    store = db.connect(settings.database_url)
    audit = AuditLog(store, key=settings.secret["AUDIT_KEY"], previous_keys=settings.previous["AUDIT_KEY"])
    gw = Gateway(_bank(), audit=audit, approvals=ApprovalQueue(store))
    gw.frozen = audit.unresolved()
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")

    def write(obj: dict) -> None:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    serve(gw, sys.stdin, write)
