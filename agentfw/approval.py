"""Human-in-the-loop approvals bound to the exact call.

An approval covers one specific tool call (tool name + canonical arguments). If the
agent later tries to execute something different - another amount, another payee -
the hash will not match and the approval is useless.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field

APPROVAL_TTL_S = 15 * 60


def call_hash(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Pending:
    id: str
    tool: str
    args: dict
    reasons: list[str]
    digest: str
    created: float = field(default_factory=time.time)
    status: str = "pending"  # pending | approved | denied | executed | expired
    decided_by: str | None = None
    result: dict | None = None


class ApprovalQueue:
    def __init__(self, ttl: float = APPROVAL_TTL_S):
        self.items: dict[str, Pending] = {}
        self.ttl = ttl
        self._lock = threading.Lock()

    def submit(self, tool: str, args: dict, reasons: list[str]) -> Pending:
        with self._lock:
            p = Pending(f"APR-{secrets.token_hex(4).upper()}", tool, dict(args), reasons, call_hash(tool, args))
            self.items[p.id] = p
            return p

    def decide(self, pid: str, approve: bool, who: str) -> Pending:
        with self._lock:
            p = self.items[pid]
            if p.status != "pending":
                raise ValueError(f"{pid} is already {p.status}")
            if time.time() - p.created > self.ttl:
                p.status = "expired"
                raise ValueError(f"{pid} expired")
            p.status, p.decided_by = ("approved" if approve else "denied"), who
            return p

    def consume(self, pid: str, tool: str, args: dict) -> Pending:
        """Mark an approved item executed; refuses if the call differs from what was approved."""
        with self._lock:
            p = self.items.get(pid)
            if p is None or p.status != "approved":
                raise PermissionError("no approved request with that id")
            if call_hash(tool, args) != p.digest:
                raise PermissionError("call differs from what the customer approved")
            p.status = "executed"
            return p

    def pending(self) -> list[Pending]:
        return [p for p in self.items.values() if p.status == "pending"]
