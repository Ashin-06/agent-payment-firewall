"""Human-in-the-loop approvals bound to the exact call.

An approval covers one specific tool call (tool name + canonical arguments). If the
agent later tries to execute something different - another amount, another payee -
the hash will not match and the approval is useless.

Approvals live in the database, so a held payment survives a restart and can be
approved on any replica. Every state change is a conditional UPDATE, so two replicas
cannot both approve, or both execute, the same request.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.engine import Engine

from . import db

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


class ApprovalQueue:
    def __init__(self, engine: Engine | None = None, ttl: float = APPROVAL_TTL_S):
        self.db = engine or db.connect("sqlite://")
        self.ttl = ttl

    def submit(self, tool: str, args: dict, reasons: list[str]) -> Pending:
        p = Pending(f"APR-{secrets.token_hex(4).upper()}", tool, dict(args), list(reasons), call_hash(tool, args))
        with self.db.begin() as c:
            c.execute(text("INSERT INTO approvals (id, tool, args, reasons, digest, created_at, status) "
                           "VALUES (:id, :tool, :args, :reasons, :digest, :created, 'pending')"),
                      {"id": p.id, "tool": tool, "args": json.dumps(p.args, default=str), "reasons": json.dumps(p.reasons),
                       "digest": p.digest, "created": int(p.created)})
        return p

    def get(self, pid: str) -> Pending | None:
        with self.db.connect() as c:
            r = c.execute(text("SELECT id, tool, args, reasons, digest, created_at, status, decided_by FROM approvals "
                               "WHERE id = :id"), {"id": pid}).first()
        return None if r is None else Pending(r[0], r[1], json.loads(r[2]), json.loads(r[3]), r[4], float(r[5]), r[6], r[7])

    def _update(self, sql: str, **params) -> bool:
        """Run one conditional UPDATE; True if it changed the row (nobody got there first)."""
        with self.db.begin() as c:
            return c.execute(text(sql), params).rowcount == 1

    def decide(self, pid: str, approve: bool, who: str) -> Pending:
        p = self.get(pid)
        if p is None:
            raise KeyError(pid)
        if p.status == "pending" and time.time() - p.created > self.ttl:
            self._update("UPDATE approvals SET status = 'expired' WHERE id = :id AND status = 'pending'", id=pid)
            raise ValueError(f"{pid} expired")
        if not self._update("UPDATE approvals SET status = :to, decided_by = :who WHERE id = :id AND status = 'pending'",
                            id=pid, to="approved" if approve else "denied", who=who):
            raise ValueError(f"{pid} is already {self.get(pid).status}")
        return self.get(pid)

    def consume(self, pid: str, tool: str, args: dict) -> Pending:
        """Mark an approved item executed; refuses if the call differs from what was approved."""
        if self._update("UPDATE approvals SET status = 'executed' WHERE id = :id AND status = 'approved' AND digest = :d",
                        id=pid, d=call_hash(tool, args)):
            return self.get(pid)
        p = self.get(pid)
        if p is None or p.status != "approved":
            raise PermissionError("no approved request with that id")
        raise PermissionError("call differs from what the customer approved")

    def pending(self) -> list[Pending]:
        with self.db.connect() as c:
            ids = [r[0] for r in c.execute(text("SELECT id FROM approvals WHERE status = 'pending' ORDER BY created_at, id"))]
        return [p for p in map(self.get, ids) if p]

    def expire_pending(self) -> None:
        """Retire every open request (the demo console's reset); nothing is deleted."""
        with self.db.begin() as c:
            c.execute(text("UPDATE approvals SET status = 'expired' WHERE status = 'pending'"))
