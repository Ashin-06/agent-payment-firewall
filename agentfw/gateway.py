"""The mediation layer between any agent and the bank's tools.

    agent --tool call--> Gateway --policy + provenance--> Bank
                           |  \\--> approval queue (held calls)
                           \\----> audit log (every decision)

Reads are executed and their output is recorded with a provenance label; untrusted
output is scanned, neutralised and fenced before the model sees it. Writes are
evaluated by the policy engine first.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .approval import ApprovalQueue
from .audit import AuditLog
from .bank import READ_TOOLS, Bank
from .detector import neutralise
from .policy import Action, PolicyEngine, Verdict
from .provenance import Context, Label


@dataclass
class Outcome:
    status: str  # executed | held | denied | error
    output: str  # text returned to the model
    verdict: Verdict | None = None
    approval_id: str | None = None
    raw: object = None


class Gateway:
    def __init__(self, bank: Bank, policy: PolicyEngine | None = None, audit: AuditLog | None = None,
                 approvals: ApprovalQueue | None = None, enforce: bool = True):
        self.bank = bank
        self.policy = policy or PolicyEngine()
        self.audit = audit or AuditLog()
        self.approvals = approvals or ApprovalQueue()
        self.enforce = enforce  # False = passthrough baseline for benchmarking
        self.ctx = Context()

    def user_message(self, text: str) -> None:
        self.ctx.add(text, Label.USER, "customer")
        self.audit.append("user_message", text=text)

    # ----------------------------------------------------------------- calls

    def call(self, tool: str, args: dict) -> Outcome:
        args = dict(args or {})
        if tool in READ_TOOLS:
            return self._read(tool, args)
        verdict = self.policy.evaluate(tool, args, self.ctx, self.bank) if self.enforce else Verdict()
        if verdict.action == Action.DENY:
            self.audit.append("denied", tool=tool, args=args, reasons=verdict.reasons)
            return Outcome("denied", "BLOCKED by the bank's security policy: " + " ".join(verdict.reasons) +
                           " Do not retry or work around this; tell the customer what was blocked and why.", verdict)
        if verdict.action == Action.APPROVE:
            p = self.approvals.submit(tool, args, verdict.reasons)
            self.audit.append("held", tool=tool, args=args, reasons=verdict.reasons, approval_id=p.id)
            return Outcome("held", f"HELD for customer confirmation (request {p.id}): " + " ".join(verdict.reasons) +
                           " Nothing has been sent yet. Tell the customer it is waiting for their approval.", verdict, p.id)
        return self._execute(tool, args, verdict)

    def execute_approved(self, approval_id: str) -> Outcome:
        p = self.approvals.get(approval_id)
        if p is None:
            raise KeyError(approval_id)
        self.approvals.consume(approval_id, p.tool, p.args)
        return self._execute(p.tool, p.args, Verdict(Action.ALLOW, [f"approved by {p.decided_by}"]))

    def _execute(self, tool: str, args: dict, verdict: Verdict) -> Outcome:
        try:
            result = getattr(self.bank, tool)(**args)
        except (KeyError, ValueError, TypeError) as e:
            self.audit.append("error", tool=tool, args=args, error=str(e))
            return Outcome("error", f"ERROR: {e}", verdict)
        self.audit.append("executed", tool=tool, args=args, result=result, reasons=verdict.reasons)
        self.ctx.add(json.dumps(result), Label.BANK, tool)
        return Outcome("executed", json.dumps(result), verdict, raw=result)

    def _read(self, tool: str, args: dict) -> Outcome:
        try:
            result = getattr(self.bank, tool)(**args)
        except (KeyError, ValueError, TypeError) as e:
            return Outcome("error", f"ERROR: {e}")
        if tool == "read_document":
            source = f"document:{args.get('doc_id')}"
            text, s = neutralise(result, source) if self.enforce else (result, None)
            self.ctx.add(s.clean_text if s else result, Label.UNTRUSTED, source, s.score if s else 0.0)
            self.audit.append("read", tool=tool, args=args, source=source,
                              injection_score=s.score if s else None, findings=[f.kind for f in s.findings] if s else None)
            return Outcome("executed", text, raw=result)
        if tool == "get_statement":
            # memo fields are written by counterparties: untrusted
            for row in result:
                if row["memo"]:
                    if self.enforce:
                        _, s = neutralise(row["memo"], f"memo from {row['counterparty']}")
                        self.ctx.add(s.clean_text, Label.UNTRUSTED, f"memo from {row['counterparty']}", s.score)
                        if s.findings:
                            row["memo"] = f"[memo withheld: suspicious content ({', '.join(f.kind for f in s.findings)})]"
                    else:
                        self.ctx.add(row["memo"], Label.UNTRUSTED, f"memo from {row['counterparty']}")
            bank_view = [{k: v for k, v in r.items() if k != "memo"} for r in result]
            self.ctx.add(json.dumps(bank_view), Label.BANK, tool)
        else:
            self.ctx.add(json.dumps(result), Label.BANK, tool)
        self.audit.append("read", tool=tool, args=args)
        return Outcome("executed", json.dumps(result), raw=result)
