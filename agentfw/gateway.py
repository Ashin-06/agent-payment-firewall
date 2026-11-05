"""The mediation layer between any agent and the bank's tools.

    agent --tool call--> Gateway --arguments + policy + provenance + mandate--> Bank
                           |  \\--> approval queue (held calls)
                           \\----> audit log (every decision)

Reads are executed and their output is recorded with a provenance label; untrusted
output is scanned, neutralised and fenced before the model sees it. Writes are
evaluated by the policy engine first.

Failure means stop. A call that can't be decided is refused; a payment that can't be recorded
is not sent; and if the bank fails in a way that leaves the outcome unknown, money movement
freezes until a person has checked the account, because the assistant's natural next move is to
retry, and a retried payment that had in fact gone through is a double payment nobody can recall.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass

from .approval import ApprovalQueue, Pending, call_hash
from .audit import AuditLog
from .bank import READ_TOOLS, TOOL_SPECS, Bank
from .detector import fence, neutralise, scan
from .policy import Action, PolicyEngine, Verdict
from .provenance import IBAN_RE, IFSC_RE, Context, Label, canon, normalise_account

log = logging.getLogger("agentfw.gateway")
SPECS = {t["name"]: t["input_schema"] for t in TOOL_SPECS}
MAX_TEXT = 200


class BadArguments(ValueError):
    """The call doesn't match its tool's schema. Nothing about it is trusted any further."""


def validate(tool: str, args: object) -> dict:
    """Checked and canonical arguments, or BadArguments. A number the bank would misread (NaN, a
    string, a boolean, a third of a paisa) never reaches the rules or the money."""
    schema = SPECS[tool]
    if not isinstance(args, dict):
        raise BadArguments("arguments must be an object")
    props, out = schema["properties"], {}
    if set(args) - set(props) or set(schema.get("required", ())) - set(args):
        raise BadArguments(f"{tool} takes exactly {sorted(props)}")
    for key, value in args.items():
        kind = props[key]["type"]
        if kind == "string":
            if not isinstance(value, str) or len(value) > MAX_TEXT:
                raise BadArguments(f"{key} must be text of at most {MAX_TEXT} characters")
            out[key] = canon(value).strip()
        elif isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise BadArguments(f"{key} must be a finite number")
        elif kind == "integer":
            if int(value) != value or not props[key].get("minimum", value) <= value <= props[key].get("maximum", value):
                raise BadArguments(f"{key} is out of range")
            out[key] = int(value)
        else:
            if value <= 0 or round(value, 2) != value:
                raise BadArguments(f"{key} must be positive with at most two decimals")
            out[key] = float(value)
    if tool == "add_payee":
        acct = normalise_account(out["account_number"])
        if not IBAN_RE.fullmatch(acct) and not (acct.isdecimal() and 8 <= len(acct) <= 18 and acct == "".join(c for c in out["account_number"] if c not in " -")):
            raise BadArguments("account_number must be 8 to 18 digits, or an IBAN")
        if not out["name"]:
            raise BadArguments("name must not be empty")
        out["ifsc"] = out["ifsc"].upper()
        if not IBAN_RE.fullmatch(acct) and not IFSC_RE.fullmatch(out["ifsc"]):
            raise BadArguments("ifsc is not a valid IFSC")
    return out


@dataclass
class Outcome:
    status: str  # executed | held | denied | error | unknown
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
        self.frozen: str | None = None  # outcome unknown: no money moves until reconcile()
        self.refused = 0  # refused or held calls since the customer last spoke
        self.held: list[str] = []

    def user_message(self, text: str) -> None:
        self.ctx.add(text, Label.USER, "customer")
        self.audit.append("user_message", text=text)
        self.refused = 0
        suspect = scan(text).score >= self.policy.p["mandate"]["paste_score"]
        names = [p.name for p in self.bank.payees.values()] + list(self.bank.billers)
        if self.ctx.mandates.add(text, self.bank.now, names, suspect):  # "cancel that": held requests go too
            for pid in self.held:
                try:
                    self.approvals.decide(pid, False, "customer cancelled in chat")
                except (KeyError, ValueError):
                    pass  # already decided or expired
            self.held = []

    @property
    def halted(self) -> bool:
        """The assistant should stop and hand back to the customer: more calls will only be refused."""
        return bool(self.frozen) or self.refused >= self.policy.p["breaker"]["max_refused_per_turn"]

    # ----------------------------------------------------------------- calls

    def call(self, tool: str, args: dict) -> Outcome:
        try:
            return self._call(tool, args)
        except Exception as e:  # fail closed: whatever went wrong, nothing has been sent
            log.exception("gateway failure")
            return Outcome("error", f"ERROR: this request could not be processed ({type(e).__name__}); nothing was sent.")

    def _call(self, tool: str, args: dict) -> Outcome:
        if tool not in SPECS:
            if self.enforce:
                self.audit.append("denied", tool=str(tool)[:100], reasons=["not on the allowlist"])
            return Outcome("denied", f"BLOCKED by the bank's security policy: tool {str(tool)[:100]!r} is not on the allowlist.")
        if self.enforce:
            try:
                args = validate(tool, args)
            except BadArguments as e:
                return self._refuse(tool, str(e))
        else:
            args = dict(args or {})
        if tool in READ_TOOLS:
            return self._read(tool, args)
        if self.enforce and self.frozen:
            return self._refuse(tool, f"money movement is frozen: {self.frozen}")
        if self.enforce and self.refused >= self.policy.p["breaker"]["max_refused_per_turn"]:
            return self._refuse(tool, "too many refused requests in a row; stop and ask the customer what they want")
        verdict = self.policy.evaluate(tool, args, self.ctx, self.bank) if self.enforce else Verdict()
        if verdict.action == Action.DENY:
            self.refused += 1
            self.audit.append("denied", tool=tool, args=args, reasons=verdict.reasons)
            return Outcome("denied", "BLOCKED by the bank's security policy: " + " ".join(verdict.reasons) +
                           " Do not retry or work around this; tell the customer what was blocked and why.", verdict)
        if verdict.action == Action.APPROVE:
            return self._hold(tool, args, verdict)
        if verdict.claim:
            verdict.claim.use()
        return self._execute(tool, args, verdict)

    def _refuse(self, tool: str, why: str) -> Outcome:
        self.refused += 1
        self.audit.append("denied", tool=tool, reasons=[why])
        return Outcome("denied", f"BLOCKED by the bank's security policy: {why}. Do not retry; tell the customer.", Verdict(Action.DENY, [why]))

    def _hold(self, tool: str, args: dict, verdict: Verdict) -> Outcome:
        self.refused += 1
        pending = self.approvals.pending()
        same = next((p for p in pending if p.digest == call_hash(tool, args)), None)
        if same is None and len(pending) >= self.policy.p["breaker"]["max_pending_approvals"]:
            return self._refuse(tool, f"{len(pending)} requests are already waiting for the customer")
        p = same or self.approvals.submit(tool, args, verdict.reasons, self.describe(tool, args))
        if verdict.claim:
            verdict.claim.use()
        self.held.append(p.id)
        self.audit.append("held", tool=tool, args=args, reasons=verdict.reasons, approval_id=p.id, summary=p.summary)
        return Outcome("held", f"HELD for customer confirmation (request {p.id}): " + " ".join(verdict.reasons) +
                       " Nothing has been sent yet. Tell the customer it is waiting for their approval.", verdict, p.id)

    def describe(self, tool: str, args: dict) -> str:
        """The call in words, with the real recipient: what the person approving must see."""
        if tool == "transfer":
            p = self.bank.payees.get(str(args.get("payee_id")))
            who = f"{p.name} (account {p.account_number}, IFSC {p.ifsc or 'n/a'})" if p else f"unknown payee {args.get('payee_id')}"
            return f"Send ₹{float(args['amount']):,.2f} to {who}. Memo: {args.get('memo', '')!r}"
        if tool == "pay_bill":
            return f"Pay ₹{float(args['amount']):,.2f} to {args['biller']}, consumer number {args['reference']}"
        if tool == "add_payee":
            return f"Add payee {args['name']}, account {args['account_number']}, IFSC {args['ifsc'] or 'n/a'}"
        return f"{tool} {json.dumps(args, default=str)}"

    def execute_approved(self, approval_id: str) -> Outcome:
        p: Pending | None = self.approvals.get(approval_id)
        if p is None:
            raise KeyError(approval_id)
        problem = self._still_valid(p)
        if problem:
            self.approvals.fail(approval_id)
            self.audit.append("denied", tool=p.tool, args=p.args, approval_id=approval_id, reasons=[problem])
            return Outcome("denied", f"BLOCKED after approval: {problem}", Verdict(Action.DENY, [problem]))
        self.approvals.consume(approval_id, p.tool, p.args)
        return self._execute(p.tool, p.args, Verdict(Action.ALLOW, [f"approved by {p.decided_by}"]))

    def _still_valid(self, p: Pending) -> str | None:
        if not self.enforce:
            return None
        if self.frozen:
            return f"money movement is frozen: {self.frozen}"
        if p.summary and p.summary != self.describe(p.tool, p.args):
            return "the payment no longer matches what was approved"
        v = self.policy.recheck(p.tool, p.args, self.bank)
        return " ".join(v.reasons) if v.action == Action.DENY else None

    def reconcile(self, who: str) -> None:
        """A person has checked the account after an unknown outcome; money may move again."""
        self.audit.append("reconciled", by=who, was=self.frozen)
        self.frozen = None

    def _execute(self, tool: str, args: dict, verdict: Verdict) -> Outcome:
        try:
            self.audit.append("executing", tool=tool, args=args)  # no record, no payment
        except Exception:
            log.exception("audit unavailable; refusing to move money")
            return Outcome("error", "ERROR: the audit log is unavailable, so nothing was sent.", verdict)
        try:
            result = getattr(self.bank, tool)(**args)
        except (KeyError, ValueError, TypeError) as e:  # the bank refused before doing anything
            self.audit.append("error", tool=tool, args=args, error=str(e))
            return Outcome("error", f"ERROR: {e}", verdict)
        except Exception as e:
            self.frozen = f"the bank failed during {tool} ({type(e).__name__}) and the outcome is unknown"
            log.exception("outcome unknown")
            self._note("outcome_unknown", tool=tool, args=args, error=type(e).__name__)
            return Outcome("unknown", f"UNKNOWN OUTCOME: {self.frozen}. Do NOT retry: it may already have gone through. "
                                      "Tell the customer to check their account.", verdict)
        self._note("executed", tool=tool, args=args, result=result, reasons=verdict.reasons)
        self.ctx.add(json.dumps(result), Label.BANK, tool)
        return Outcome("executed", json.dumps(result), verdict, raw=result)

    def _note(self, event: str, **fields) -> None:
        """Record what already happened. The money has moved; if the log fails, stop further movement."""
        try:
            self.audit.append(event, **fields)
        except Exception:
            log.exception("audit unavailable after execution")
            self.frozen = self.frozen or "the audit log failed after a payment, so the record is incomplete"

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
        output = json.dumps(result)
        if tool == "get_statement":
            output = self._statement(result)
        elif tool == "list_documents":
            for doc_id in result:  # file names are chosen by whoever sent the file
                self.ctx.add(doc_id, Label.UNTRUSTED, "document name")
            if self.enforce:
                output = fence(output, "document names")
        else:
            self.ctx.add(output, Label.BANK, tool)
        self.audit.append("read", tool=tool, args=args)
        return Outcome("executed", output, raw=result)

    def _statement(self, rows: list[dict]) -> str:
        """Memos and the names on incoming transfers are written by whoever sent the money."""
        for row in rows:
            fields = ["memo"] + (["counterparty"] if row["kind"] == "credit" else [])
            for key in fields:
                if not row[key]:
                    continue
                source = f"{key} on a statement line"
                if not self.enforce:
                    self.ctx.add(row[key], Label.UNTRUSTED, source)
                    continue
                _, s = neutralise(row[key], source)
                self.ctx.add(s.clean_text, Label.UNTRUSTED, source, s.score)
                if s.findings:
                    row[key] = f"[{key} withheld: suspicious content ({', '.join(f.kind for f in s.findings)})]"
        bank_view = [{k: ("" if k == "counterparty" and r["kind"] == "credit" else v) for k, v in r.items() if k != "memo"} for r in rows]
        self.ctx.add(json.dumps(bank_view), Label.BANK, "get_statement")
        output = json.dumps(rows)
        return fence(output, "statement") if self.enforce else output
