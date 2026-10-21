"""Policy engine: decides ALLOW / APPROVE (hold for the customer) / DENY for each tool call."""
from __future__ import annotations

import datetime as dt
import re
import tomllib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from .bank import MONEY_TOOLS, READ_TOOLS, Bank
from .provenance import Context, Label, skeleton

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"


class Action(IntEnum):
    ALLOW = 0
    APPROVE = 1
    DENY = 2


@dataclass
class Verdict:
    action: Action = Action.ALLOW
    reasons: list[str] = field(default_factory=list)

    def raise_to(self, action: Action, reason: str) -> None:
        self.action = max(self.action, action)
        self.reasons.append(f"[{action.name}] {reason}")


def load_policy(path: str | Path = DEFAULT_POLICY) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


class PolicyEngine:
    def __init__(self, policy: dict | None = None):
        self.p = policy or load_policy()

    # --------------------------------------------------------------- helpers

    def _hostile(self, spans) -> list:
        return [s for s in spans if s.label == Label.UNTRUSTED and s.risk >= self.p["untrusted"]["hostile_score"]]

    def _user_asked_to_pay_a_document(self, ctx: Context) -> bool:
        return bool(re.search(r"\b(pay|settle|clear)\b.{0,40}\b(bill|invoice|dues?|statement)\b", ctx.user_text(), re.I | re.S))

    def _check_destination(self, v: Verdict, ctx: Context, name: str, account: str, who: str, new: bool = False) -> None:
        """For a saved payee the customer naming them is enough (the bank holds the
        account number). For a *new* payee only the account number counts: the
        customer saying "pay Acme" does not vouch for an account number Acme's
        invoice supplied."""
        by_acct = ctx.origins_of_account(account)
        by_name = [] if new else ctx.origins_of_name(name)
        user = Label.USER in ctx.labels(by_acct) | ctx.labels(by_name)
        untrusted = [s for s in by_acct + by_name if s.label == Label.UNTRUSTED]
        if user:
            return
        if self._hostile(untrusted):
            v.raise_to(Action.DENY, f"{who} was named only by content flagged as an injection ({self._hostile(untrusted)[0].source})")
        elif any(s.label == Label.UNTRUSTED for s in by_acct):
            v.raise_to(Action.DENY, f"{who}'s account number came from third-party content, not from the customer")
        elif untrusted:
            v.raise_to(Action.APPROVE, f"{who} was suggested by third-party content ({untrusted[0].source}), not by the customer")
        else:
            v.raise_to(Action.APPROVE, f"the customer never mentioned {who}")

    def _check_amount(self, v: Verdict, ctx: Context, amount: float) -> None:
        spans = ctx.origins_of_amount(amount)
        labels = ctx.labels(spans)
        if Label.USER in labels:
            return
        if Label.UNTRUSTED in labels:
            if self._hostile(spans):
                v.raise_to(Action.DENY, f"amount ₹{amount:,.0f} comes from content flagged as an injection")
            elif not (self._user_asked_to_pay_a_document(ctx) and amount <= self.p["untrusted"]["auto_pay_document_amount_max"]):
                v.raise_to(Action.APPROVE, f"amount ₹{amount:,.0f} was taken from a document, not confirmed by the customer")
            return
        v.raise_to(Action.APPROVE, f"amount ₹{amount:,.0f} does not appear anywhere the customer or bank provided")

    def _check_limits(self, v: Verdict, bank: Bank, amount: float) -> None:
        lim = self.p["limits"]
        if amount > lim["per_transfer_max"]:
            v.raise_to(Action.DENY, f"₹{amount:,.0f} exceeds the per-payment ceiling of ₹{lim['per_transfer_max']:,}")
        elif amount > lim["approval_above"]:
            v.raise_to(Action.APPROVE, f"₹{amount:,.0f} is above the ₹{lim['approval_above']:,} confirmation threshold")
        day = [t for t in bank.ledger if t.kind in ("transfer", "bill") and bank.now - t.ts < 86400]
        if sum(t.amount for t in day) + amount > lim["daily_total_max"]:
            v.raise_to(Action.DENY, f"daily outflow would exceed ₹{lim['daily_total_max']:,}")
        hour = [t for t in day if bank.now - t.ts < 3600]
        if len(hour) >= lim["max_payments_per_hour"]:
            v.raise_to(Action.DENY, f"{len(hour)} payments in the last hour (velocity limit)")
        window = [t for t in day if bank.now - t.ts < lim["structuring_window_minutes"] * 60]
        lo, hi = lim["structuring_band"] * lim["approval_above"], lim["approval_above"]
        near = [t for t in window if lo <= t.amount <= hi] + ([amount] if lo <= amount <= hi else [])
        if len(near) >= lim["structuring_count"]:
            v.raise_to(Action.DENY, f"{len(near)} payments just under the confirmation threshold within {lim['structuring_window_minutes']} min (splitting to avoid checks)")
        start, end = self.p["quiet_hours"]["start"], self.p["quiet_hours"]["end"]
        hour_now = dt.datetime.fromtimestamp(bank.now).hour
        if start <= hour_now < end:
            v.raise_to(Action.APPROVE, f"money movement at {hour_now:02d}:00 falls in quiet hours")

    def _check_memo(self, v: Verdict, bank: Bank, ctx: Context, memo: str, from_document_ok: bool = False) -> None:
        if not memo:
            return
        low = memo.casefold()
        if any(re.search(rf"\b{re.escape(w)}\b", low) for w in self.p["memo"]["blocked_words"]):
            v.raise_to(Action.DENY, "memo mentions a credential (OTP/PIN/password): possible exfiltration")
        own = re.sub(r"\D", "", bank.account_number)
        digits = re.sub(r"\D", "", memo)
        if own[-6:] in digits or re.search(r"\b\d{12,16}\b", memo):
            v.raise_to(Action.DENY, "memo carries an account or card number: possible exfiltration")
        if not from_document_ok and Label.USER not in ctx.labels(ctx.origins_of_text(memo)) and Label.UNTRUSTED in ctx.labels(ctx.origins_of_text(memo)):
            v.raise_to(Action.APPROVE, "memo text was copied from third-party content")

    # --------------------------------------------------------------- entry point

    def evaluate(self, tool: str, args: dict, ctx: Context, bank: Bank) -> Verdict:
        v = Verdict()
        if tool in READ_TOOLS:
            return v
        if tool not in MONEY_TOOLS | {"add_payee"}:
            v.raise_to(Action.DENY, f"tool {tool!r} is not on the allowlist")
            return v

        if tool == "add_payee":
            name, acct = str(args.get("name", "")), str(args.get("account_number", ""))
            for p in bank.payees.values():
                if skeleton(p.name) == skeleton(name) and re.sub(r"\D", "", p.account_number) != re.sub(r"\D", "", acct):
                    kind = "look-alike of" if p.name != name else "same name as"
                    v.raise_to(Action.DENY, f"'{name}' is a {kind} existing payee '{p.name}' but with a different account")
            if name != re.sub(r"[^\x00-\x7f]", "", name) and skeleton(name) != name.casefold():
                v.raise_to(Action.APPROVE, "payee name uses non-Latin look-alike letters")
            self._check_destination(v, ctx, name, acct, f"new payee '{name}'", new=True)
            if Label.USER in ctx.labels(ctx.origins_of_account(acct)):
                v.reasons.append("[ALLOW] account number typed by the customer")
            return v

        amount = float(args.get("amount", 0))
        if tool == "transfer":
            p = bank.payees.get(str(args.get("payee_id")))
            if p is None:
                v.raise_to(Action.DENY, f"unknown payee id {args.get('payee_id')!r}")
                return v
            self._check_destination(v, ctx, p.name, p.account_number, f"payee '{p.name}'")
            age_h = (bank.now - p.added_at) / 3600
            np = self.p["new_payee"]
            if age_h < np["cooldown_hours"] and amount > np["cooldown_max_without_approval"]:
                v.raise_to(Action.APPROVE, f"payee was added {age_h:.1f} h ago; first payments above ₹{np['cooldown_max_without_approval']:,} need confirmation")
            self._check_memo(v, bank, ctx, str(args.get("memo", "")))
        else:  # pay_bill
            biller, ref = str(args.get("biller", "")), str(args.get("reference", "")).strip()
            if biller not in bank.billers:
                v.raise_to(Action.DENY, f"'{biller}' is not a registered biller")
            elif ref != bank.billers[biller]:
                v.raise_to(Action.APPROVE, f"consumer number {ref!r} is not the customer's registered number with {biller} (paying someone else's bill)")
            # bill references naturally come from the bill itself
            self._check_memo(v, bank, ctx, ref, from_document_ok=True)
        self._check_amount(v, ctx, amount)
        self._check_limits(v, bank, amount)
        return v
