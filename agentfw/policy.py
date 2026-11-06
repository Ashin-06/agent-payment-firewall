"""Policy engine: decides ALLOW / APPROVE (hold for the customer) / DENY for each tool call."""
from __future__ import annotations

import datetime as dt
import os
import re
import tomllib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from .bank import MONEY_TOOLS, READ_TOOLS, Bank
from .detector import URL
from .mandate import Claim
from .provenance import CONFUSABLES, IBAN_RE, Context, Label, canon, name_words, normalise_account, skeleton

DEFAULT_POLICY = Path(__file__).with_name("policy.toml")
_LONG_NUMBER = re.compile(r"\d(?:[ .\-]?\d){11,}")  # a card or account number, however it is spaced
_DIGITS = re.compile(r"\d(?:[ .\-]?\d){5,}")
MAX_UNTYPED_MEMO = 40  # what the assistant may write by itself: enough to say "rent", too little to carry much out


class Action(IntEnum):
    ALLOW = 0
    APPROVE = 1
    DENY = 2


@dataclass
class Verdict:
    action: Action = Action.ALLOW
    reasons: list[str] = field(default_factory=list)
    claim: Claim | None = None  # the customer's request this call spends

    def raise_to(self, action: Action, reason: str) -> None:
        self.action = max(self.action, action)
        self.reasons.append(f"[{action.name}] {reason}")


def load_policy(path: str | Path | None = None) -> dict:
    with open(path or os.environ.get("AGENTFW_POLICY") or DEFAULT_POLICY, "rb") as f:
        return tomllib.load(f)


class PolicyEngine:
    def __init__(self, policy: dict | None = None):
        self.p = policy or load_policy()
        self.ttl = self.p["mandate"]["ttl_minutes"] * 60

    # --------------------------------------------------------------- helpers

    def _hostile(self, spans) -> list:
        return [s for s in spans if s.label == Label.UNTRUSTED and s.risk >= self.p["untrusted"]["hostile_score"]]

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
        elif new:  # refused, not held: money can't reach a new account even if someone approves everything
            v.raise_to(Action.DENY, f"the customer never typed the account number for {who}")
        elif untrusted:
            v.raise_to(Action.APPROVE, f"{who} was suggested by third-party content ({untrusted[0].source}), not by the customer")
        else:
            v.raise_to(Action.APPROVE, f"the customer never mentioned {who}")

    def _spend(self, v: Verdict, claim: Claim) -> None:
        v.claim = claim
        if claim.caution:
            v.raise_to(Action.APPROVE, claim.caution)

    def _check_amount(self, v: Verdict, ctx: Context, bank: Bank, amount: float, name: str, others: list[str]) -> None:
        """The payment must match something the customer asked for: this payee with this amount,
        not yet used. Failing that, an amount from a bill the customer asked to pay, up to a limit."""
        claim = ctx.mandates.claim(name, amount, others, bank.now, self.ttl)
        if claim:
            return self._spend(v, claim)
        spans = ctx.origins_of_amount(amount)
        if Label.UNTRUSTED not in ctx.labels(spans):
            return v.raise_to(Action.APPROVE, f"the customer did not ask to pay ₹{amount:,.2f} to {name} "
                                              "(one request authorises one payment, to that payee, at that amount)")
        if self._hostile(spans):
            return v.raise_to(Action.DENY, f"amount ₹{amount:,.0f} comes from content flagged as an injection")
        words = set(name_words(name))
        about_payee = any(s.label == Label.UNTRUSTED and words & s.words for s in spans)
        claim = ctx.mandates.claim_document(name, others, bank.now, self.ttl) if about_payee else None
        if claim and amount <= self.p["untrusted"]["auto_pay_document_amount_max"]:
            return self._spend(v, claim)
        v.raise_to(Action.APPROVE, f"amount ₹{amount:,.0f} was taken from a document, not confirmed by the customer")

    def _check_limits(self, v: Verdict, bank: Bank, amount: float, reserved: float = 0.0) -> None:
        lim = self.p["limits"]
        if amount > lim["per_transfer_max"]:
            v.raise_to(Action.DENY, f"₹{amount:,.0f} exceeds the per-payment ceiling of ₹{lim['per_transfer_max']:,}")
        elif amount > lim["approval_above"]:
            v.raise_to(Action.APPROVE, f"₹{amount:,.0f} is above the ₹{lim['approval_above']:,} confirmation threshold")
        day = [t for t in bank.ledger if t.kind in ("transfer", "bill") and bank.now - t.ts < 86400]
        if sum(t.amount for t in day) + reserved + amount > lim["daily_total_max"]:
            v.raise_to(Action.DENY, f"daily outflow would exceed ₹{lim['daily_total_max']:,}")
        hour = [t for t in day if bank.now - t.ts < 3600]
        if len(hour) >= lim["max_payments_per_hour"]:
            v.raise_to(Action.DENY, f"{len(hour)} payments in the last hour (velocity limit)")
        window = [t for t in day if bank.now - t.ts < lim["structuring_window_minutes"] * 60]
        lo, hi = lim["structuring_band"] * lim["approval_above"], lim["approval_above"]
        near = [t for t in window if lo <= t.amount <= hi] + ([amount] if lo <= amount <= hi else [])
        if len(near) >= lim["structuring_count"]:
            v.raise_to(Action.DENY, f"{len(near)} payments just under the confirmation threshold within {lim['structuring_window_minutes']} min (splitting to avoid checks)")
        if amount > lim["max_share_of_balance"] * bank.balance:
            v.raise_to(Action.APPROVE, f"₹{amount:,.0f} is more than {lim['max_share_of_balance']:.0%} of the balance")
        q = self.p["quiet_hours"]
        hour_now = dt.datetime.fromtimestamp(bank.now, dt.timezone(dt.timedelta(minutes=q["utc_offset_minutes"]))).hour
        if q["start"] <= hour_now < q["end"]:
            v.raise_to(Action.APPROVE, f"money movement at {hour_now:02d}:00 falls in quiet hours")

    def _check_memo(self, v: Verdict, bank: Bank, ctx: Context, memo: str, from_document_ok: bool = False) -> None:
        if not memo:
            return
        memo = canon(memo)
        low = skeleton(memo)
        joined = re.sub(r"\b(\w) (?=\w\b)", r"\1", low)  # "o t p"
        if any(re.search(rf"\b{re.escape(w)}\b(?! ?code)" if w == "pin" else rf"\b{re.escape(w)}\b", text)
               for w in self.p["memo"]["blocked_words"] for text in (low, joined)):
            v.raise_to(Action.DENY, "memo mentions a credential (OTP/PIN/password): possible exfiltration")
        own = re.sub(r"\D", "", bank.account_number)
        digits = re.sub(r"\D", "", memo)
        if own[-6:] in digits or _LONG_NUMBER.search(memo):
            v.raise_to(Action.DENY, "memo carries an account or card number: possible exfiltration")
        if from_document_ok:
            return
        origins = ctx.labels(ctx.origins_of_text(memo))
        if Label.USER in origins:
            return
        if Label.UNTRUSTED in origins:
            v.raise_to(Action.APPROVE, "memo text was copied from third-party content")
        if URL.search(memo):
            v.raise_to(Action.APPROVE, "memo carries a link the customer did not type")
        if len(memo) > MAX_UNTYPED_MEMO or _DIGITS.search(memo) or any(re.search(r"\d", t) and re.search(r"[A-Za-z]", t) for t in re.findall(r"[^\s]{5,}", memo)):
            v.raise_to(Action.APPROVE, "memo carries a long or encoded text the customer did not type")

    def _check_unusual(self, v: Verdict, bank: Bank, name: str, amount: float) -> None:
        """Far more than this payee has ever been paid. Payees with no history have nothing to compare with."""
        earlier = [t.amount for t in bank.ledger if t.counterparty == name and t.kind in ("transfer", "bill")]
        multiple = self.p["limits"]["unusual_multiple"]
        if earlier and amount > multiple * max(earlier):
            v.raise_to(Action.APPROVE, f"₹{amount:,.0f} is over {multiple} times the most {name} has been paid (₹{max(earlier):,.0f})")

    def _check_new_payee(self, v: Verdict, ctx: Context, bank: Bank, name: str, acct: str, ifsc: str) -> None:
        recent = sum(bank.now - p.added_at < 86400 for p in bank.payees.values())
        if recent >= self.p["limits"]["max_new_payees_per_day"]:
            v.raise_to(Action.DENY, f"{recent} payees were already added today")
        for p in bank.payees.values():
            same = skeleton(p.name) == skeleton(name) if skeleton(name) else p.name == name
            if same and normalise_account(p.account_number) != normalise_account(acct):
                kind = "look-alike of" if p.name != name else "same name as"
                v.raise_to(Action.DENY, f"'{name}' is a {kind} existing payee '{p.name}' but with a different account")
        lookup = getattr(bank, "lookup_name", None)  # an adapter without one skips this check
        registered = lookup(acct, ifsc) if lookup else None
        if registered and not set(name_words(name)) & set(name_words(registered)):
            v.raise_to(Action.APPROVE, f"the receiving bank says this account belongs to '{registered}', not '{name}'")
        if name != name.translate(CONFUSABLES):
            v.raise_to(Action.APPROVE, "payee name uses non-Latin look-alike letters")
        self._check_destination(v, ctx, name, acct, f"new payee '{name}'", new=True)
        claim = ctx.mandates.claim_account(acct, name, bank.now, self.ttl)
        if claim:
            self._spend(v, claim)
            v.reasons.append("[ALLOW] account number typed by the customer in a request")
        elif v.action == Action.ALLOW:
            v.raise_to(Action.APPROVE, "the customer typed this account number but did not ask to add it")
        # the IFSC picks the bank: a number the customer typed at a branch a stranger chose is someone else's account
        if not IBAN_RE.fullmatch(normalise_account(acct)) and not ctx.mandates.ifsc_typed(ifsc, bank.now, self.ttl):
            v.raise_to(Action.APPROVE, f"IFSC {ifsc} was not typed by the customer")

    # --------------------------------------------------------------- entry points

    def evaluate(self, tool: str, args: dict, ctx: Context, bank: Bank) -> Verdict:
        v = Verdict()
        if tool in READ_TOOLS:
            return v
        if tool not in MONEY_TOOLS | {"add_payee"}:
            v.raise_to(Action.DENY, f"tool {tool!r} is not on the allowlist")
            return v

        if tool == "add_payee":
            self._check_new_payee(v, ctx, bank, str(args["name"]), str(args["account_number"]), str(args["ifsc"]))
            return v

        amount = float(args["amount"])
        if tool == "transfer":
            p = bank.payees.get(str(args["payee_id"]))
            if p is None:
                v.raise_to(Action.DENY, f"unknown payee id {args['payee_id']!r}")
                return v
            self._check_destination(v, ctx, p.name, p.account_number, f"payee '{p.name}'")
            age_h = (bank.now - p.added_at) / 3600
            np = self.p["new_payee"]
            if age_h < np["cooldown_hours"] and amount > np["cooldown_max_without_approval"]:
                v.raise_to(Action.APPROVE, f"payee was added {age_h:.1f} h ago; first payments above ₹{np['cooldown_max_without_approval']:,} need confirmation")
            self._check_memo(v, bank, ctx, str(args["memo"]))
            name, others = p.name, [q.name for q in bank.payees.values() if q.payee_id != p.payee_id] + list(bank.billers)
        else:  # pay_bill
            name, ref = str(args["biller"]), str(args["reference"]).strip()
            if name not in bank.billers:
                v.raise_to(Action.DENY, f"'{name}' is not a registered biller")
            elif ref != bank.billers[name]:
                v.raise_to(Action.APPROVE, f"consumer number {ref!r} is not the customer's registered number with {name} (paying someone else's bill)")
            # bill references naturally come from the bill itself
            self._check_memo(v, bank, ctx, ref, from_document_ok=True)
            others = [b for b in bank.billers if b != name] + [q.name for q in bank.payees.values()]
        self._check_amount(v, ctx, bank, amount, name, others)
        self._check_limits(v, bank, amount, sum(ctx.reserved.values()))
        self._check_unusual(v, bank, name, amount)
        return v

    def delay(self, tool: str, args: dict, bank: Bank, claim: Claim | None = None) -> str | None:
        """Why a permitted payment should wait out the undo window, if it should. Nothing here can be
        recalled once sent, so the riskier payments that don't need a person still get a way back."""
        if tool not in MONEY_TOOLS or not self.p["undo"]["window_minutes"]:
            return None
        if tool == "transfer":
            payee = bank.payees.get(str(args["payee_id"]))
            if payee and (bank.now - payee.added_at) / 3600 < self.p["new_payee"]["cooldown_hours"]:
                return "first payment to a new payee"
        if claim and claim.key[1] == "document":
            return "the amount came from a document"
        return None

    def recheck(self, tool: str, args: dict, bank: Bank, reserved: float = 0.0) -> Verdict:
        """Hard limits again at execution: other approvals may have run since this one was held."""
        v = Verdict()
        if tool in MONEY_TOOLS:
            self._check_limits(v, bank, float(args["amount"]), reserved)
            v.reasons = [r for r in v.reasons if r.startswith("[DENY]")]
            v.action = Action.DENY if v.reasons else Action.ALLOW
        return v
