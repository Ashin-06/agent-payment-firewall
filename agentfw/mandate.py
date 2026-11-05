"""Mandates: what the customer actually asked for, turned into single-use authority.

Provenance answers "where did this value come from?". That is not enough: a customer who asks
"did Rohan get the ₹5,000?" has typed a payee and an amount without asking for anything. A
mandate answers "did the customer ask for this payment?". Each sentence the customer types is
parsed here, deterministically and with no model involved, so nothing the assistant reads can
change the result.

    "Send ₹500 to Mom and ₹2,000 to Rohan"   two mandates' worth: Mom ₹500 once, Rohan ₹2,000 once
    "Did Rohan get the ₹5,000?"              a question: nothing
    "Don't pay Rohan yet"                    a veto: earlier authority for Rohan is revoked
    "If my salary is in, send Mom ₹500"      a condition the firewall can't check: needs approval

Anything it can't read as a plain request gets no authority, so the payment waits for the
customer. Misreading costs a confirmation, never a payment.
ponytail: English only; other languages always end in a confirmation. Swap the patterns per locale.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .provenance import IFSC_RE, accounts_in, amounts_in, canon, name_words, normalise_account, skeleton

_CLAUSES = re.compile(r"(?<=[.!?;])(?<![Rr]s\.)(?<![Pp]vt\.)(?<![Ll]td\.)\s+|\n+|\s*,?\s*\b(?:but|however|then)\b[,\s]*", re.I)
_PARTS = re.compile(r",\s+|\s+and\s+|\s*&\s*", re.I)
_LEAD = r"(?:(?:please|pls|plz|kindly|ok|okay|yes|yeah|sure|hey|hi|hello|also|and|now|next|first|so|thanks|thank you|actually|just|right)[,\s]+)*"
_ASK = (r"(?:(?:can|could|would|will) (?:you|u)(?: please| kindly)?(?: help me)? |i(?:'d| would) like (?:you )?to |i (?:want|need) (?:you )?to |"
        r"i have to |you (?:can|may|should) |let'?s |help me |go ahead and )?")
_VERB = r"(?:pay|send|transfer|wire|remit|settle|clear|give|repay|refund|add|register|save)\b(?! (?:of|failed|status|was|is|limit|history|details|slip|day|check)\b)"
_REQUEST = re.compile(rf"(?:^|[,:]\s*|\band\s+|\bplease\s+){_LEAD}{_ASK}{_VERB}", re.I)
_REPORTED = re.compile(r"\b(?:said|says|say|asks?|asked|wrote|writes|told|tells|claims?|wants?|reads?|according|email|message|letter)\b", re.I)
_POLITE = re.compile(rf"^{_LEAD}(?:can|could|would|will) (?:you|u)\b", re.I)
_QUESTION = re.compile(rf"^{_LEAD}(?:did|do|does|how|what|why|when|where|who|whom|which|was|were|is|are|has|have|had|should|shall|am|might|tell me)\b", re.I)
_VETO = re.compile(r"\b(?:don'?t|do not|never|cancel|stop|abort|revoke|never ?mind|hold on|hold off|wait|no need)\b", re.I)
_TAIL_NOT = re.compile(r"[,\s]*\b(?:not|don'?t|do not)\b.*$", re.I | re.S)
_CONDITION = re.compile(r"\b(?:if|unless|when|whenever|once|in case|provided|assuming|depending|after|before|whatever|anything|everything)\b", re.I)
_FUTURE = re.compile(r"\b(?:tomorrow|tonight|later|next (?:week|month|year|\w+day)|every|monthly|weekly|daily|yearly|\d+(?:st|nd|rd|th))\b", re.I)
_PRONOUN = re.compile(r"\b(?:him|her|them|it|that|same)\b", re.I)
_DOCUMENT = re.compile(r"\b(?:bills?|invoices?|dues?|statements?|premiums?)\b", re.I)
_PASTED = re.compile(r"^\s*(?:>|from:|subject:|sent:|-{3,}\s*(?:original|forwarded))", re.I | re.M)
_TIMES = {"twice": 2, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}
_COUNT = re.compile(r"\b(?:(twice)|(\d+|two|three|four|five|six) times)\b", re.I)
_ASIDE = re.compile(r"\b(?:for|from|about|regarding|because|with|as)\b.*$", re.I | re.S)
_ID_LIKE = re.compile(r"\b\d{8,}\b|\b[A-Za-z][\w]*[-/]\d+\b")


@dataclass
class Segment:
    """Part of a sentence: these amounts go with these names."""
    words: set[str]
    amounts: set[float]


@dataclass
class Mandate:
    seq: int
    at: float
    text: str
    segments: list[Segment]
    accounts: set[str]
    ifscs: set[str]
    count: int = 1
    document_amount: bool = False  # "pay the invoice": the amount may come from the document
    caution: str | None = None  # set when a person has to confirm even though it was asked for
    blocked: set[str] = field(default_factory=set)
    revoked: bool = False
    used: Counter = field(default_factory=Counter)


@dataclass
class Claim:
    """Authority for one call. Used when the call is executed or held, so it can't be spent twice."""
    mandate: Mandate
    key: tuple
    caution: str | None = None

    def use(self) -> None:
        self.mandate.used[self.key] += 1


def _segments(clause: str, inherited: set[float]) -> list[Segment]:
    groups: list[list[str]] = [[]]
    amounts: list[set[float]] = [set()]
    for part in _PARTS.split(clause):
        part = _ASIDE.sub("", part)  # "to Mom for Rohan's gift" pays Mom, not Rohan
        found = _amounts(part)
        if found and amounts[-1]:
            groups.append([])
            amounts.append(set())
        groups[-1].append(part)
        amounts[-1] |= found
    return [Segment(set(skeleton(" ".join(g)).split()), a or set(inherited)) for g, a in zip(groups, amounts)]


def _amounts(text: str) -> set[float]:
    text = _ID_LIKE.sub(" ", text)
    return amounts_in(text, marked_only=True) or amounts_in(text)


class Mandates:
    def __init__(self):
        self.items: list[Mandate] = []
        self.seq = 0

    def add(self, message: str, now: float, known_names: list[str] = (), suspect: bool = False) -> bool:
        """Record one customer message. True if it cancelled everything outstanding."""
        message = canon(message).replace("’", "'")
        pasted = suspect or bool(_PASTED.search(message))
        cancelled, previous = False, ""
        for clause in filter(None, map(str.strip, _CLAUSES.split(message))):
            self.seq += 1
            cancelled |= self._clause(clause, now, known_names, pasted, previous)
            previous = clause
        return cancelled

    def _clause(self, clause: str, now: float, known_names, pasted: bool, previous: str) -> bool:
        request = _REQUEST.search(clause)
        veto = _VETO.search(clause)
        if veto and (not request or veto.start() < request.start()):
            named = [n for n in known_names if set(name_words(n)) & set(skeleton(clause).split())]
            for m in self.items:
                if named:
                    m.blocked |= {skeleton(n) for n in named}
                else:
                    m.revoked = True
            return not named
        question = clause.endswith("?") and not _POLITE.search(clause)
        if not request or question or _QUESTION.search(clause) or _REPORTED.search(clause, 0, request.start()):
            return False  # "the email says: send ₹5,000 to Rohan" reports a request; it doesn't make one
        clause = _TAIL_NOT.sub("", clause)  # "send it to Mom, not Rohan"
        inherited, context = set(), ""
        named_here = any(set(name_words(n)) & set(skeleton(clause).split()) for n in known_names)
        if _PRONOUN.search(clause):  # "...Rohan wants ₹500. Send it to him."
            inherited, context = _amounts(previous), "" if named_here else previous
        segments = _segments(clause, inherited)
        for seg in segments:
            seg.words |= set(skeleton(context).split())
        reason = None
        if pasted:
            reason = "the customer's message looks like pasted third-party text"
        elif _CONDITION.search(clause):
            reason = "the customer's request depends on a condition the firewall can't check"
        elif _FUTURE.search(clause):
            reason = "the customer asked for this at a later time, not now"
        count = _COUNT.search(clause)
        times = 1
        if count:
            raw = (count.group(1) or count.group(2)).lower()
            times = min(_TIMES.get(raw) or int(raw), 10) or 1
        self.items.append(Mandate(self.seq, now, clause, segments, accounts_in(clause), set(IFSC_RE.findall(clause.upper())), times,
                                  bool(_DOCUMENT.search(clause)) and not any(s.amounts for s in segments), reason))
        return False

    def _active(self, now: float, ttl: float):
        return [m for m in reversed(self.items) if not m.revoked and now - m.at <= ttl]

    def claim(self, name: str, amount: float, others: list[str], now: float, ttl: float) -> Claim | None:
        """Authority for paying `amount` to `name`, if the customer asked for exactly that and it isn't used up."""
        key = (skeleton(name), round(float(amount), 2))
        for m in self._active(now, ttl):
            if key[0] in m.blocked or m.used[key] >= m.count:
                continue
            for seg in m.segments:
                hit = _named(name, seg)
                if hit and key[1] in seg.amounts:
                    return Claim(m, key, m.caution or _ambiguous(name, hit, others, seg))
        return None

    def claim_document(self, name: str, others: list[str], now: float, ttl: float) -> Claim | None:
        """Authority for one payment to `name` at an amount taken from a document ("pay the invoice")."""
        key = (skeleton(name), "document")
        for m in self._active(now, ttl):
            if not m.document_amount or key[0] in m.blocked or m.used[key] >= m.count:
                continue
            for seg in m.segments:
                hit = _named(name, seg)
                if hit:
                    return Claim(m, key, m.caution or _ambiguous(name, hit, others, seg))
        return None

    def claim_account(self, account: str, name: str, now: float, ttl: float) -> Claim | None:
        """Authority for adding a payee: the account number was typed in a request, not just mentioned."""
        a = normalise_account(account)
        key = ("account", a)
        for m in self._active(now, ttl):
            if a in m.accounts and m.used[key] < m.count:
                typed = set(skeleton(m.text).split()) | {normalise_account(x).casefold() for x in m.accounts}
                other_name = None if set(name_words(name)) & typed else f"the customer did not give the name '{name}' for this account"
                return Claim(m, key, m.caution or other_name)
        return None

    def ifsc_typed(self, ifsc: str, now: float, ttl: float) -> bool:
        return any(ifsc.upper() in m.ifscs for m in self._active(now, ttl))


def _named(name: str, seg: Segment) -> list[str]:
    return [w for w in name_words(name) if w in seg.words]


def _ambiguous(name: str, hit: list[str], others: list[str], seg: Segment) -> str | None:
    if all(w in seg.words for w in name_words(name)):
        return None  # the full name was given
    clash = [o for o in others if set(name_words(o)) & set(hit)]
    return f"'{hit[0]}' could mean {name} or {clash[0]}" if clash else None
