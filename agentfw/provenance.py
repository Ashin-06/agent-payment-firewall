"""Provenance (taint) tracking for everything the assistant has seen.

Every piece of text entering the conversation is recorded with where it came from.
When the assistant later asks to move money, each security-relevant argument (who
gets paid, how much, what the memo says) is traced back to its origin. Values the
customer typed are trusted; values that only ever appeared inside an email, invoice,
web page or a counterparty-controlled memo field are not.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum


class Label(str, Enum):
    USER = "user"            # typed by the authenticated customer
    BANK = "bank"            # structured data from the bank's own systems
    UNTRUSTED = "untrusted"  # documents, emails, web pages, memo fields


@dataclass
class Span:
    text: str
    label: Label
    source: str
    risk: float = 0.0  # injection score of this span (untrusted only)


ACCOUNT_RE = re.compile(r"\d[\d \-]{6,22}\d")
# IBANs carry letters in the bank code (GB29 NWBK 6016...), so they are compared whole, not as digits
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[A-Z0-9]{10,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)\b")  # compact or in fours
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr)?\s*(\d{1,3}(?:,\d{2,3})+(?:\.\d+)?|\d+(?:\.\d+)?)\s*(k|l|lakh|lakhs)?\b", re.I)

# Latin look-alikes from Cyrillic and Greek, enough to catch payee-name spoofing
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "ο": "o", "ν": "v", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
})


def skeleton(name: str) -> str:
    s = unicodedata.normalize("NFKC", name).translate(CONFUSABLES).casefold()
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def normalise_account(acct: str) -> str:
    s = re.sub(r"[\s-]", "", str(acct)).upper()
    return s if IBAN_RE.fullmatch(s) else re.sub(r"\D", "", s)


def accounts_in(text: str) -> set[str]:
    found = {re.sub(r"\D", "", m) for m in ACCOUNT_RE.findall(text) if len(re.sub(r"\D", "", m)) >= 8}
    return found | {m.group(0).replace(" ", "") for m in IBAN_RE.finditer(text)}


def amounts_in(text: str) -> set[float]:
    out = set()
    for num, unit in AMOUNT_RE.findall(text):
        try:
            v = float(num.replace(",", ""))
        except ValueError:
            continue
        unit = unit.lower()
        if unit == "k":
            v *= 1_000
        elif unit in ("l", "lakh", "lakhs"):
            v *= 100_000
        out.add(round(v, 2))
    return out


@dataclass
class Context:
    spans: list[Span] = field(default_factory=list)

    def add(self, text: str, label: Label, source: str, risk: float = 0.0) -> None:
        if text:
            self.spans.append(Span(str(text), label, source, risk))

    def _match(self, pred) -> list[Span]:
        return [s for s in self.spans if pred(s)]

    def origins_of_account(self, acct: str) -> list[Span]:
        a = normalise_account(acct)
        return self._match(lambda s: a in accounts_in(s.text))

    def origins_of_amount(self, amount: float) -> list[Span]:
        a = round(float(amount), 2)
        return self._match(lambda s: a in amounts_in(s.text))

    def origins_of_name(self, name: str) -> list[Span]:
        """Name mentioned in a span. Matches on any distinctive word of the name so
        'pay Rohan' traces to payee 'Rohan Mehta'."""
        words = [w for w in skeleton(name).split() if len(w) >= 3 and w not in {"pvt", "ltd", "the", "services", "and"}]
        if not words:
            return []
        return self._match(lambda s: any(re.search(rf"\b{re.escape(w)}\b", skeleton(s.text)) for w in words))

    def origins_of_text(self, value: str) -> list[Span]:
        v = skeleton(value)
        return self._match(lambda s: v and v in skeleton(s.text)) if len(v) >= 4 else []

    @staticmethod
    def labels(spans: list[Span]) -> set[Label]:
        return {s.label for s in spans}

    def user_text(self) -> str:
        return "\n".join(s.text for s in self.spans if s.label == Label.USER)
