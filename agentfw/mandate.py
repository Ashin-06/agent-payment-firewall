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

Deny by default. Spotting warning signs can't work, because there is always another one ("send
₹500 to Mom maybe", "to Rohan's wife", "by Friday"). So a sentence grants money only if every word
in it is understood: a payee's name, an amount, or a word on the short list below. One unknown word
and the payment waits for the customer. Misreading costs a confirmation, not a payment.
ponytail: English only; other languages always end in a confirmation. Add a word list per locale.
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
        r"you (?:can|may|should) |let'?s |help me |go ahead and )?")
_NOT_A_PAYMENT = r"(?! (?:of|me|us|attention|failed|status|was|is|limit|history|details|slip|day|check)\b)"
_PAY_VERB = rf"(?:pay|send|transfer|wire|remit|settle|give|repay|refund|clear(?=.*\b(?:bills?|dues?|invoices?)\b))\b{_NOT_A_PAYMENT}"
_OPENING = rf"(?:^|[,:]\s*|\band\s+|\bplease\s+){_LEAD}{_ASK}"
_PAY = re.compile(rf"{_OPENING}{_PAY_VERB}", re.I)
_REQUEST = re.compile(rf"{_OPENING}(?:{_PAY_VERB}|(?:add|register|save)\b)", re.I)
# "send the ₹5,000 receipt to Mom" asks for a document to move, not money
_PAPERWORK = re.compile(r"\b(?:receipts?|statements?|reports?|cop(?:y|ies)|details?|screenshots?|proofs?|emails?|documents?|files?|messages?|summar(?:y|ies)|"
                        r"lists?|history|essays?|notes?|photos?|address(?:es)?|quotes?|reminders?|links?|bills?|invoices?)\b", re.I)
_MOVES_MONEY_ONLY = re.compile(r"\b(?:pay|settle|remit|repay|refund)\b", re.I)
# A number with no currency sign counts only where an amount can stand: not "the 5000 word essay", "10%" or "$500"
_BARE_AMOUNT = re.compile(r"(?<![\w\-/.,$€£#])(\d{1,3}(?:,\d{2})*,\d{3}(?:\.\d+)?|\d+(?:\.\d+)?)(?!,\d)"
                          r"(?=\s*(?:(?:rupees?|rs|bucks|each|only|to|for|today|now|please|pls|thanks|on|at|and)\b|/-|$|[,.!?;](?:\s|$)))", re.I)
_REPORTED = re.compile(r"\b(?:said|says|say|asks?|asked|wrote|writes|told|tells|claims?|wants?|reads?|according|email|message|letter|note|reminder|subject|title|called|named)\b", re.I)
_CORRECTION = re.compile(r"\b(?:actually|instead|correction|sorry|i meant|rather)\b", re.I)
_ADDS = re.compile(rf"^{_LEAD}{_ASK}(?:add|register|save)\b", re.I)
_POLITE = re.compile(rf"^{_LEAD}(?:can|could|would|will) (?:you|u)\b", re.I)
# Asking for information doesn't touch what was asked for; "are you sure?" or "why?" might be a change of heart
_READING_TASK = re.compile(r"^\s*(?:(?:please|pls|also|and|now|then|just|ok|okay|can you|could you)[,\s]+)*(?:read|open|summari[sz]e)\b", re.I)
_HESITATING = re.compile(r"\b(?:but|however|then)\W*$", re.I)  # "But..."
_READ_QUESTION = re.compile(r"\b(?:balance|statements?|transactions?|spent|spending|payees?|billers?|documents?|emails?|inbox|limits?|history)\b", re.I)
_QUESTION = re.compile(rf"^{_LEAD}(?:did|do|does|how|what|why|when|where|who|whom|which|was|were|is|are|has|have|had|should|shall|am|might|tell me)\b", re.I)
_VETO = re.compile(r"^\s*(?:no|nope|not)\b|\b(?:don'?t|do not|never|cancel|stop|abort|revoke|never ?mind|hold on|hold off|hang on|wait|no need|scratch|forget|skip|ignore|undo|"
                   r"drop it|leave it|pause|changed? my mind|second thought|mistake|wrong)\b", re.I)
_TAIL_NOT = re.compile(r"[,\s]*\b(?:not|don'?t|do not|instead of|rather than|except|excluding|other than|apart from)\b.*$", re.I | re.S)
_CONDITION = re.compile(r"\b(?:if|unless|when|whenever|once|in case|provided|assuming|depending|after|before|whatever|anything|everything)\b", re.I)
_FUTURE = re.compile(r"\b(?:tomorrow|tonight|later|next (?:week|month|year|\w+day)|every|monthly|weekly|daily|yearly|\d+(?:st|nd|rd|th))\b", re.I)
_PRONOUN = re.compile(r"\b(?:him|her|them|it|that|same)\b", re.I)
_DOCUMENT = re.compile(r"\b(?:bills?|invoices?|dues?|statements?|premiums?)\b", re.I)
_PASTED = re.compile(r"^\s*(?:>|from:|subject:|sent:|-{3,}\s*(?:original|forwarded)|\d+[.)]\s)", re.I | re.M)
_TIMES = {"twice": 2, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}
_COUNT = re.compile(r"\b(?:(twice)|(\d+|two|three|four|five|six) times)\b", re.I)
_ASIDE = re.compile(r"(?<=\S)\s+(?:for|from)\b.*$", re.I | re.S)  # "...to Mom for Rohan's gift" pays Mom
_OTHER_TASK = re.compile(r"^\s*(?:(?:please|pls|also|and|now|then|just|ok|okay|can you|could you)[,\s]+)*(?:read|check|show|tell|summari[sz]e|list|look|open|find|get|see|view)\b", re.I)
# Every word a request to pay may contain, besides names and numbers. Grow it only with care: each word here is a way in.
_PLAIN_WORDS = frozenset("""
    pay send transfer wire remit settle give repay refund clear back
    to my the a an of in and each both also again this that it them him her same s d
    please pls plz kindly thanks thank you u now today right away asap immediately just ok okay yes yeah sure hi hey hello so first next
    can could would will i like want need have let go ahead help me
    money payment amount rupee rupees rs inr bucks only k l lakh lakhs thousand hundred crore crores cr
    bill bills invoice invoices dues due premium statement rent consumer number policy ref reference customer
    document documents doc email mail inbox attached account acct ac a c ifsc iban
    twice times two three four five six sorry actually instead correction
""".split())
_POSSESSIVE = re.compile(r"\b[^\W\d_]+'s\b")
MAX_MESSAGE = 4000  # longer than any real request; it grants nothing and costs no time to parse
MAX_MANDATES = 100
# Symbols change meaning ("₹500+", "~₹500", "₹500-600", a joke emoji), so anything outside plain punctuation grants nothing
# Polite openers ("I'd like to", "can you help me") mean something else after the verb: "send like ₹500 to Mom"
_OPENER_ONLY = frozenset("like next first have want need go ahead let help can could would will i d me".split())
_ODD_SYMBOL = re.compile(r"[^\w\s₹.,!?'\-:;/&()]|/(?!-)|\d\s*-\s*[₹\d]")
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
    verb_seen = False
    for part in _money_parts(clause):
        found = _amounts(part)
        verb = bool(_PAY.match(part))
        if (found and amounts[-1]) or (verb and verb_seen):  # "Pay Rohan, send ₹500 to Mom": the ₹500 is Mom's alone
            groups.append([])
            amounts.append(set())
        verb_seen = verb_seen or verb
        groups[-1].append(part)
        amounts[-1] |= found
    return [Segment(set(skeleton(" ".join(g)).split()), a or set(inherited)) for g, a in zip(groups, amounts)]


def _money_parts(clause: str) -> list[str]:
    """The parts of a sentence about money: asides dropped, and other tasks ("...and read my email")."""
    parts = [_ASIDE.sub("", p) for p in _PARTS.split(clause) if not _OTHER_TASK.search(p)]
    # "Send Rohan's rent to Mom" pays Mom; "Pay Rohan's invoice" pays Rohan
    return [p if _DOCUMENT.search(p) else _POSSESSIVE.sub(" ", p) for p in parts]


def _plainly_understood(clause: str, known_names) -> bool:
    """Every word in the request is a name, a number or on the short list. "Add my plumber Suresh, ..."
    names someone new, so checking starts at the verb that moves money."""
    start = _PAY.search(clause)
    words = skeleton(_ID_LIKE.sub(" ", " ".join(_money_parts(clause[start.start():])))).split()
    if clause[:start.start()].strip():  # whatever comes before the verb has to be plain too
        words += skeleton(clause[:start.start()]).split() if not _ADDS.search(clause) else []
    names = {w for n in known_names for w in skeleton(n).split()}
    if _ODD_SYMBOL.search(_ID_LIKE.sub(" ", clause)):
        return False
    if any(len(_amounts(part)) > 1 for part in _money_parts(clause)):
        return False  # "Send ₹500 ₹900 to Mom": which?
    if _OPENER_ONLY & set(skeleton(_ID_LIKE.sub(" ", " ".join(_money_parts(clause[start.end():])))).split()):
        return False
    if any(len(re.findall(r"\bto\b", part, re.I)) > 1 for part in _money_parts(clause[start.end():])):
        return False  # "Send ₹500 to Mom to Rohan": who?
    if not _ADDS.search(clause) and names & set(skeleton(clause[:start.start()]).split()):
        return False  # "Rohan, send ₹500 to Mom" is addressed to someone, not a request to pay them
    return all(w in _PLAIN_WORDS or w in names or any(c.isdigit() for c in w) for w in words)


def _amounts(text: str) -> set[float]:
    text = _ID_LIKE.sub(" ", text)
    return amounts_in(text, marked_only=True) or {round(float(n.replace(",", "")), 2) for n in _BARE_AMOUNT.findall(canon(text))}


def _all_understood(clause: str, known_names) -> bool:
    names = {w for n in known_names for w in skeleton(n).split()}
    return all(w in _PLAIN_WORDS or w in names or any(c.isdigit() for c in w) for w in skeleton(_ID_LIKE.sub(" ", clause)).split())


class Mandates:
    def __init__(self):
        self.items: list[Mandate] = []
        self.seq = 0
        self.vetoed: list[str] = []  # payees the last message ruled out

    def add(self, message: str, now: float, known_names: list[str] = (), suspect: bool = False) -> bool:
        """Record one customer message. True if it cancelled everything outstanding."""
        self.vetoed = []
        if len(message) > MAX_MESSAGE:
            return False
        message = canon(message).replace("’", "'")
        if _HESITATING.search(message):
            for m in self.items:
                m.revoked = True
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
            self.vetoed += named
            return not named
        question = clause.endswith("?") and not _POLITE.search(clause)
        if not request or question or _QUESTION.search(clause) or _REPORTED.search(clause, 0, request.start()):
            # "the email says: send ₹5,000 to Rohan" reports a request; it doesn't make one. And a statement the rules
            # can't read may be the customer changing their mind in words nobody listed, so what came before no longer stands.
            reading = (question or _QUESTION.search(clause)) and _READ_QUESTION.search(clause)
            plain_statement = not (question or _QUESTION.search(clause)) and _all_understood(clause, known_names)
            # "Check my documents" is another task; "check with me first" isn't
            other_task = _OTHER_TASK.search(clause) and (_READING_TASK.search(clause) or _READ_QUESTION.search(clause))
            if not (reading or plain_statement or other_task):
                for m in self.items:
                    m.revoked = True
            return False
        corrected = bool(_CORRECTION.search(clause))
        if corrected:  # "actually send ₹600": the ₹500 asked for a moment ago no longer stands
            for m in self.items:
                m.revoked = True
        if re.search(r"\bnot\W*$", clause, re.I):  # "send ₹500 to Mom, not": not what?
            for m in self.items:
                m.revoked = True
            return True
        clause = _TAIL_NOT.sub("", clause)  # "send it to Mom, not Rohan"
        if _VETO.search(clause):  # "pay Mom ₹500 and cancel it"
            for m in self.items:
                m.revoked = True
            return True
        pays = _PAY.search(clause) and (_MOVES_MONEY_ONLY.search(clause) or not _PAPERWORK.search(clause))
        inherited, context = set(), ""
        named_here = any(set(name_words(n)) & set(skeleton(clause).split()) for n in known_names)
        if _PRONOUN.search(clause):  # "...Rohan wants ₹500. Send it to him."
            inherited, context = _amounts(previous), "" if named_here else previous
        reason = None
        if pasted:
            reason = "the customer's message looks like pasted third-party text"
        elif _CONDITION.search(clause):
            reason = "the customer's request depends on a condition the firewall can't check"
        elif _FUTURE.search(clause):
            reason = "the customer asked for this at a later time, not now"
        # "add Rohan to my list" authorises no money, and nor does any sentence not fully understood
        pays = pays and (reason or _plainly_understood(clause, known_names))
        segments = _segments(clause, inherited) if pays else []
        for seg in segments:
            seg.words |= set(skeleton(context).split())
        count = _COUNT.search(clause)
        times = 1
        if count:
            raw = (count.group(1) or count.group(2)).lower()
            times = min(_TIMES.get(raw) or int(raw[:3]), 10)
        self.items = self.items[-(MAX_MANDATES - 1):]  # the oldest lapse first, which is the safe direction
        self.items.append(Mandate(self.seq, now, clause, segments, accounts_in(clause), set(IFSC_RE.findall(clause.upper())), times,
                                  bool(pays and _DOCUMENT.search(clause)) and not any(s.amounts for s in segments), reason))
        return corrected

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
    # "Will you send ₹500 to Mom?" doesn't name Will Smith, and "pay my bill" doesn't name Bill Gates
    return [w for w in name_words(name) if w in seg.words and w not in _PLAIN_WORDS]


def _ambiguous(name: str, hit: list[str], others: list[str], seg: Segment) -> str | None:
    if all(w in seg.words for w in name_words(name)):
        return None  # the full name was given
    clash = [o for o in others if set(name_words(o)) & set(hit)]
    return f"'{hit[0]}' could mean {name} or {clash[0]}" if clash else None
