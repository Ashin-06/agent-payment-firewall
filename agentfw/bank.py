"""In-memory core-banking sandbox the assistant operates on.

The tool surface mirrors what a retail banking assistant typically gets: read balances,
statements and the customer's inbox/documents, manage payees, move money, pay bills.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field


@dataclass
class Payee:
    payee_id: str
    name: str
    account_number: str
    ifsc: str
    added_at: float


@dataclass
class Txn:
    ts: float
    kind: str  # transfer | bill | credit
    amount: float
    counterparty: str
    memo: str = ""
    account: str = ""


@dataclass
class Bank:
    customer: str = "Priya Sharma"
    account_number: str = "50100234567812"
    balance: float = 245_000.0
    payees: dict[str, Payee] = field(default_factory=dict)
    # registered billers -> the customer's own consumer number with that biller
    billers: dict[str, str] = field(default_factory=lambda: {
        "BESCOM Electricity": "88121", "Airtel Postpaid": "9845012345", "Mahanagar Gas": "MG70012", "LIC Premium": "4455112"})
    ledger: list[Txn] = field(default_factory=list)
    documents: dict[str, str] = field(default_factory=dict)  # doc_id -> text (invoices, emails, web pages)
    now: float = field(default_factory=time.time)

    @classmethod
    def demo(cls) -> "Bank":
        b = cls()
        old = b.now - 90 * 86400
        for pid, name, acct, ifsc in [
            ("P1", "Rohan Mehta", "918020045566771", "UTIB0000123"),
            ("P2", "Acme Interiors Pvt Ltd", "50200011223344", "HDFC0001234"),
            ("P3", "Green Leaf Landlord Services", "33450067891234", "SBIN0004567"),
            ("P4", "Mom", "10023456789012", "ICIC0000456"),
        ]:
            b.payees[pid] = Payee(pid, name, acct, ifsc, old)
        b.ledger += [
            Txn(b.now - 5 * 86400, "credit", 152_000, "Infosys Payroll", "Salary Oct"),
            Txn(b.now - 3 * 86400, "transfer", 28_000, "Green Leaf Landlord Services", "Rent Oct"),
            Txn(b.now - 2 * 86400, "bill", 2_340, "BESCOM Electricity", "Bill 7781"),
        ]
        return b

    def snapshot(self) -> "Bank":
        return copy.deepcopy(self)

    # ------------------------------------------------------------- tools

    def get_balance(self) -> dict:
        return {"account_number": self.account_number, "balance": round(self.balance, 2), "currency": "INR"}

    def list_payees(self) -> list[dict]:
        return [{"payee_id": p.payee_id, "name": p.name, "account_number": p.account_number, "ifsc": p.ifsc} for p in self.payees.values()]

    def get_statement(self, limit: int = 10) -> list[dict]:
        return [{"days_ago": round((self.now - t.ts) / 86400, 1), "kind": t.kind, "amount": t.amount,
                 "counterparty": t.counterparty, "memo": t.memo} for t in self.ledger[-limit:][::-1]]

    def read_document(self, doc_id: str) -> str:
        if doc_id not in self.documents:
            raise KeyError(f"no document {doc_id}")
        return self.documents[doc_id]

    def list_documents(self) -> list[str]:
        return sorted(self.documents)

    def add_payee(self, name: str, account_number: str, ifsc: str) -> dict:
        pid = f"P{len(self.payees) + 1}"
        while pid in self.payees:
            pid = f"P{int(pid[1:]) + 1}"
        self.payees[pid] = Payee(pid, name.strip(), str(account_number).strip(), ifsc.strip().upper(), self.now)
        return {"payee_id": pid, "status": "added"}

    def transfer(self, payee_id: str, amount: float, memo: str = "") -> dict:
        if payee_id not in self.payees:
            raise KeyError(f"unknown payee {payee_id}")
        amount = float(amount)
        if amount <= 0 or amount > self.balance:
            raise ValueError("invalid amount or insufficient balance")
        self.balance -= amount
        p = self.payees[payee_id]
        self.ledger.append(Txn(self.now, "transfer", amount, p.name, memo, p.account_number))
        return {"status": "completed", "to": p.name, "account_number": p.account_number, "amount": amount, "reference": f"IMPS{len(self.ledger):06d}"}

    def pay_bill(self, biller: str, amount: float, reference: str) -> dict:
        if biller not in self.billers:
            raise KeyError(f"unknown biller {biller}")
        amount = float(amount)
        if amount <= 0 or amount > self.balance:
            raise ValueError("invalid amount or insufficient balance")
        self.balance -= amount
        self.ledger.append(Txn(self.now, "bill", amount, biller, reference))
        return {"status": "paid", "biller": biller, "amount": amount, "reference": reference}


TOOL_SPECS = [
    {"name": "get_balance", "description": "Current balance of the customer's savings account.",
     "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "list_payees", "description": "Saved payees (beneficiaries) with their ids and account numbers.",
     "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "get_statement", "description": "Most recent transactions, newest first.",
     "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50}},
                      "required": ["limit"], "additionalProperties": False}},
    {"name": "list_documents", "description": "Ids of documents and emails in the customer's inbox.",
     "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "read_document", "description": "Read an invoice, email or saved web page by id.",
     "input_schema": {"type": "object", "properties": {"doc_id": {"type": "string"}}, "required": ["doc_id"], "additionalProperties": False}},
    {"name": "add_payee", "description": "Register a new payee (beneficiary).",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "account_number": {"type": "string"},
                                                       "ifsc": {"type": "string"}},
                      "required": ["name", "account_number", "ifsc"], "additionalProperties": False}},
    {"name": "transfer", "description": "Send money to a saved payee.",
     "input_schema": {"type": "object", "properties": {"payee_id": {"type": "string"}, "amount": {"type": "number"},
                                                       "memo": {"type": "string"}},
                      "required": ["payee_id", "amount", "memo"], "additionalProperties": False}},
    {"name": "pay_bill", "description": "Pay a registered biller.",
     "input_schema": {"type": "object", "properties": {"biller": {"type": "string"}, "amount": {"type": "number"},
                                                       "reference": {"type": "string"}},
                      "required": ["biller", "amount", "reference"], "additionalProperties": False}},
]

READ_TOOLS = {"get_balance", "list_payees", "get_statement", "list_documents", "read_document"}
MONEY_TOOLS = {"transfer", "pay_bill"}
