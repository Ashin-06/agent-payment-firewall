"""Tamper-evident audit log: every entry carries the hash of the one before it, and
optionally an HMAC so an attacker with file access cannot rebuild the chain."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str | Path | None = None, key: bytes | None = None):
        self.path = Path(path) if path else None
        self.key = key
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self.entries = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _digest(self, body: dict) -> str:
        data = _canon(body)
        if self.key:
            return hmac.new(self.key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def append(self, event: str, **fields) -> dict:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
            body = {"seq": len(self.entries), "ts": time.time(), "event": event, "prev": prev, **fields}
            entry = {**body, "hash": self._digest(body)}
            self.entries.append(entry)
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            return entry

    def verify(self) -> tuple[bool, str]:
        prev = self.GENESIS
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != i:
                return False, f"entry {i}: sequence number {e.get('seq')} out of order (deleted or inserted entry)"
            if e.get("prev") != prev:
                return False, f"entry {i}: chain broken (previous hash mismatch)"
            if not hmac.compare_digest(self._digest(json.loads(_canon(body))), e["hash"]):
                return False, f"entry {i}: contents were modified"
            prev = e["hash"]
        return True, f"{len(self.entries)} entries, chain intact"
