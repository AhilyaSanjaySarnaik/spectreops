from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class AuditLog:
    """Append-only, hash-chained JSONL audit log.

    Each record includes the hash of the previous record, so any tampering
    or deletion breaks the chain and is detectable via verify().
    """

    def __init__(self, path: Path, hash_chain: bool = True):
        self.path = path
        self.hash_chain = hash_chain
        path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = self.path.read_text().rstrip("\n").rsplit("\n", 1)[-1]
        try:
            return json.loads(last).get("hash", "0" * 64)
        except json.JSONDecodeError:
            return "0" * 64

    def record(self, event: str, actor: str, **fields) -> str:
        body = {"ts": time.time(), "event": event, "actor": actor, **fields}
        payload = json.dumps(body, sort_keys=True, default=str)
        digest = hashlib.sha256((self._prev_hash + payload).encode()).hexdigest()
        record = {"body": body, "prev": self._prev_hash, "hash": digest}
        with self.path.open("a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
        self._prev_hash = digest
        return digest

    def verify(self) -> bool:
        prev = "0" * 64
        for line in self.path.read_text().splitlines():
            rec = json.loads(line)
            recomputed = hashlib.sha256(
                (prev + json.dumps(rec["body"], sort_keys=True, default=str)).encode()
            ).hexdigest()
            if rec["prev"] != prev or rec["hash"] != recomputed:
                return False
            prev = rec["hash"]
        return True
