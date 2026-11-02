from __future__ import annotations

import hashlib
import json
import os
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
            fh.flush()
            os.fsync(fh.fileno())
        self._prev_hash = digest
        return digest

    def verify(self) -> bool:
        """True if every record chains to the previous one.

        Note: a hash chain detects edits, insertions and deletions in the middle,
        but not truncation of the newest records — anchor the latest hash
        elsewhere (or sign it) if that matters for your engagement.
        """
        if not self.path.exists():
            return True
        prev = "0" * 64
        for line in self.path.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False
            if not isinstance(rec, dict) or "body" not in rec:
                return False
            recomputed = hashlib.sha256(
                (prev + json.dumps(rec["body"], sort_keys=True, default=str)).encode()
            ).hexdigest()
            if rec["prev"] != prev or rec["hash"] != recomputed:
                return False
            prev = rec["hash"]
        return True
