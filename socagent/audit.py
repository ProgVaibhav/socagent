"""Tamper-evident audit log.

Every model call, tool call and approval decision is appended as one JSON line
with a sequence number and the SHA-256 of the previous entry, so an edited or
deleted line breaks the chain.

What a local hash chain does NOT stop: an attacker who can rewrite the whole
file can recompute every hash, and silently truncating the tail leaves a valid
shorter chain. So in production:
  * ship every entry to append-only remote storage (SIEM, WORM bucket) as written,
  * publish HMAC-signed checkpoints (sequence number + hash) to a separate system
    the agent host cannot write to, and verify the log against the latest one,
  * restrict who can write the log, and alert when shipping stops.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None, checkpoint_key: bytes | None = None):
        self.path = Path(path) if path else None
        self.key = checkpoint_key
        self.entries: list[dict[str, Any]] = []
        self._prev = GENESIS
        self._seq = 0

    def log(self, event: str, **data: Any) -> dict[str, Any]:
        entry = {"seq": self._seq, "ts": datetime.now(timezone.utc).isoformat(),
                 "event": event, "data": data, "prev": self._prev}
        entry["hash"] = _digest(entry)
        if self.path:  # write first: if the write fails, the entry does not count as logged
            with self.path.open("a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        self._prev, self._seq = entry["hash"], self._seq + 1
        self.entries.append(entry)
        return entry

    def checkpoint(self) -> dict[str, Any]:
        """Signed (seq, hash) of the latest entry. Store it where the agent cannot write."""
        if not self.key:
            raise ValueError("checkpoint_key required")
        last = self.entries[-1] if self.entries else {"seq": -1, "hash": GENESIS}
        msg = f"{last['seq']}:{last['hash']}".encode()
        return {"seq": last["seq"], "hash": last["hash"],
                "sig": hmac.new(self.key, msg, hashlib.sha256).hexdigest()}

    @staticmethod
    def verify(entries: list[dict[str, Any]], checkpoint: dict[str, Any] | None = None,
               key: bytes | None = None) -> bool:
        prev = GENESIS
        for i, e in enumerate(entries):
            if e.get("seq") != i or e.get("prev") != prev or _digest(e) != e.get("hash"):
                return False
            prev = e["hash"]
        if checkpoint is not None:
            if key is None:
                return False
            msg = f"{checkpoint['seq']}:{checkpoint['hash']}".encode()
            if not hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).hexdigest(), checkpoint["sig"]):
                return False
            # Truncation or rollback: the log must reach the checkpointed entry, unchanged.
            if checkpoint["seq"] >= len(entries) or entries[checkpoint["seq"]]["hash"] != checkpoint["hash"]:
                return False
        return True
