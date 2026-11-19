"""Append-only evidence log.

Each record carries its sequence number and the hash of the record before it,
so an edited, deleted or reordered record breaks the chain.

Give the log a secret key (`key=` or the `READBACK_LOG_KEY` environment
variable) and every hash becomes an HMAC-SHA256: a party without the key
cannot rewrite the chain from genesis and present it as genuine. Without a
key the chain still detects accidental damage, but not deliberate forgery.

Truncation (dropping the newest records) cannot be detected from the file
alone. Record the head hash (`EvidenceLog.head`, printed by `readback
verify-log`) somewhere the log writer cannot reach, and compare.

By default the log stores no values read from the system of record and no
agent text, because those can contain personal data. It stores field names,
whether each matched, and a digest of the agent's message (HMAC when a key is
set). Pass `keep_fields` to store the values of named fields, or
`keep_fields="*"` to store everything. `Claim.context` (run id, model name)
is always stored as given: keep personal data out of it.

The file is created readable by its owner only (where the OS supports it) and
opened in append mode. Use one writer per file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Iterable

from .core import Verdict

GENESIS = "0" * 64
REDACTED = "[redacted]"
KEY_ENV = "READBACK_LOG_KEY"


def _key_from(key: bytes | str | None) -> bytes | None:
    if key is None:
        key = os.environ.get(KEY_ENV)
    if key is None or key == "":
        return None
    return key.encode() if isinstance(key, str) else key


def _mac(key: bytes | None, data: bytes) -> str:
    if key is None:
        return hashlib.sha256(data).hexdigest()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _digest(prev: str, seq: int, body: dict[str, Any], key: bytes | None) -> str:
    payload = f"{prev}:{seq}:" + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return _mac(key, payload.encode())


def redact(body: dict[str, Any], keep: frozenset[str], key: bytes | None = None) -> dict[str, Any]:
    """Return a copy of a verdict dict with values outside `keep` removed."""
    claim = body["claim"]
    said = claim.get("agent_said") or ""
    return {
        **body,
        "observed": None,
        "claim": {
            **claim,
            "agent_said": None,
            "agent_said_digest": _mac(key, said.encode()),
            "expected": {k: (v if k in keep else REDACTED) for k, v in claim["expected"].items()},
        },
        "findings": [
            {
                **finding,
                "detail": finding["detail"] if finding.get("field") in keep else finding["kind"],
                "expected": finding["expected"] if finding.get("field") in keep else REDACTED,
                "actual": finding["actual"] if finding.get("field") in keep else REDACTED,
            }
            for finding in body["findings"]
        ],
    }


class EvidenceLog:
    def __init__(
        self, path: str | Path, keep_fields: Iterable[str] | str = (), key: bytes | str | None = None
    ) -> None:
        self.path = Path(path)
        self.keep_all = keep_fields == "*"
        self.keep = frozenset() if self.keep_all else frozenset(keep_fields)
        self.key = _key_from(key)
        self._last = GENESIS
        self._count = 0
        for record in self.records():
            self._last = record["hash"]
            self._count += 1

    @property
    def head(self) -> str:
        """Hash of the newest record. Anchor it externally to detect truncation."""
        return self._last

    def append(self, verdict: Verdict) -> str:
        body = verdict.to_dict()
        if not self.keep_all:
            body = redact(body, self.keep, self.key)
        body = json.loads(json.dumps(body, default=str))  # store exactly what will be re-read
        seq = self._count
        record = {"seq": seq, "prev": self._last, "body": body, "hash": _digest(self._last, seq, body, self.key)}
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        self._last = record["hash"]
        self._count += 1
        return self._last

    def records(self) -> list[dict[str, Any]]:
        """All records in order. Raises ValueError on a line that is not a record."""
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not all(k in record for k in ("seq", "prev", "body", "hash")):
                    raise ValueError("missing fields")
            except ValueError as error:
                raise ValueError(f"line {number + 1} of {self.path} is not an evidence record: {error}") from None
            out.append(record)
        return out

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (True, None) if intact, else (False, index of first bad record)."""
        prev = GENESIS
        for index, record in enumerate(self.records()):
            if (
                record["seq"] != index
                or record["prev"] != prev
                or not hmac.compare_digest(record["hash"], _digest(prev, index, record["body"], self.key))
            ):
                return False, index
            prev = record["hash"]
        return True, None
