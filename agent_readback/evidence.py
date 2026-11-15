"""Append-only evidence log.

Each record carries the hash of the one before it, so an edited or deleted
record breaks the chain.

By default the log stores no values read from the system of record and no
agent text, because those can contain personal data. It stores field names,
whether each matched, and a SHA-256 of the agent's message. Pass `keep_fields`
to store the values of named fields, or `keep_fields="*"` to store everything.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .core import Verdict

GENESIS = "0" * 64
REDACTED = "[redacted]"


def _digest(prev: str, body: dict[str, Any]) -> str:
    payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def redact(body: dict[str, Any], keep: frozenset[str]) -> dict[str, Any]:
    """Return a copy of a verdict dict with values outside `keep` removed."""
    claim = body["claim"]
    said = claim.get("agent_said", "")
    out = {
        **body,
        "observed": None,
        "claim": {
            **claim,
            "agent_said": None,
            "agent_said_sha256": hashlib.sha256(said.encode()).hexdigest(),
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
    return out


class EvidenceLog:
    def __init__(self, path: str | Path, keep_fields: Iterable[str] | str = ()) -> None:
        self.path = Path(path)
        self.keep_all = keep_fields == "*"
        self.keep = frozenset() if self.keep_all else frozenset(keep_fields)
        self._last = GENESIS
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self._last = json.loads(line)["hash"]

    def append(self, verdict: Verdict) -> str:
        body = verdict.to_dict()
        if not self.keep_all:
            body = redact(body, self.keep)
        body = json.loads(json.dumps(body, default=str))  # store exactly what will be re-read
        record = {"prev": self._last, "body": body, "hash": _digest(self._last, body)}
        with self.path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        self._last = record["hash"]
        return self._last

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (True, None) if intact, else (False, index of first bad record)."""
        prev = GENESIS
        for index, record in enumerate(self.records()):
            if record["prev"] != prev or record["hash"] != _digest(prev, record["body"]):
                return False, index
            prev = record["hash"]
        return True, None
