"""Append-only evidence log.

Each record carries its sequence number and the hash of the record before it,
so an edited, deleted or reordered record breaks the chain.

Give the log a secret key (`key=` or the `READBACK_LOG_KEY` environment
variable) and every hash becomes an HMAC-SHA256: a party without the key
cannot rewrite the chain from genesis and present it as genuine. Without a
key the chain still detects accidental damage, but not deliberate forgery.

Truncation (dropping the newest records) cannot be detected from the file
alone. Pass `anchor=` (for example `FileAnchor(path)`) and the log reports
its record count and head hash after every append to somewhere the log writer
cannot reach; `readback verify-log --anchor FILE` (or `--head HASH`) then
fails on a log that lost its newest records.

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
import re
import threading
import warnings
from pathlib import Path
from typing import Any, Callable, Iterable

from .core import Verdict

GENESIS = "0" * 64
REDACTED = "[redacted]"
KEY_ENV = "READBACK_LOG_KEY"
MAC_ALG = "hmac-sha256"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Fingerprints of every key an EvidenceLog in this process has used, so that
# WebhookAlert can refuse to sign with one (CodeRabbit #1). Per-process only:
# keys used by other processes are not visible here.
_LOG_KEY_FINGERPRINTS: set[str] = set()


def _fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"readback-log-key:" + key).hexdigest()


def is_log_key(key: bytes) -> bool:
    """True if `key` is READBACK_LOG_KEY or a key an EvidenceLog in this process uses."""
    env = os.environ.get(KEY_ENV, "").encode()
    return bool(key) and ((bool(env) and hmac.compare_digest(key, env)) or _fingerprint(key) in _LOG_KEY_FINGERPRINTS)


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


Anchor = Callable[[int, str], None]  # called with (record count, head hash) after each append
_SID = re.compile(r"^S-1-\d+(-\d+)+$")


def _owner_only(path: Path) -> None:
    """Windows ignores mode 0o600; drop inherited access so only the current user can open the log.

    Never raises: a failure warns, like a failing anchor, so the agent keeps running.
    """
    if os.name != "nt":
        return  # 0o600 at creation already does this
    import ctypes
    import subprocess  # fixed system tools, argument lists, no shell  # nosec B404

    # Nothing here comes from the environment: SystemRoot, PATH, USERNAME and
    # USERDOMAIN can all name the wrong thing (e.g. under `runas /env`), and a
    # grant to the wrong account locks this process out of its own log.
    buffer = ctypes.create_unicode_buffer(260)
    system32 = Path(buffer.value) if ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260) else None
    failed = "" if system32 else "could not locate the System32 directory"
    try:
        if not failed:  # whoami reads the SID from this process's own access token
            run = lambda *args: subprocess.run(  # noqa: E731  # absolute executable, list args  # nosec B603
                [str(system32 / args[0]), *args[1:]], capture_output=True, text=True, errors="replace", timeout=30
            )
            who = run("whoami.exe", "/user", "/fo", "csv", "/nh")
            sid = who.stdout.strip().rsplit(",", 1)[-1].strip('"') if who.returncode == 0 else ""
            if not _SID.match(sid):
                failed = f"could not read the current user's SID: {(who.stderr or who.stdout).strip()!r}"
            else:
                # /reset drops explicit entries (some hosts, e.g. GitHub's Windows runners,
                # put explicit ones on new files); /inheritance:r then drops inherited ones,
                # leaving only this SID. The file is still empty while this runs.
                for step in (("/reset",), ("/inheritance:r", "/grant:r", f"*{sid}:F")):
                    result = run("icacls.exe", str(path), *step)
                    if result.returncode != 0:  # icacls can fail without printing anything
                        failed = (result.stderr or result.stdout).strip() or f"icacls exited with {result.returncode}"
                        break
    except (OSError, subprocess.SubprocessError, ValueError) as error:  # ValueError: e.g. UnicodeDecodeError
        failed = str(error)
    if failed:
        warnings.warn(f"could not restrict {path} to the current user: {failed}", RuntimeWarning, stacklevel=5)


class FileAnchor:
    """Keep a log's newest (record count, head hash) in a separate small file.

    The log writer tries to replace this file after every append, so on its own
    it is only as safe as the log. Check against a copy that the writer cannot
    rewrite and that holds the current head, such as a synced replica whose
    history it cannot erase; an older copy (a backup) only proves the log still
    reaches that older head. Or pass an anchor callable that appends to an
    independent append-only store instead. A failed replacement does not stop
    the append: it warns and sets ``EvidenceLog.anchor_error``, so monitor that
    if you rely on the anchor. Whoever can edit both the log and the anchor copy
    you check against can still truncate undetected.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __call__(self, count: int, head: str) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps({"count": count, "head": head}), encoding="utf-8")
        os.replace(tmp, self.path)  # readers never see a half-written anchor

    def read(self) -> tuple[int, str]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            count, head = data["count"], data["head"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(f"{self.path} is not a Readback anchor: {error}") from None
        if type(count) is not int or count < 1 or not isinstance(head, str) or not _HEX64.match(head):
            raise ValueError(f"{self.path} is not a Readback anchor: bad count or head")
        return count, head


class EvidenceLog:
    def __init__(
        self, path: str | Path, keep_fields: Iterable[str] | str = (), key: bytes | str | None = None,
        anchor: Anchor | None = None,
    ) -> None:
        self.path = Path(path)
        self.anchor = anchor
        self.anchor_error: Exception | None = None
        self.keep_all = keep_fields == "*"
        self.keep = frozenset() if self.keep_all else frozenset(keep_fields)
        self.key = _key_from(key)
        if self.key:
            _LOG_KEY_FINGERPRINTS.add(_fingerprint(self.key))
        self._lock = threading.Lock()  # parallel tool calls (e.g. LangGraph ToolNode) share one log
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
        with self._lock:  # seq, prev and the file write must happen as one step
            return self._append(verdict)

    def _append(self, verdict: Verdict) -> str:
        body = verdict.to_dict()
        if not self.keep_all:
            body = redact(body, self.keep, self.key)
        body = json.loads(json.dumps(body, default=str))  # store exactly what will be re-read
        seq = self._count
        record = {"seq": seq, "prev": self._last, "body": body, "hash": _digest(self._last, seq, body, self.key)}
        if self.key is not None:
            # Informational, not hashed: lets a verifier without the key say "keyed log"
            # instead of "edited". A forger can delete it, so the CLI also flags every
            # keyless verification as not forgery-proof.
            record["mac"] = MAC_ALG
        if not self.path.exists():
            # Create it empty and restrict it before the first record is written.
            # ponytail: a process that opens the file in the moment between create and
            # restrict keeps that handle; a log folder only you can access closes that too.
            try:
                os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            except FileExistsError:
                pass  # another writer created it first and restricts it
            else:
                _owner_only(self.path)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as handle:  # same bytes on every OS
            handle.write(json.dumps(record) + "\n")
        self._last = record["hash"]
        self._count += 1
        if self.anchor is not None:
            try:
                self.anchor(self._count, self._last)
                self.anchor_error = None
            except Exception as error:  # never break the agent's flow; surface the gap instead
                self.anchor_error = error
                warnings.warn(f"evidence log anchor failed: {error}", RuntimeWarning, stacklevel=4)
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
                if not isinstance(record, dict):
                    raise ValueError("not a JSON object")
                if not all(k in record for k in ("seq", "prev", "body", "hash")):
                    raise ValueError("missing fields")
                if not isinstance(record["body"], dict):
                    raise ValueError("body must be an object")
                for name in ("hash", "prev"):  # compare_digest rejects non-ASCII strings with a TypeError
                    if not isinstance(record[name], str) or not _HEX64.match(record[name]):
                        raise ValueError(f"{name} must be 64 lowercase hex characters")
            except ValueError as error:
                raise ValueError(f"line {number + 1} of {self.path} is not an evidence record: {error}") from None
            out.append(record)
        return out

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (True, None) if intact, else (False, index of first bad record)."""
        prev = GENESIS
        for index, record in enumerate(self.records()):
            if (
                type(record["seq"]) is not int  # `True == 1` must not pass as seq 1
                or record["seq"] != index
                or record["prev"] != prev
                or not hmac.compare_digest(record["hash"], _digest(prev, index, record["body"], self.key))
            ):
                return False, index
            prev = record["hash"]
        return True, None

    def check_anchor(self, count: int, head: str) -> str | None:
        """None if record `count` of this log has hash `head`; otherwise what is wrong."""
        records = self.records()
        if len(records) < count:
            return f"the log has {len(records)} records but the anchor says {count}: newest records were dropped"
        if not hmac.compare_digest(records[count - 1]["hash"], head):
            return f"record {count - 1} (line {count}) does not match the anchored head: the log was rewritten"
        return None

    def needs_key(self) -> bool:
        """True if records say they were written with a key that this log does not have."""
        return self.key is None and any(record.get("mac") == MAC_ALG for record in self.records())
