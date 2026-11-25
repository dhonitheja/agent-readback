"""Receipts: a portable, signed record that a claimed outcome was read back.

A receipt says what was claimed, which system of record was read, what the
verdict was and when, and nothing else. It holds no identifiers, amounts,
times or agent text: identifiers appear only as keyed digests, so a receipt
can be handed to a buyer, a vendor or an auditor without handing over payment
or health data. See docs/receipts/ for the requirements and threat model.

Every receipt carries an HMAC-SHA256 under a receipt key (`key=` or the
`READBACK_RECEIPT_KEY` environment variable). The key is required, must be at
least 32 bytes, and must differ from the evidence-log and alert keys: anyone
who holds it can check receipts and can also make them.

    receipts = ReceiptLog("receipts.jsonl")         # key from READBACK_RECEIPT_KEY
    receipt = issue_receipt(verdict, receipts.key, outcome_id="fin-00412")
    receipts.append(receipt)
    verify_receipt(receipt.to_dict(), receipts.key)  # -> None when intact
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

from .alerts import ALERT_KEY_ENV
from .core import FindingKind, Status, Verdict
from .evidence import KEY_ENV as LOG_KEY_ENV
from .evidence import EvidenceLog, is_log_key

RECEIPT_KEY_ENV = "READBACK_RECEIPT_KEY"
RECEIPT_VERSION = 1
MAC_ALG = "hmac-sha256"
MIN_KEY_BYTES = 32
_MAC_DOMAIN = b"readback-receipt-v1:"
_OUTCOME_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")  # first character never a spreadsheet formula
_ACTION = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+){1,4}$")
_RECEIPT_ID = re.compile(r"^rcpt_[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Value-free descriptions of each read-back, so a receipt says where it looked
# without saying which customer it looked at.
QUERIES = {
    "stripe.refund.create": "GET /v1/refunds?payment_intent={subject}",
    "fhir.appointment.create": "GET Appointment?patient={subject}",
    "fhir.appointment.update": "GET Appointment/{subject}",
    "fhir.appointment.cancel": "GET Appointment/{subject}",
    "sql.row.insert": "SELECT ... WHERE key = {subject}",
    "sql.row.update": "SELECT ... WHERE key = {subject}",
}
# Which expected fields name the thing that was read (digested, never stored).
SUBJECT_FIELDS = {
    "stripe.refund.create": ("payment_intent",),
    "fhir.appointment.create": ("patient",),
    "fhir.appointment.update": ("id", "patient"),
    "fhir.appointment.cancel": ("id", "patient"),
}


class ReceiptVerdict(str, Enum):
    VERIFIED = "verified"          # the outcome is in the system of record; the only billable verdict
    MISSING = "missing"            # the claimed outcome is not there
    CONTRADICTED = "contradicted"  # something is there but it differs, is extra, or already backs another outcome
    PENDING = "pending"            # it is there but not settled yet; re-check later
    UNVERIFIABLE = "unverifiable"  # the system of record could not be read completely

    @classmethod
    def from_verdict(cls, verdict: Verdict) -> "ReceiptVerdict":
        kinds = {finding.kind for finding in verdict.findings}
        if verdict.status is Status.VERIFIED:
            return cls.VERIFIED
        if verdict.status is Status.FAILED:
            return cls.MISSING if FindingKind.MISSING in kinds else cls.CONTRADICTED
        return cls.PENDING if FindingKind.PENDING in kinds else cls.UNVERIFIABLE


class ReceiptKeyError(ValueError):
    """The receipt key is missing, too short, or also used for something else."""


def receipt_key(key: bytes | str | None = None) -> bytes:
    """Resolve and check a receipt key: `key`, else READBACK_RECEIPT_KEY. Fails closed."""
    if key is None:
        key = os.environ.get(RECEIPT_KEY_ENV)
    if not key:
        raise ReceiptKeyError(f"a receipt key is required: pass key= or set {RECEIPT_KEY_ENV}")
    raw = key.encode() if isinstance(key, str) else bytes(key)
    if len(raw) < MIN_KEY_BYTES:
        raise ReceiptKeyError(f"the receipt key must be at least {MIN_KEY_BYTES} bytes")
    if is_log_key(raw):
        raise ReceiptKeyError(f"the receipt key must differ from {LOG_KEY_ENV}: receipts leave the machine, the log key must not")
    alert = os.environ.get(ALERT_KEY_ENV, "").encode()
    if alert and hmac.compare_digest(raw, alert):
        raise ReceiptKeyError(f"the receipt key must differ from {ALERT_KEY_ENV}")
    return raw


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def keyed_digest(key: bytes, label: str, value: Any) -> str:
    """HMAC-SHA256 of a labelled canonical value. The label keeps digests of different roles apart."""
    return hmac.new(key, label.encode() + b":" + canonical(value), hashlib.sha256).hexdigest()


def _subject(action: str, expected: dict[str, Any], subject_fields: Iterable[str] | None) -> dict[str, Any] | None:
    names = tuple(subject_fields) if subject_fields is not None else SUBJECT_FIELDS.get(action, ())
    subject = {name: expected[name] for name in names if name in expected}
    return subject or None


def effect_of(verdict: Verdict) -> str | None:
    """Name of the real-world effect a verified verdict matched, e.g. "stripe:refund:re_1"; None otherwise."""
    if verdict.status is not Status.VERIFIED or not isinstance(verdict.observed, dict):
        return None
    system, resource, verb = (verdict.claim.action.split(".") + ["", "", ""])[:3]
    current = verdict.observed.get("current")
    if isinstance(current, dict) and current.get("id"):
        return f"{system}:{resource}:{current['id']}:{verb}"
    created = verdict.observed.get("created")
    if isinstance(created, list) and len(created) == 1 and isinstance(created[0], dict) and created[0].get("id"):
        return f"{system}:{resource}:{created[0]['id']}"
    return None


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    outcome_id: str | None
    action: str
    system: str
    query: str
    verdict: str
    billable: bool
    reasons: tuple[dict[str, Any], ...]
    checked_at: str
    issued_at: str
    claim_digest: str
    subject_digest: str | None
    observed_digest: str | None
    effect_digest: str | None
    receipt_version: int = RECEIPT_VERSION
    mac_alg: str = MAC_ALG
    mac: str = field(default="", compare=False)

    def unsigned(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("mac")
        data["reasons"] = [dict(reason) for reason in self.reasons]
        return data

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "mac": self.mac}


def _mac(key: bytes, unsigned: dict[str, Any]) -> str:
    return hmac.new(key, _MAC_DOMAIN + canonical(unsigned), hashlib.sha256).hexdigest()


def issue_receipt(
    verdict: Verdict,
    key: bytes | str | None = None,
    *,
    outcome_id: str | None = None,
    effect: str | None = None,
    override: ReceiptVerdict | None = None,
    extra_reasons: Iterable[str] = (),
    subject_fields: Iterable[str] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Receipt:
    """Turn a Readback verdict into a signed receipt.

    `effect` names the matched real-world effect (defaults to `effect_of(verdict)`);
    only its keyed digest is stored. `override` and `extra_reasons` let
    reconciliation mark an effect that already backs another outcome.
    """
    secret = receipt_key(key)
    claim = verdict.claim
    if not _ACTION.fullmatch(claim.action):
        raise ValueError(f"unsafe action name: {claim.action!r}")
    if outcome_id is not None and not _OUTCOME_ID.fullmatch(outcome_id):
        raise ValueError("outcome_id must be 1-128 of A-Z a-z 0-9 . _ : - and start with a letter or digit")
    status = override or ReceiptVerdict.from_verdict(verdict)
    if status is ReceiptVerdict.VERIFIED and verdict.status is not Status.VERIFIED:
        raise ValueError("a receipt can only be verified when the read-back verified it")
    reasons = [{"kind": finding.kind.value, "field": finding.field} for finding in verdict.findings]
    reasons += [{"kind": kind, "field": None} for kind in extra_reasons]
    if effect is None:
        effect = effect_of(verdict)
    subject = _subject(claim.action, claim.expected, subject_fields)
    receipt = Receipt(
        receipt_id="rcpt_" + secrets.token_hex(16),
        outcome_id=outcome_id,
        action=claim.action,
        system=claim.action.split(".", 1)[0],
        query=QUERIES.get(claim.action, "verifier read-back"),
        verdict=status.value,
        billable=status is ReceiptVerdict.VERIFIED,
        reasons=tuple(reasons),
        checked_at=verdict.checked_at,
        issued_at=now().isoformat(),
        claim_digest=keyed_digest(secret, "claim", {"action": claim.action, "expected": claim.expected}),
        subject_digest=keyed_digest(secret, "subject", subject) if subject else None,
        observed_digest=keyed_digest(secret, "observed", verdict.observed) if verdict.observed is not None else None,
        effect_digest=effect_digest(secret, effect) if effect else None,
    )
    return Receipt(**{**receipt.__dict__, "mac": _mac(secret, receipt.unsigned())})


def effect_digest(key: bytes, effect: str) -> str:
    return keyed_digest(key, "effect", effect)


_FIELDS = {
    "receipt_version": int, "receipt_id": str, "outcome_id": (str, type(None)), "action": str, "system": str,
    "query": str, "verdict": str, "billable": bool, "reasons": list, "checked_at": str, "issued_at": str,
    "claim_digest": str, "subject_digest": (str, type(None)), "observed_digest": (str, type(None)),
    "effect_digest": (str, type(None)), "mac_alg": str, "mac": str,
}


def verify_receipt(receipt: dict[str, Any], key: bytes | str | None = None) -> str | None:
    """None if `receipt` is intact and was made with `key`; otherwise what is wrong.

    Checks the layout first, so a malformed receipt is reported, not crashed on.
    """
    secret = receipt_key(key)
    if not isinstance(receipt, dict):
        return "not a receipt object"
    if set(receipt) != set(_FIELDS):
        return "unexpected or missing fields"
    for name, kind in _FIELDS.items():
        # bool is an int subclass: `True` must not pass as version 1, and 1 must not pass as a bool
        if not isinstance(receipt[name], kind) or (kind is int and isinstance(receipt[name], bool)):
            return f"{name} has the wrong type"
    if receipt["receipt_version"] != RECEIPT_VERSION:
        return f"unsupported receipt_version {receipt['receipt_version']!r}"
    if receipt["mac_alg"] != MAC_ALG:
        return f"unsupported mac_alg {receipt['mac_alg']!r}"
    if not _RECEIPT_ID.fullmatch(receipt["receipt_id"]) or not _ACTION.fullmatch(receipt["action"]):
        return "bad receipt_id or action"
    if receipt["verdict"] not in {v.value for v in ReceiptVerdict}:
        return "unknown verdict"
    if receipt["billable"] is not (receipt["verdict"] == ReceiptVerdict.VERIFIED.value):
        return "billable does not match the verdict"
    for name in ("claim_digest", "subject_digest", "observed_digest", "effect_digest", "mac"):
        if receipt[name] is not None and not _HEX64.fullmatch(receipt[name]):
            return f"{name} must be 64 lowercase hex characters"
    unsigned = {k: v for k, v in receipt.items() if k != "mac"}
    if not hmac.compare_digest(receipt["mac"], _mac(secret, unsigned)):
        return "the MAC does not match: the receipt was edited or made with another key"
    return None


class ReceiptLog(EvidenceLog):
    """Append-only, hash-chained file of receipts, keyed with the receipt key.

    Same file guarantees as EvidenceLog (owner-only, append mode, optional
    anchor). It refuses to open a file that holds anything but receipts, so
    receipts never land in an evidence log.
    """

    _is_evidence_log = False

    @staticmethod
    def _resolve_key(key: bytes | str | None) -> bytes:
        return receipt_key(key)

    def __init__(self, path: str | Path, key: bytes | str | None = None, anchor: Any = None) -> None:
        super().__init__(path, key=key, anchor=anchor)
        for number, record in enumerate(self.records()):
            if record["body"].get("receipt_version") is None:
                raise ValueError(f"{self.path} is not a receipt log (record {number} is not a receipt)")

    def append(self, receipt: Receipt) -> str:  # type: ignore[override]
        if not isinstance(receipt, Receipt):
            raise TypeError("ReceiptLog.append takes a Receipt")
        problem = verify_receipt(receipt.to_dict(), self.key)
        if problem:
            raise ValueError(f"refusing to log a receipt that does not verify with this log's key: {problem}")
        with self._lock:
            return self._write(receipt.to_dict())

    def receipts(self) -> list[dict[str, Any]]:
        return [record["body"] for record in self.records()]

    def verify(self) -> list[str]:
        """Every problem found: a broken chain and each receipt that does not verify. Empty when intact."""
        problems: list[str] = []
        intact, bad = self.verify_chain()
        if not intact:
            problems.append(f"chain broken at record {bad} (line {bad + 1})")
        for number, body in enumerate(self.receipts()):
            problem = verify_receipt(body, self.key)
            if problem:
                problems.append(f"record {number}: {problem}")
        return problems
