"""Reconcile a vendor's outcome export against the system of record.

Input is a CSV (columns `outcome_id`, `action`, then expected fields) or JSONL
(`{"outcome_id": ..., "action": ..., "expected": {...}}`) file of outcomes an
agent claimed or was billed for. Each one is read back, through the same
read-only code the verifiers use, and gets a signed receipt.

There is no "before" snapshot after the fact, so the question is: does an
effect exist that matches this claim and does not already back another
outcome? Each real effect backs at most one outcome, in file order; effects
used by verified receipts in `prior` receipt logs count as already billed.

The file is untrusted: sizes are capped, ids and values are pattern-checked,
and no error message repeats a value from it.
"""

from __future__ import annotations

import csv
import errno
import hmac
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import AbstractSet, Any, Callable, Iterable

import httpx

from .core import Claim, Finding, FindingKind, Status, Verdict, compare_fields
from .receipts import (
    AlreadyBilled, Receipt, ReceiptKeyError, ReceiptLog, ReceiptVerdict, _OUTCOME_ID, effect_digest, outcome_ref,
    receipt_key,
)
from .receipts import issue_receipt as _issue  # wrapped per outcome in _one
from .verifiers.fhir import CANCEL as FHIR_CANCEL
from .verifiers.fhir import CREATE as FHIR_CREATE
from .verifiers.fhir import FHIR_ID, UPDATE as FHIR_UPDATE
from .verifiers.fhir import FhirAppointmentVerifier, _normalized
from .verifiers.stripe import CREATE as STRIPE_REFUND
from .verifiers.stripe import StripeRefundVerifier

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ROWS = 100_000
MAX_COLUMNS = 32
MAX_CELL = 1024

_REF = r"[A-Za-z0-9\-.]{1,64}"
_PATTERNS = {
    "payment_intent": re.compile(r"pi_[A-Za-z0-9_]{1,250}"),
    "currency": re.compile(r"[a-z]{3}"),
    "status": re.compile(r"[a-z][a-z_-]{0,31}"),
    "patient": re.compile(rf"Patient/{_REF}"),
    "practitioner": re.compile(rf"Practitioner/{_REF}"),
    "id": FHIR_ID,
    "start": re.compile(r"[0-9T:+\-.Z]{4,40}"),
    "end": re.compile(r"[0-9T:+\-.Z]{4,40}"),
}
# action -> (system, required fields, allowed fields)
ACTIONS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    STRIPE_REFUND: ("stripe", ("payment_intent", "amount", "currency"), ("payment_intent", "amount", "currency", "status")),
    FHIR_CREATE: ("fhir", ("patient",), ("patient", "practitioner", "start", "end", "status")),
    FHIR_UPDATE: ("fhir", ("id", "patient"), ("id", "patient", "practitioner", "start", "end", "status")),
    FHIR_CANCEL: ("fhir", ("id", "patient"), ("id", "patient")),
}
_KNOWN = {name for _, _, allowed in ACTIONS.values() for name in allowed} | {"outcome_id", "action"}


class ExportError(ValueError):
    """The outcome export cannot be used. The message names lines and columns, never values."""


@dataclass(frozen=True)
class Outcome:
    outcome_id: str
    claim: Claim
    line: int


def _value(name: str, raw: Any, where: str) -> Any:
    if name == "amount":
        if isinstance(raw, str) and re.fullmatch(r"[0-9]{1,12}", raw):
            return int(raw)
        if type(raw) is int and 0 <= raw < 10**12:  # not bool, not float
            return raw
        raise ExportError(f"{where}: amount must be a whole number in the smallest currency unit (e.g. 2500 for $25.00)")
    if not isinstance(raw, str) or len(raw) > MAX_CELL or not _PATTERNS[name].fullmatch(raw):
        raise ExportError(f"{where}: {name} is not in the expected format")
    if name == "id" and not raw.strip("."):
        raise ExportError(f"{where}: id is not in the expected format")
    return raw


def _outcome(row: dict[str, Any], where: str, system: str | None) -> Outcome:
    outcome_id, action = row.get("outcome_id"), row.get("action")
    if not isinstance(outcome_id, str) or not _OUTCOME_ID.fullmatch(outcome_id):
        raise ExportError(f"{where}: outcome_id must be 1-128 of A-Z a-z 0-9 . _ : - and start with a letter or digit")
    if not isinstance(action, str) or action not in ACTIONS:
        raise ExportError(f"{where}: unknown action (supported: {', '.join(sorted(ACTIONS))})")
    owner, required, allowed = ACTIONS[action]
    if system is not None and owner != system:
        raise ExportError(f"{where}: action {action} is not a {system} action")
    expected = row.get("expected")
    if not isinstance(expected, dict):
        raise ExportError(f"{where}: expected must be an object")
    unexpected = sorted(set(expected) - set(allowed))
    if unexpected:
        raise ExportError(f"{where}: fields not used by {action}: {', '.join(unexpected)}")
    missing = [name for name in required if name not in expected]
    if missing:
        raise ExportError(f"{where}: {action} needs {', '.join(missing)}")
    values = {name: _value(name, raw, where) for name, raw in expected.items()}
    return Outcome(outcome_id, Claim(action, "", values, {"outcome_id": outcome_id}), 0)


def load_outcomes(path: str | Path, *, system: str | None = None, max_rows: int = MAX_ROWS) -> list[Outcome]:
    """Parse a CSV or JSONL outcome export (by extension: .csv, else JSONL). Raises ExportError."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ExportError(f"{path.name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        text = path.read_text(encoding="utf-8-sig")
    except OSError as error:
        raise ExportError(f"cannot read {path.name}: {error.strerror or error}") from None
    except UnicodeDecodeError:
        raise ExportError(f"{path.name} is not UTF-8 text") from None
    rows = _csv_rows(text) if path.suffix.lower() == ".csv" else _jsonl_rows(text)
    outcomes: list[Outcome] = []
    for line, row in rows:
        if len(outcomes) >= max_rows:
            raise ExportError(f"more than {max_rows} outcomes; split the export or raise the limit")
        outcome = _outcome(row, f"line {line}", system)
        outcomes.append(Outcome(outcome.outcome_id, outcome.claim, line))
    if not outcomes:
        raise ExportError(f"{path.name} has no outcomes")
    return outcomes


def _csv_rows(text: str) -> Iterable[tuple[int, dict[str, Any]]]:
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        return
    except csv.Error:
        raise ExportError("line 1: not valid CSV") from None
    header = [name.strip() for name in header]
    if len(header) > MAX_COLUMNS or len(set(header)) != len(header):
        raise ExportError(f"line 1: at most {MAX_COLUMNS} columns, each named once")
    unknown = sorted(set(header) - _KNOWN)
    if unknown or "outcome_id" not in header or "action" not in header:
        raise ExportError("line 1: header must have outcome_id and action, plus only these fields: "
                          + ", ".join(sorted(_KNOWN - {"outcome_id", "action"})))
    try:
        for cells in reader:
            line = reader.line_num
            if not any(cell.strip() for cell in cells):
                continue
            if len(cells) != len(header):
                raise ExportError(f"line {line}: expected {len(header)} cells, found {len(cells)}")
            if any(len(cell) > MAX_CELL for cell in cells):
                raise ExportError(f"line {line}: a cell is longer than {MAX_CELL} characters")
            row = dict(zip(header, (cell.strip() for cell in cells), strict=True))
            expected = {k: v for k, v in row.items() if k not in ("outcome_id", "action") and v != ""}
            yield line, {"outcome_id": row["outcome_id"], "action": row["action"], "expected": expected}
    except csv.Error:
        raise ExportError(f"line {reader.line_num}: not valid CSV") from None


def _reject_constant(name: str) -> Any:
    raise ExportError(f"{name} is not allowed")


def _jsonl_rows(text: str) -> Iterable[tuple[int, dict[str, Any]]]:
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line) > 64 * MAX_CELL:
            raise ExportError(f"line {number}: longer than {64 * MAX_CELL} characters")
        try:
            row = json.loads(line, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            raise ExportError(f"line {number}: not a JSON object") from None
        if not isinstance(row, dict) or set(row) != {"outcome_id", "action", "expected"}:
            raise ExportError(f"line {number}: must be an object with exactly outcome_id, action and expected")
        yield number, row


def parse_since(value: str) -> int:
    """A date (2026-11-01, midnight UTC) or ISO datetime, as a Unix timestamp."""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("--since must be a date like 2026-11-01 or an ISO datetime") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


# -- finding effects -----------------------------------------------------------------

@dataclass
class _Found:
    """What the system of record holds for one claim."""

    matches: list[tuple[str, dict[str, Any]]] = field(default_factory=list)  # (effect, item) matching every field
    pending: list[tuple[str, dict[str, Any]]] = field(default_factory=list)  # match, but not settled
    contradicted: list[Finding] = field(default_factory=list)              # the claimed thing is there but differs
    error: str | None = None                                               # read error: unverifiable


class _Reads:
    """One read per subject per run, errors included, so a big export does not hammer the server."""

    def __init__(self, read: Callable[[str], Any]) -> None:
        self.read, self.cache = read, {}

    def __call__(self, subject: str) -> Any:
        if subject not in self.cache:
            try:
                self.cache[subject] = ("ok", self.read(subject))
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
                # Never keep the text: httpx errors quote the URL, which holds the subject.
                self.cache[subject] = ("error", type(error).__name__)
        return self.cache[subject]


METADATA_KEY = re.compile(r"[A-Za-z0-9_-]{1,40}")  # Stripe metadata keys are at most 40 characters


_REFUND_STATUSES = frozenset({"succeeded", "pending", "requires_action", "failed", "canceled"})


class StripeRefunds:
    """Stripe refunds for each claimed payment intent.

    `match_metadata` ties a refund to the outcome that caused it: the refund
    must carry `metadata[KEY] == outcome_id`, so a refund that only happens to
    match the amount cannot verify a claim it was not made for.
    """

    def __init__(self, verifier: StripeRefundVerifier, since: int | None = None, match_metadata: str | None = None) -> None:
        if match_metadata is not None and not METADATA_KEY.fullmatch(match_metadata):
            raise ValueError("match_metadata must be 1-40 of A-Z a-z 0-9 _ -")
        self.verifier, self.since, self.match_metadata = verifier, since, match_metadata
        self.reads = _Reads(verifier._refunds)

    def find(self, claim: Claim, outcome_id: str | None = None) -> _Found:
        outcome, refunds = self.reads(claim.expected["payment_intent"])
        if outcome == "error":
            return _Found(error=refunds)
        found = _Found()
        match_on = {k: v for k, v in claim.expected.items() if k != "status"}
        for refund_id, item in refunds.items():
            if self.since is not None:
                if type(item.get("created")) is not int:
                    return _Found(error="refund without a creation time")
                if item["created"] < self.since:
                    continue
            if self.match_metadata is not None:
                metadata = item.get("metadata")
                if not isinstance(metadata, dict) or metadata.get(self.match_metadata) != outcome_id:
                    continue
            item = {k: v for k, v in item.items() if k != "metadata"}  # never digest free-form metadata
            if compare_fields(match_on, item):
                continue
            effect = f"stripe:refund:{refund_id}"
            status = item.get("status")
            if not isinstance(status, str) or status not in _REFUND_STATUSES:
                # Settlement cannot be told from a missing or unknown status.
                return _Found(error="refund without a known status")
            if "status" in claim.expected and status != claim.expected["status"]:
                found.contradicted.append(Finding(FindingKind.WRONG_VALUE, "status differs", "status"))
            elif status in ("failed", "canceled"):
                found.contradicted.append(Finding(FindingKind.WRONG_VALUE, "refund did not go through", "status"))
            elif status != "succeeded":
                # Pending or waiting on the customer is never billable, even
                # when the export itself claims that status.
                found.pending.append((effect, item))
            else:
                found.matches.append((effect, item))
        return found


class FhirAppointments:
    def __init__(self, verifier: FhirAppointmentVerifier) -> None:
        self.verifier = verifier
        self.lists = _Reads(verifier._appointments)
        self.ones = _Reads(verifier._one)

    def find(self, claim: Claim, outcome_id: str | None = None) -> _Found:
        expected = _normalized(claim.expected)
        if claim.action == FHIR_CREATE:
            outcome, items = self.lists(expected["patient"])
            if outcome == "error":
                return _Found(error=items)
            return _Found(matches=[
                (f"fhir:appointment:{key}", item) for key, item in items.items() if not compare_fields(expected, item)
            ])
        outcome, current = self.ones(expected["id"])
        if outcome == "error":
            return _Found(error=current)
        if current is None:
            return _Found()  # gone: missing
        verb = claim.action.rsplit(".", 1)[-1]
        if claim.action == FHIR_CANCEL:
            expected = {"id": expected["id"], "patient": expected["patient"], "status": "cancelled"}
        differs = compare_fields(expected, current)
        if differs:
            # Kind and field only: the values are health data.
            return _Found(contradicted=[Finding(f.kind, f"{f.field} differs", f.field) for f in differs])
        return _Found(matches=[(f"fhir:appointment:{current['id']}:{verb}", current)])


# -- reconciliation ---------------------------------------------------------------

def prior_effects(paths: Iterable[str | Path], key: bytes | str | None = None, *, public_key: Any = None) -> set[str]:
    """Effect digests already billed: from verified receipts in earlier receipt logs (chain checked).

    `public_key` checks Ed25519-signed receipts in those logs.
    """
    secret = receipt_key(key)
    used: set[str] = set()
    for path in paths:
        if not Path(path).is_file():
            # A misspelt path must not read as an empty history.
            raise FileNotFoundError(errno.ENOENT, f"prior receipt log {Path(path).name} not found", str(path))
        used |= _billed(ReceiptLog(path, key=secret, public_key=public_key), "prior receipt log")
    return used


def _billed(log: ReceiptLog, what: str) -> set[str]:
    problems = log.verify()
    if problems:
        raise ValueError(f"{what} {log.path.name} does not verify: {problems[0]}")
    return {r["effect_digest"] for r in log.receipts() if r["verdict"] == ReceiptVerdict.VERIFIED.value and r["effect_digest"]}


def reconcile(
    outcomes: Iterable[Outcome],
    finder: StripeRefunds | FhirAppointments,
    key: bytes | str | None = None,
    *,
    prior: AbstractSet[str] = frozenset(),
    receipts: ReceiptLog | None = None,
    keep_outcome_ids: bool = False,
    labels: dict[str, str] | None = None,
    signing_key: Any = None,
) -> list[Receipt]:
    """Read back every outcome in order and return (and log, if `receipts`) one receipt each.

    Receipts carry a keyed stand-in for each outcome id (`oid_...`) unless
    `keep_outcome_ids`, because a vendor's references can hold personal data.
    Pass a `labels` dict to get receipt_id -> original outcome id for your own report.
    Signs with `signing_key`, else the receipt log's signing key, if either is set.
    Effects already billed in `receipts` count as `prior`, so a rerun into the
    same log cannot bill them twice. If another reconcile sharing that log
    bills an effect first, this run logs `already_billed` for it instead.
    With `receipts`, `key` defaults to that log's key, and a different key is
    refused: effects digested under another key would not match the ones the
    log already billed, so the same effect could be billed again.
    """
    if receipts is not None and key is None:
        key = receipts.key
    secret = receipt_key(key)
    if receipts is not None and not hmac.compare_digest(secret, receipts.key):
        raise ReceiptKeyError("the reconcile key must be the receipt log's key, or the log's billed effects cannot be matched")
    if signing_key is None and receipts is not None:
        signing_key = receipts.signing_key
    if receipts is not None:
        # A rerun into the same log must not bill again what that log already billed.
        prior = frozenset(prior) | _billed(receipts, "receipt log")
    prior, used = frozenset(prior), set(prior)
    seen_ids: set[str] = set()
    out: list[Receipt] = []
    for outcome in outcomes:
        ref = outcome.outcome_id if keep_outcome_ids else outcome_ref(secret, outcome.outcome_id)
        receipt = _one(outcome, ref, finder, secret, used, seen_ids, prior, signing_key)
        if receipts is not None:
            try:
                receipts.append(receipt)
            except AlreadyBilled:
                # An overlapping run billed this effect after our history was read.
                receipt = _issue(Verdict(Status.FAILED, outcome.claim), secret, outcome_id=ref, signing_key=signing_key,
                                 override=ReceiptVerdict.CONTRADICTED, extra_reasons=["already_billed"])
                receipts.append(receipt)
        if labels is not None:
            labels[receipt.receipt_id] = outcome.outcome_id
        out.append(receipt)
    return out


def _one(outcome: Outcome, ref: str, finder: Any, key: bytes, used: set[str], seen_ids: set[str],
         prior: AbstractSet[str], signing_key: Any) -> Receipt:
    claim, oid = outcome.claim, outcome.outcome_id

    def issue_receipt(verdict: Verdict, key: bytes, **options: Any) -> Receipt:
        return _issue(verdict, key, outcome_id=ref, signing_key=signing_key, **options)

    if oid in seen_ids:
        verdict = Verdict(Status.FAILED, claim)
        return issue_receipt(verdict, key, override=ReceiptVerdict.CONTRADICTED,
                             extra_reasons=["duplicate_outcome"])
    seen_ids.add(oid)
    found = finder.find(claim, oid)
    if found.error is not None:
        verdict = Verdict(Status.UNVERIFIED, claim, (Finding(FindingKind.UNREACHABLE, "read failed"),))
        return issue_receipt(verdict, key)
    for pool, status in ((found.matches, Status.VERIFIED), (found.pending, Status.UNVERIFIED)):
        for effect, item in pool:
            digest = effect_digest(key, effect)
            if digest in used:
                continue
            used.add(digest)
            findings = () if status is Status.VERIFIED else (Finding(FindingKind.PENDING, "not settled yet"),)
            verdict = Verdict(status, claim, findings, {"matched": item})
            return issue_receipt(verdict, key, effect=effect)
    if found.matches or found.pending:
        # Something matches, but it already backs another outcome: earlier in this file, or billed before.
        digests = {effect_digest(key, e) for e, _ in found.matches + found.pending}
        reason = "already_billed" if digests <= prior else "duplicate_effect"
        return issue_receipt(Verdict(Status.FAILED, claim), key,
                             override=ReceiptVerdict.CONTRADICTED, extra_reasons=[reason])
    if found.contradicted:
        return issue_receipt(Verdict(Status.FAILED, claim, tuple(found.contradicted)), key)
    missing = Finding(FindingKind.MISSING, "no matching effect in the system of record")
    return issue_receipt(Verdict(Status.FAILED, claim, (missing,)), key)


def summarise(receipts: Iterable[Receipt | dict[str, Any]], labels: dict[str, str] | None = None) -> dict[str, Any]:
    """Billed against verified. `labels` (from `reconcile`) shows your own outcome ids instead of `oid_...`."""
    rows = [r.to_dict() if isinstance(r, Receipt) else r for r in receipts]
    labels = labels or {}
    counts = {v.value: 0 for v in ReceiptVerdict}
    for row in rows:
        counts[row["verdict"]] += 1
    billed = len(rows)
    verified = counts[ReceiptVerdict.VERIFIED.value]
    return {
        "billed": billed,
        "verified": verified,
        "verified_rate": round(verified / billed, 4) if billed else None,
        "counts": counts,
        "not_verified": [
            {"outcome_id": labels.get(row["receipt_id"], row["outcome_id"]), "verdict": row["verdict"], "reasons": sorted({r["kind"] for r in row["reasons"]})}
            for row in rows if row["verdict"] != ReceiptVerdict.VERIFIED.value
        ],
    }


def render(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    rate = "n/a" if summary["verified_rate"] is None else f"{summary['verified_rate']:.1%}"
    lines = [
        f"{summary['billed']} billed, {summary['verified']} verified ({rate})",
        "  " + ", ".join(f"{name} {counts[name]}" for name in counts),
    ]
    if summary["not_verified"]:
        lines.append("Not verified:")
        lines += [
            f"  {row['outcome_id']}  {row['verdict']}" + (f"  ({', '.join(row['reasons'])})" if row["reasons"] else "")
            for row in summary["not_verified"]
        ]
    return "\n".join(lines)


__all__ = [
    "ExportError", "FhirAppointments", "Outcome", "StripeRefunds", "load_outcomes", "parse_since",
    "prior_effects", "reconcile", "render", "summarise",
]
