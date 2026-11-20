"""Core types: a claim, a verifier that reads the real system, and a verdict.

The rule this library enforces: an agent never gets to declare its own success.
It makes a claim; a verifier the agent cannot write to reads the system of
record and decides.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Iterator, Protocol


class Status(str, Enum):
    VERIFIED = "verified"      # the system of record matches the claim, with no extra effects
    FAILED = "failed"          # the system of record contradicts the claim
    UNVERIFIED = "unverified"  # the check could not be completed; treat as an open item


class FindingKind(str, Enum):
    MISSING = "missing"            # the claimed effect is not there
    WRONG_VALUE = "wrong_value"    # the effect exists but a field differs
    EXTRA_EFFECT = "extra_effect"  # something changed that the claim did not cover
    UNREACHABLE = "unreachable"    # the system of record could not be read
    PENDING = "pending"            # the effect exists but has not settled yet; re-check later


@dataclass(frozen=True)
class Claim:
    """What the agent says it did, plus what must be true if that is so."""

    action: str               # e.g. "fhir.appointment.create"
    agent_said: str           # the agent's own completion message, kept as evidence
    expected: dict[str, Any]  # field -> value that the system of record must show
    context: dict[str, Any] = field(default_factory=dict)  # run id, model name, etc. Stored unredacted in the evidence log: no personal data here.


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    detail: str
    field: str | None = None
    expected: Any = None
    actual: Any = None


@dataclass(frozen=True)
class Verdict:
    status: Status
    claim: Claim
    findings: tuple[Finding, ...] = ()
    observed: dict[str, Any] | None = None  # what the system of record returned
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def ok(self) -> bool:
        return self.status is Status.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["findings"] = [{**f, "kind": f["kind"].value} for f in data["findings"]]
        return data


class Verifier(Protocol):
    """Reads one system of record. Must use credentials the agent does not hold."""

    def snapshot(self, claim: Claim) -> Any:
        """Capture state before the agent acts, so new and extra effects can be told apart."""

    def check(self, claim: Claim, before: Any) -> Verdict:
        """Read the system again and judge the claim."""


def compare_fields(expected: dict[str, Any], actual: dict[str, Any]) -> list[Finding]:
    """Return one finding per expected field that is absent or different."""
    findings: list[Finding] = []
    for name, want in expected.items():
        have = actual.get(name)
        if have == want:
            continue
        if have is None:
            findings.append(Finding(FindingKind.WRONG_VALUE, f"{name} is not set", name, want, None))
        else:
            findings.append(
                Finding(FindingKind.WRONG_VALUE, f"{name} is {have!r}, expected {want!r}", name, want, have)
            )
    return findings


class Watch:
    """Holds the claim and verdict for one watched action."""

    def __init__(self) -> None:
        self.claim: Claim | None = None
        self.verdict: Verdict | None = None

    def claims(self, claim: Claim) -> None:
        self.claim = claim

    def _record(self, verdict: Verdict, log: Any, on_verdict: Iterable[Callable[[Verdict], None]]) -> None:
        self.verdict = verdict
        if log is not None:
            log.append(verdict)
        for callback in on_verdict:
            callback(verdict)


def _check(
    verifier: Verifier,
    claim: Claim,
    before: Any,
    *,
    settle_attempts: int = 1,
    settle_delay: float = 0.5,
    sleep: Callable[[float], None] = time.sleep,
) -> Verdict:
    verdict = verifier.check(claim, before)
    for _ in range(max(settle_attempts, 1) - 1):
        if verdict.status is not Status.FAILED:
            break
        sleep(settle_delay)
        verdict = verifier.check(claim, before)
    return verdict


def recheck(
    verifier: Verifier,
    verdict: Verdict | dict[str, Any],
    log: Any | None = None,
    *,
    on_verdict: Iterable[Callable[[Verdict], None]] = (),
) -> Verdict:
    """Judge an unverified verdict again later, for example a refund the bank had not settled.

    `verdict` is the Verdict or its `to_dict()`. Keep that in your own queue:
    the evidence log redacts the claim, so it cannot be rebuilt from the log.
    The verifier needs a `recheck(claim, observed)` method; without one the
    result stays unverified. The new verdict is logged and passed to
    `on_verdict` with `context["recheck_of"]` set to the first `checked_at`.
    Only unverified verdicts are re-checked: a verified or failed verdict is
    already evidence and is never overturned.
    """
    if isinstance(verdict, dict):
        status, claim = Status(verdict["status"]), Claim(**verdict["claim"])
        observed, first = verdict.get("observed"), verdict["checked_at"]
    else:
        status, claim, observed, first = verdict.status, verdict.claim, verdict.observed, verdict.checked_at
    if status is not Status.UNVERIFIED:
        raise ValueError(f"only unverified verdicts are re-checked, not {status.value!r}")
    claim = replace(claim, context={**claim.context, "recheck_of": first})
    again = getattr(verifier, "recheck", None)
    if again is None or not observed:
        new = Verdict(Status.UNVERIFIED, claim, (Finding(FindingKind.UNREACHABLE, "nothing to re-check"),))
    else:
        new = again(claim, observed)
    Watch()._record(new, log, on_verdict)
    return new


@contextmanager
def watch(
    verifier: Verifier,
    probe: Claim,
    log: Any | None = None,
    *,
    settle_attempts: int = 1,
    settle_delay: float = 0.5,
    on_verdict: Iterable[Callable[[Verdict], None]] = (),
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[Watch]:
    """Snapshot before the agent acts, verify after, and record the result.

    `probe` describes what is about to be attempted, so the verifier knows where
    to look for the snapshot. Inside the block, call `w.claims(...)` with the
    final claim once the agent has reported back; otherwise `probe` is used.

    Some systems apply writes with a delay. Set `settle_attempts` above 1 to
    re-check a failed verdict that many times, `settle_delay` seconds apart,
    before accepting it. Unverified verdicts are not retried.

        with watch(verifier, probe, log, settle_attempts=3) as w:
            message = agent.book(...)
            w.claims(Claim(probe.action, message, probe.expected, probe.context))
        if not w.verdict.ok:
            escalate(w.verdict)
    """
    held = Watch()
    before = verifier.snapshot(probe)
    try:
        yield held
    finally:
        # Runs even when the agent raises: the system of record may have changed
        # before the crash, and that must leave a verdict and an evidence record.
        verdict = _check(
            verifier, held.claim or probe, before,
            settle_attempts=settle_attempts, settle_delay=settle_delay, sleep=sleep,
        )
        held._record(verdict, log, on_verdict)
