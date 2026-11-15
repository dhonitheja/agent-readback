"""Core types: a claim, a verifier that reads the real system, and a verdict.

The rule this library enforces: an agent never gets to declare its own success.
It makes a claim; a verifier the agent cannot write to reads the system of
record and decides.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
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


@dataclass(frozen=True)
class Claim:
    """What the agent says it did, plus what must be true if that is so."""

    action: str               # e.g. "fhir.appointment.create"
    agent_said: str           # the agent's own completion message, kept as evidence
    expected: dict[str, Any]  # field -> value that the system of record must show
    context: dict[str, Any] = field(default_factory=dict)  # run id, model name, etc.


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
        if have is None:
            findings.append(Finding(FindingKind.WRONG_VALUE, f"{name} is not set", name, want, None))
        elif have != want:
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
    yield held
    claim = held.claim or probe
    verdict = verifier.check(claim, before)
    for _ in range(max(settle_attempts, 1) - 1):
        if verdict.status is not Status.FAILED:
            break
        sleep(settle_delay)
        verdict = verifier.check(claim, before)
    held.verdict = verdict
    if log is not None:
        log.append(verdict)
    for callback in on_verdict:
        callback(verdict)
