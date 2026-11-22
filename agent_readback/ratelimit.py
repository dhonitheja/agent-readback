"""Cap how fast a verifier reads the system of record.

Every verifier reads through something you inject, so the limit goes there:

    limit = RateLimit(per_second=5, burst=10)
    FhirAppointmentVerifier(limit_reads(httpx.Client(...), limit))   # every GET, paging included
    SqlRowVerifier(limit_reads(connect, limit), "orders", "id")       # every connection

Share one ``RateLimit`` between all clients that count against the same quota.
Waiting is the only effect: a read is delayed, never dropped or failed, so a
limit cannot turn a verdict into ``failed``. A server that still answers 429
makes that read ``unverified``, as any read error does.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, TypeVar

import httpx

T = TypeVar("T")
_MARK = "_readback_rate_limit"  # set on a limited client's hook or connect wrapper


class RateLimitTimeout(httpx.TimeoutException):
    """A read would have waited longer than ``max_wait``. An httpx error, so every verifier reports ``unverified``."""


class RateLimit:
    """Token bucket (GCRA): bursts of up to ``burst`` reads, long-run rate ``per_second``. Thread-safe.

    It spaces reservations, not start times: callers that wake late from their
    sleep can start together. The long-run rate still holds.

    With ``max_wait`` (seconds), a read that would wait longer is not made: it
    raises ``RateLimitTimeout`` at once, uses no slot, and the verdict is
    ``unverified`` instead of the agent stalling behind a long queue.
    ``RateLimitTimeout`` subclasses ``httpx.TimeoutException``: do not let a
    retry-on-timeout wrapper retry it, or it spins against the limit.
    """

    def __init__(
        self, per_second: float, burst: int = 1,
        clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], Any] = time.sleep,
        *, max_wait: float | None = None,  # keyword-only, so clock and sleep keep their positions
    ) -> None:
        if not per_second > 0:  # also rejects NaN
            raise ValueError("per_second must be greater than 0")
        if type(burst) is not int or burst < 1:
            raise ValueError("burst must be an integer of at least 1")
        if max_wait is not None and not max_wait >= 0:  # also rejects NaN
            raise ValueError("max_wait must be None or at least 0")
        self.interval = 1.0 / per_second
        self.burst = burst
        self.max_wait = max_wait
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()
        self._next_free = clock()  # when the bucket would be full again (GCRA's "theoretical arrival time")

    def acquire(self) -> float:
        """Block until a read may start; return the seconds waited."""
        with self._lock:  # reserve a slot in order; sleep outside the lock
            now = self._clock()
            start = max(self._next_free, now)
            wait = start - (self.burst - 1) * self.interval - now
            wait = wait if wait > 1e-9 else 0.0  # float rounding must not refuse a read inside a fresh burst
            if self.max_wait is not None and wait > self.max_wait:
                raise RateLimitTimeout(f"read rate limit: would wait {wait:.2f}s, more than max_wait {self.max_wait}s")
            self._next_free = start + self.interval
        if wait:
            self._sleep(wait)
        return wait


def limit_reads(target: T, limit: RateLimit) -> T:
    """Apply ``limit`` to a verifier's read path and return it.

    ``target`` is an ``httpx.Client`` (FHIR, Stripe: each request waits, including
    paging) or a zero-argument ``connect`` callable (SQL: each connection waits).
    A target that is already limited is refused: a second limit would silently
    halve its rate. Share one ``RateLimit`` instead.
    """
    if isinstance(target, httpx.Client):
        hooks = target.event_hooks
        if any(hasattr(hook, _MARK) for hook in hooks.get("request", [])):
            raise ValueError("this client is already rate-limited; share one RateLimit instead of limiting it twice")

        def wait_for_slot(request: httpx.Request) -> None:
            limit.acquire()

        setattr(wait_for_slot, _MARK, limit)
        hooks["request"] = [*hooks.get("request", []), wait_for_slot]
        target.event_hooks = hooks
        return target
    if isinstance(target, httpx.AsyncClient):
        raise TypeError("verifiers read with a synchronous httpx.Client; an AsyncClient would block its event loop")
    if callable(target):
        if hasattr(target, _MARK):
            raise ValueError("this connect callable is already rate-limited; share one RateLimit instead")
        connect = target

        def limited_connect(*args: Any, **kwargs: Any) -> Any:
            limit.acquire()
            return connect(*args, **kwargs)

        setattr(limited_connect, _MARK, limit)
        return limited_connect  # type: ignore[return-value]
    raise TypeError(f"cannot rate-limit {type(target).__name__}: pass an httpx.Client or a connect callable")
