import asyncio
import sqlite3
import threading
import time
from contextlib import closing

import httpx
import pytest

from agent_readback import Claim, FindingKind, RateLimit, RateLimitTimeout, Status, limit_reads, watch
from agent_readback.verifiers import FhirAppointmentVerifier, SqlRowVerifier

from .conftest import DOCTOR, END, PATIENT, START, create_claim


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(seconds, 6))
        self.now += seconds


def test_burst_then_steady_rate_then_refill_after_idle():
    clock = FakeClock()
    limit = RateLimit(per_second=5, burst=3, clock=clock, sleep=clock.sleep)
    waits = [round(limit.acquire(), 6) for _ in range(5)]
    assert waits == [0, 0, 0, 0.2, 0.2]  # three at once, then one every 0.2 s
    clock.now += 10  # idle: the bucket refills, but never beyond `burst`
    assert [round(limit.acquire(), 6) for _ in range(4)] == [0, 0, 0, 0.2]


@pytest.mark.parametrize("per_second, burst", [(0, 1), (-1, 1), (float("nan"), 1), (1, 0), (1, 1.5)])
def test_rejects_a_limit_that_would_never_or_wrongly_allow_reads(per_second, burst):
    with pytest.raises(ValueError):
        RateLimit(per_second, burst)


def test_fhir_verifier_waits_on_every_read_and_verdict_is_unchanged(server, tools):
    clock = FakeClock()
    limit = RateLimit(per_second=2, burst=1, clock=clock, sleep=clock.sleep)
    sent = []

    def handle(request):
        sent.append(request.url.path)
        return server._handle(request)

    client = limit_reads(httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test"), limit)
    with watch(FhirAppointmentVerifier(client), create_claim()) as watched:
        tools["book_appointment"](PATIENT, DOCTOR, START, END)
    assert watched.verdict.status is Status.VERIFIED
    assert len(sent) >= 2 and len(clock.slept) == len(sent) - 1  # every read after the first waited
    assert set(clock.slept) == {0.5}


def test_sql_connect_is_limited_and_reads_still_work(tmp_path):
    path = tmp_path / "orders.db"
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE orders (id TEXT, total INTEGER)")
    clock = FakeClock()
    limit = RateLimit(per_second=4, burst=1, clock=clock, sleep=clock.sleep)
    verifier = SqlRowVerifier(limit_reads(lambda: sqlite3.connect(path), limit), "orders", "id", placeholder="?")
    with watch(verifier, Claim("sql.row.insert", "DONE", {"id": "A1", "total": 5})) as watched:
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("INSERT INTO orders VALUES ('A1', 5)")
    assert watched.verdict.status is Status.VERIFIED
    assert clock.slept == [0.25]  # snapshot connection free, check connection waited


def test_threads_sharing_one_limit_never_exceed_it():
    limit = RateLimit(per_second=50, burst=1)  # real clock: 10 reads must span at least 9 intervals
    starts = []
    lock = threading.Lock()

    def read():
        limit.acquire()
        with lock:
            starts.append(time.monotonic())

    threads = [threading.Thread(target=lambda: [read() for _ in range(2)]) for _ in range(5)]
    began = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(starts) == 10
    assert max(starts) - began >= 9 * 0.02 * 0.9  # 10% slack for timer resolution, lower bound only


def test_wrong_targets_are_refused():
    limit = RateLimit(1)
    async_client = httpx.AsyncClient()
    try:
        with pytest.raises(TypeError, match="AsyncClient"):
            limit_reads(async_client, limit)
    finally:
        asyncio.run(async_client.aclose())
    with pytest.raises(TypeError, match="cannot rate-limit"):
        limit_reads("https://fhir.test", limit)


def test_existing_request_hooks_are_kept():
    seen = []
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        event_hooks={"request": [lambda request: seen.append("mine")]},
    )
    clock = FakeClock()
    limit_reads(client, RateLimit(1, clock=clock, sleep=clock.sleep)).get("https://x.test/")
    client.get("https://x.test/")
    assert seen == ["mine", "mine"] and clock.slept == [1.0]


def test_a_read_that_would_wait_past_max_wait_fails_fast_and_uses_no_slot():
    clock = FakeClock()
    limit = RateLimit(1, clock=clock, sleep=clock.sleep, max_wait=0.5)
    assert limit.acquire() == 0
    with pytest.raises(RateLimitTimeout, match="would wait 1.00s"):
        limit.acquire()  # next slot is 1 s away: more than max_wait
    assert clock.slept == []  # it did not sleep first
    clock.now += 1.0
    assert limit.acquire() == 0  # the refused read did not take the slot


def test_max_wait_makes_a_starved_verifier_unverified_instead_of_stalling(server, tools, tmp_path):
    clock = FakeClock()  # never advances on its own, so the second read always has to wait
    limit = RateLimit(1, clock=clock, sleep=clock.sleep, max_wait=0)
    client = limit_reads(httpx.Client(transport=httpx.MockTransport(server._handle), base_url="https://fhir.test"), limit)
    with watch(FhirAppointmentVerifier(client), create_claim()) as watched:
        tools["book_appointment"](PATIENT, DOCTOR, START, END)
    assert watched.verdict.status is Status.UNVERIFIED  # not FAILED, and no hang
    assert [f.kind for f in watched.verdict.findings] == [FindingKind.UNREACHABLE]
    assert clock.slept == []

    path = tmp_path / "orders.db"
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE orders (id TEXT, total INTEGER)")
    sql_limit = RateLimit(1, clock=clock, sleep=clock.sleep, max_wait=0)
    verifier = SqlRowVerifier(limit_reads(lambda: sqlite3.connect(path), sql_limit), "orders", "id", placeholder="?")
    with watch(verifier, Claim("sql.row.insert", "DONE", {"id": "A1", "total": 5})) as watched:
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("INSERT INTO orders VALUES ('A1', 5)")
    assert watched.verdict.status is Status.UNVERIFIED


@pytest.mark.parametrize("max_wait", [-1, float("nan")])
def test_rejects_a_negative_or_nan_max_wait(max_wait):
    with pytest.raises(ValueError, match="max_wait"):
        RateLimit(1, max_wait=max_wait)


def test_clock_and_sleep_still_work_by_position():
    clock = FakeClock()
    limit = RateLimit(2, 1, clock, clock.sleep)
    limit.acquire()
    limit.acquire()
    assert clock.slept == [0.5] and limit.max_wait is None


def test_limiting_the_same_target_twice_is_refused():
    limit = RateLimit(10)
    with httpx.Client() as client, httpx.Client() as other:
        limit_reads(client, limit)
        with pytest.raises(ValueError, match="already rate-limited"):
            limit_reads(client, limit)
        limit_reads(other, limit)  # a second client sharing the same limit is fine
    connect = limit_reads(lambda: None, limit)
    with pytest.raises(ValueError, match="already rate-limited"):
        limit_reads(connect, limit)
