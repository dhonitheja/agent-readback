import pytest
import json
import sqlite3
from contextlib import closing

import httpx

from agent_readback import Claim, EvidenceLog, FindingKind, Status, WebhookAlert, recheck, watch
from agent_readback.verifiers import SqlRowVerifier, StripeRefundVerifier


class MockStripe:
    def __init__(self):
        self.refunds = []
        self.down = False

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self._handle), base_url="https://stripe.test")

    def refund(self, payment_intent, amount, currency="usd", status="succeeded"):
        self.refunds.append(
            {"id": f"re_{len(self.refunds) + 1}", "payment_intent": payment_intent, "amount": amount, "currency": currency, "status": status, "charge": "ch_1"}
        )

    def _handle(self, request):
        if self.down:
            return httpx.Response(500, json={"error": "down"})
        wanted = request.url.params.get("payment_intent")
        return httpx.Response(200, json={"data": [r for r in self.refunds if r["payment_intent"] == wanted], "has_more": False})


REFUND = Claim("stripe.refund.create", "DONE: refunded $25", {"payment_intent": "pi_1", "amount": 2500, "currency": "usd"})


def stripe_run(action):
    stripe = MockStripe()
    stripe.refund("pi_1", 1000)        # an older refund that must not count
    stripe.refund("pi_other", 2500)    # another customer's refund
    with watch(StripeRefundVerifier(stripe.client()), REFUND) as watched:
        action(stripe)
    return watched.verdict


def kinds(verdict):
    return [finding.kind for finding in verdict.findings]


def test_stripe_refund_verified():
    assert stripe_run(lambda s: s.refund("pi_1", 2500)).status is Status.VERIFIED


def test_stripe_refund_never_issued():
    verdict = stripe_run(lambda s: None)
    assert verdict.status is Status.FAILED and kinds(verdict) == [FindingKind.MISSING]


def test_stripe_wrong_amount_and_failed_status():
    verdict = stripe_run(lambda s: s.refund("pi_1", 250, status="failed"))
    assert verdict.status is Status.FAILED
    assert sorted(f.field for f in verdict.findings) == ["amount", "status"]


def test_stripe_double_refund_is_an_extra_effect():
    def twice(stripe):
        stripe.refund("pi_1", 2500)
        stripe.refund("pi_1", 2500)

    verdict = stripe_run(twice)
    assert verdict.status is Status.FAILED and kinds(verdict) == [FindingKind.EXTRA_EFFECT]


def test_stripe_unreachable_is_unverified():
    def go_down(stripe):
        stripe.refund("pi_1", 2500)
        stripe.down = True

    assert stripe_run(go_down).status is Status.UNVERIFIED


def make_db(tmp_path):
    path = str(tmp_path / "app.db")
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT, total INTEGER)")
        db.execute("INSERT INTO orders VALUES ('o1', 'open', 500)")
    return path


def sql_run(tmp_path, action_name, expected, statements):
    path = make_db(tmp_path)
    verifier = SqlRowVerifier(lambda: sqlite3.connect(path), "orders", "id", placeholder="?")
    with watch(verifier, Claim(action_name, "DONE", expected)) as watched:
        with closing(sqlite3.connect(path)) as db, db:
            for statement in statements:
                db.execute(statement)
    return watched.verdict


def test_sql_insert_verified_and_missing(tmp_path):
    expected = {"id": "o2", "status": "open", "total": 900}
    good = sql_run(tmp_path, "sql.row.insert", expected, ["INSERT INTO orders VALUES ('o2', 'open', 900)"])
    assert good.status is Status.VERIFIED
    (tmp_path / "app.db").unlink()
    missing = sql_run(tmp_path, "sql.row.insert", expected, [])
    assert missing.status is Status.FAILED and kinds(missing) == [FindingKind.MISSING]


def test_sql_insert_with_an_unclaimed_extra_row(tmp_path):
    verdict = sql_run(
        tmp_path,
        "sql.row.insert",
        {"id": "o2", "status": "open", "total": 900},
        ["INSERT INTO orders VALUES ('o2', 'open', 900)", "INSERT INTO orders VALUES ('o3', 'open', 900)"],
    )
    assert verdict.status is Status.FAILED and kinds(verdict) == [FindingKind.EXTRA_EFFECT]


def test_sql_insert_with_deleted_existing_row(tmp_path):
    verdict = sql_run(
        tmp_path,
        "sql.row.insert",
        {"id": "o2", "status": "open", "total": 900},
        ["INSERT INTO orders VALUES ('o2', 'open', 900)", "DELETE FROM orders WHERE id = 'o1'"],
    )
    assert verdict.status is Status.FAILED
    assert kinds(verdict) == [FindingKind.EXTRA_EFFECT]


def test_sql_update_wrong_value_and_deleted_rows(tmp_path):
    wrong = sql_run(tmp_path, "sql.row.update", {"id": "o1", "status": "paid"}, ["UPDATE orders SET status = 'void' WHERE id = 'o1'"])
    assert wrong.status is Status.FAILED and [f.field for f in wrong.findings] == ["status"]
    (tmp_path / "app.db").unlink()
    good = sql_run(tmp_path, "sql.row.update", {"id": "o1", "status": "paid"}, ["UPDATE orders SET status = 'paid' WHERE id = 'o1'"])
    assert good.status is Status.VERIFIED


def test_sql_rejects_unsafe_identifiers(tmp_path):
    try:
        SqlRowVerifier(lambda: None, "orders; DROP TABLE orders", "id")
    except ValueError:
        return
    raise AssertionError("unsafe table name was accepted")


def test_webhook_fires_only_for_problems_and_carries_no_values():
    sent = []

    def handle(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200)

    alert = WebhookAlert("https://hooks.test/x", httpx.Client(transport=httpx.MockTransport(handle)))
    stripe = MockStripe()
    verifier = StripeRefundVerifier(stripe.client())
    with watch(verifier, REFUND, on_verdict=[alert]):
        stripe.refund("pi_1", 2500)
    assert sent == []
    with watch(verifier, REFUND, on_verdict=[alert]):
        pass
    assert len(sent) == 1 and sent[0]["status"] == "failed"
    assert "pi_1" not in json.dumps(sent[0]) and "2500" not in json.dumps(sent[0])


def test_stripe_pending_refund_is_unverified_not_verified():
    verdict = stripe_run(lambda s: s.refund("pi_1", 2500, status="pending"))
    assert verdict.status is Status.UNVERIFIED and kinds(verdict) == [FindingKind.PENDING]


def test_stripe_pending_refund_with_wrong_amount_is_failed_not_pending():
    verdict = stripe_run(lambda s: s.refund("pi_1", 250, status="pending"))
    assert verdict.status is Status.FAILED and [f.field for f in verdict.findings] == ["amount"]


def pending_then(settle, tmp_path=None, as_dict=False):
    stripe = MockStripe()
    stripe.refund("pi_1", 1000)
    verifier = StripeRefundVerifier(stripe.client())
    with watch(verifier, REFUND) as watched:
        stripe.refund("pi_1", 2500, status="pending")
    first = watched.verdict
    assert kinds(first) == [FindingKind.PENDING]
    settle(stripe)
    stored = json.loads(json.dumps(first.to_dict())) if as_dict else first
    log = EvidenceLog(tmp_path / "e.jsonl") if tmp_path else None
    return first, recheck(verifier, stored, log), log


def test_recheck_turns_a_settled_refund_into_verified(tmp_path):
    first, again, log = pending_then(lambda s: s.refunds[1].update(status="succeeded"), tmp_path, as_dict=True)
    assert again.status is Status.VERIFIED
    assert again.claim.context["recheck_of"] == first.checked_at
    assert log.verify_chain()[0] and log.records()[-1]["body"]["status"] == "verified"


def test_recheck_catches_a_refund_the_bank_failed():
    _, again, _ = pending_then(lambda s: s.refunds[1].update(status="failed"))
    assert again.status is Status.FAILED and [f.field for f in again.findings] == ["status"]


def test_recheck_still_pending_stays_unverified():
    _, again, _ = pending_then(lambda s: None)
    assert again.status is Status.UNVERIFIED and kinds(again) == [FindingKind.PENDING]


def test_recheck_ignores_refunds_created_after_the_first_check():
    _, again, _ = pending_then(lambda s: (s.refunds[1].update(status="succeeded"), s.refund("pi_1", 500)))
    assert again.status is Status.VERIFIED


def test_recheck_unreachable_and_bad_observed_stay_unverified():
    first, again, _ = pending_then(lambda s: setattr(s, "down", True))
    assert again.status is Status.UNVERIFIED and kinds(again) == [FindingKind.UNREACHABLE]
    assert again.observed == first.observed  # can be queued again
    verifier = StripeRefundVerifier(MockStripe().client())
    for bad in ({"created": "re_2"}, {"created": [{"no_id": 1}]}, {"other": 1}):
        assert verifier.recheck(REFUND, bad).status is Status.UNVERIFIED


def test_recheck_reads_stripe_once():
    stripe = MockStripe()
    verifier = StripeRefundVerifier(stripe.client())
    with watch(verifier, REFUND) as watched:
        stripe.refund("pi_1", 2500, status="pending")
    stripe.refunds[0]["status"] = "succeeded"
    reads = []
    real = verifier._refunds
    verifier._refunds = lambda pi: (reads.append(pi), stripe.refund("pi_1", 700), real(pi))[2]  # a refund lands mid-check
    assert recheck(verifier, watched.verdict).status is Status.VERIFIED and reads == ["pi_1"]


def test_recheck_of_a_recheck_keeps_the_first_time():
    first, again, _ = pending_then(lambda s: None)
    assert recheck(StripeRefundVerifier(MockStripe().client()), again).claim.context["recheck_of"] == first.checked_at


def test_recheck_never_overturns_a_verified_or_failed_verdict():
    verifier = StripeRefundVerifier(MockStripe().client())
    for verdict in (stripe_run(lambda s: s.refund("pi_1", 2500)), stripe_run(lambda s: None)):
        with pytest.raises(ValueError):
            recheck(verifier, verdict)
        with pytest.raises(ValueError):
            recheck(verifier, verdict.to_dict())


def test_webhook_with_a_bad_url_never_breaks_the_agent():
    alert = WebhookAlert("not a url")
    stripe = MockStripe()
    with watch(StripeRefundVerifier(stripe.client()), REFUND, on_verdict=[alert]):
        pass
    assert alert.last_error is not None


def test_webhook_is_signed_when_a_key_is_set():
    import hashlib
    import hmac

    seen = {}

    def handle(request):
        seen["sig"] = request.headers.get("X-Readback-Signature")
        seen["body"] = request.content
        return httpx.Response(200)

    alert = WebhookAlert("https://hooks.test/x", httpx.Client(transport=httpx.MockTransport(handle)), key="k")
    stripe = MockStripe()
    with watch(StripeRefundVerifier(stripe.client()), REFUND, on_verdict=[alert]):
        pass
    expected = "sha256=" + hmac.new(b"k", seen["body"], hashlib.sha256).hexdigest()
    assert seen["sig"] == expected


def test_stripe_endless_pagination_is_unverified_not_a_hang():
    def handle(request):
        return httpx.Response(200, json={"data": [{"id": "re_x", "payment_intent": "pi_1"}], "has_more": True})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="https://stripe.test")
    verdict = StripeRefundVerifier(client).check(REFUND, before=set())
    assert verdict.status is Status.UNVERIFIED


def test_webhook_never_signs_with_the_evidence_log_key(monkeypatch):
    import hashlib
    import hmac

    seen = []

    def handle(request):
        seen.append(request.headers.get("X-Readback-Signature"))
        return httpx.Response(200)

    monkeypatch.setenv("READBACK_LOG_KEY", "log-key")
    monkeypatch.delenv("READBACK_ALERT_KEY", raising=False)
    stripe = MockStripe()
    verifier = StripeRefundVerifier(stripe.client())
    alert = WebhookAlert("https://hooks.test/x", httpx.Client(transport=httpx.MockTransport(handle)))
    with watch(verifier, REFUND, on_verdict=[alert]):
        pass
    assert seen == [None]  # receiver gets nothing derived from the log key

    monkeypatch.setenv("READBACK_ALERT_KEY", "alert-key")
    bodies = []
    alert = WebhookAlert(
        "https://hooks.test/x",
        httpx.Client(transport=httpx.MockTransport(lambda r: bodies.append(r) or httpx.Response(200))),
    )
    with watch(verifier, REFUND, on_verdict=[alert]):
        pass
    body = bodies[0].content
    assert bodies[0].headers["X-Readback-Signature"] == "sha256=" + hmac.new(b"alert-key", body, hashlib.sha256).hexdigest()
    assert bodies[0].headers["X-Readback-Signature"] != "sha256=" + hmac.new(b"log-key", body, hashlib.sha256).hexdigest()


def test_alert_key_equal_to_the_log_key_is_refused(monkeypatch):
    monkeypatch.setenv("READBACK_LOG_KEY", "same")
    monkeypatch.setenv("READBACK_ALERT_KEY", "same")
    with pytest.raises(ValueError, match="must differ"):
        WebhookAlert("https://hooks.test/x")
    with pytest.raises(ValueError, match="must differ"):
        WebhookAlert("https://hooks.test/x", key=b"same")
    monkeypatch.setenv("READBACK_ALERT_KEY", "different")
    assert WebhookAlert("https://hooks.test/x").key == b"different"


def test_alert_key_equal_to_an_explicit_log_key_is_refused(monkeypatch, tmp_path):
    from agent_readback import EvidenceLog

    monkeypatch.delenv("READBACK_LOG_KEY", raising=False)
    monkeypatch.delenv("READBACK_ALERT_KEY", raising=False)
    EvidenceLog(tmp_path / "e.jsonl", key="explicit-shared")
    with pytest.raises(ValueError, match="must differ"):
        WebhookAlert("https://hooks.test/x", key="explicit-shared")


def test_alert_created_before_the_log_takes_its_key_is_not_sent(monkeypatch, tmp_path):
    from agent_readback import EvidenceLog

    monkeypatch.delenv("READBACK_LOG_KEY", raising=False)
    sent = []
    client = httpx.Client(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    alert = WebhookAlert("https://hooks.test/x", client, key="late-shared")
    EvidenceLog(tmp_path / "e.jsonl", key="late-shared")
    stripe = MockStripe()
    with watch(StripeRefundVerifier(stripe.client()), REFUND, on_verdict=[alert]):
        pass
    assert sent == [] and "evidence-log key" in str(alert.last_error)
