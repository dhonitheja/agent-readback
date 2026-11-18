import json
import sqlite3

import httpx

from agent_readback import Claim, FindingKind, Status, WebhookAlert, watch
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
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT, total INTEGER)")
        db.execute("INSERT INTO orders VALUES ('o1', 'open', 500)")
    return path


def sql_run(tmp_path, action_name, expected, statements):
    path = make_db(tmp_path)
    verifier = SqlRowVerifier(lambda: sqlite3.connect(path), "orders", "id", placeholder="?")
    with watch(verifier, Claim(action_name, "DONE", expected)) as watched:
        with sqlite3.connect(path) as db:
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


def test_stripe_snapshot_fails_closed_if_pagination_repeats():
    cursors = []

    def handle(request):
        cursors.append(request.url.params.get("starting_after"))
        return httpx.Response(200, json={"data": [{"id": "re_1"}], "has_more": True})

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://stripe.test") as client:
        assert StripeRefundVerifier(client).snapshot(REFUND) is None
    assert cursors == [None, "re_1"]
