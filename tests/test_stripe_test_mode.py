import hashlib
import hmac
import json
import os
import time
from uuid import uuid4

import httpx
import pytest

from agent_readback import Status

pytest.importorskip("stripe")

from agent_readback import stripe_test_mode as demo


@pytest.mark.parametrize("key", ["", "sk_live_fake", "rk_live_fake", "pk_test_fake", "sk_test_"])
def test_writer_rejects_non_test_keys(monkeypatch, key):
    monkeypatch.setenv("STRIPE_TEST_SECRET_KEY", key)
    with pytest.raises(ValueError, match="STRIPE_TEST_SECRET_KEY"):
        demo.test_key("STRIPE_TEST_SECRET_KEY", "sk_test_", "rk_test_")


def test_checkout_uses_stripe_hosted_card_form():
    def handle(request):
        assert request.url.path == "/v1/checkout/sessions"
        assert request.headers["Idempotency-Key"].startswith("readback-checkout-")
        form = httpx.QueryParams(request.content.decode())
        assert form["payment_method_types[0]"] == "card"
        assert form["line_items[0][price_data][unit_amount]"] == str(demo.AMOUNT)
        assert form["success_url"] == f"{demo.BASE_URL}/success"
        return httpx.Response(200, json={"livemode": False, "url": "https://checkout.stripe.com/test"})

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://stripe.test") as client:
        assert demo.create_checkout(client)["url"] == "https://checkout.stripe.com/test"


@pytest.mark.parametrize("paid", [True, False])
def test_checkout_must_be_paid_before_refund(paid):
    session = {
        "livemode": False, "metadata": demo.MARKER, "mode": "payment",
        "payment_status": "paid" if paid else "unpaid", "amount_total": demo.AMOUNT,
        "currency": demo.CURRENCY, "payment_intent": "pi_demo",
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=session))
    with httpx.Client(transport=transport, base_url="https://stripe.test") as client:
        if paid:
            assert demo.paid_checkout_intent(client, "cs_test_demo") == "pi_demo"
        else:
            with pytest.raises(ValueError, match="Complete payment"):
                demo.paid_checkout_intent(client, "cs_test_demo")


def test_refund_is_verified_using_independent_reader():
    refund = {"id": "re_demo", "object": "refund", "amount": demo.AMOUNT, "currency": demo.CURRENCY,
              "status": "succeeded", "payment_intent": "pi_demo"}
    calls = []

    def read(request):
        assert request.method == "GET"
        if request.url.path == "/v1/payment_intents/pi_demo":
            return httpx.Response(200, json={"livemode": False, "status": "succeeded",
                                              "amount_received": demo.AMOUNT, "currency": demo.CURRENCY})
        assert request.url.path == "/v1/refunds"
        assert request.url.params["payment_intent"] == "pi_demo"
        data = [refund] if "write" in calls else []
        calls.append("read")
        return httpx.Response(200, json={"data": data, "has_more": False})

    def write(request):
        assert request.method == "POST" and request.url.path == "/v1/refunds"
        assert request.headers["Idempotency-Key"] == "readback-refund-pi_demo"
        calls.append("write")
        return httpx.Response(200, json=refund)

    with (
        httpx.Client(transport=httpx.MockTransport(read), base_url="https://stripe.test") as reader,
        httpx.Client(transport=httpx.MockTransport(write), base_url="https://stripe.test") as writer,
    ):
        assert demo.verify_refund(writer, reader, "pi_demo").status is Status.VERIFIED
        with pytest.raises(ValueError, match="already has a refund"):
            demo.verify_refund(writer, reader, "pi_demo")
    assert calls == ["read", "write", "read", "read"]


@pytest.mark.parametrize(
    "event_type, object_data, expected",
    [
        ("refund.created", {"object": "refund"}, "Received test event refund.created."),
        ("checkout.session.completed", {"object": "checkout.session", "metadata": demo.MARKER,
                                        "payment_status": "paid"}, "Received a paid demo Checkout event."),
        ("checkout.session.completed", {"object": "checkout.session", "payment_status": "unpaid"}, None),
        ("payment_intent.created", {"object": "payment_intent"}, None),
    ],
)
def test_webhook_validates_signature_and_mode(event_type, object_data, expected):
    import stripe

    event = {"id": "evt_demo", "object": "event", "type": event_type, "livemode": False,
             "data": {"object": object_data}}
    secret = "demo_signing_fixture"
    stamp = int(time.time())

    def signed(timestamp):
        payload = json.dumps(event).encode()
        digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
        return payload, f"t={timestamp},v1={digest}"

    payload, signature = signed(stamp)
    assert demo.webhook_event(payload, signature, secret) == expected
    with pytest.raises(stripe.SignatureVerificationError):
        demo.webhook_event(payload + b" ", signature, secret)
    with pytest.raises(stripe.SignatureVerificationError):
        demo.webhook_event(*signed(stamp - 600), secret)
    event["livemode"] = True
    with pytest.raises(ValueError, match="test-mode webhook"):
        demo.webhook_event(*signed(stamp), secret)


@pytest.mark.skipif(os.environ.get("STRIPE_RUN_TEST_MODE") != "1", reason="Stripe API smoke test is opt-in")
def test_stripe_api_refund_smoke():
    writer_key = demo.test_key("STRIPE_TEST_SECRET_KEY", "sk_test_", "rk_test_")
    reader_key = demo.test_key("STRIPE_TEST_READ_ONLY_KEY", "rk_test_")
    if writer_key == reader_key:
        pytest.fail("Use separate Stripe test keys.", pytrace=False)
    with demo.stripe_client(writer_key) as writer, demo.stripe_client(reader_key) as reader:
        intent = demo.stripe_object(
            writer, "POST", "/v1/payment_intents",
            data={"amount": demo.AMOUNT, "currency": demo.CURRENCY, "payment_method_types[0]": "card",
                  "payment_method": "pm_card_visa", "confirm": "true"},
            idempotency_key=f"readback-smoke-{uuid4()}",
        )
        assert intent["status"] == "succeeded"
        assert demo.verify_refund(writer, reader, intent["id"]).status is Status.VERIFIED
