"""Local Stripe Checkout, refund read-back, and webhook test harness."""

from __future__ import annotations

import argparse
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import httpx
import stripe

from agent_readback import Claim, Status, Verdict
from agent_readback.verifiers.stripe import CREATE, StripeRefundVerifier

AMOUNT = 500
CURRENCY = "usd"
PORT = 4242
BASE_URL = f"http://localhost:{PORT}"
MARKER = {"agent_readback_demo": "true"}


def test_key(name: str, *prefixes: str) -> str:
    key = os.environ.get(name, "").strip()
    if not any(key.startswith(prefix) and len(key) > len(prefix) for prefix in prefixes):
        raise ValueError(f"Set {name} to a Stripe test-mode key of the required type.")
    return key


def stripe_client(key: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://api.stripe.com",
        auth=(key, ""),
        timeout=15,
        trust_env=False,
    )


def stripe_object(
    client: httpx.Client, method: str, path: str, *, data=None, idempotency_key=None, is_refund=False
) -> dict:
    headers = {"Idempotency-Key": idempotency_key} if idempotency_key else {}
    response = client.request(method, path, data=data, headers=headers)
    response.raise_for_status()
    obj = response.json()
    # Refund objects have no livemode field. The test key and preflight PaymentIntent scope the write.
    if is_refund and obj.get("object") != "refund":
        raise ValueError("Stripe did not return a refund object.")
    if not is_refund and obj.get("livemode") is not False:
        raise ValueError("Stripe did not return a test-mode object.")
    return obj


def create_checkout(writer: httpx.Client) -> dict:
    return stripe_object(
        writer, "POST", "/v1/checkout/sessions",
        idempotency_key=f"readback-checkout-{uuid4()}",
        data={
            "mode": "payment",
            "payment_method_types[0]": "card",
            "line_items[0][price_data][currency]": CURRENCY,
            "line_items[0][price_data][unit_amount]": AMOUNT,
            "line_items[0][price_data][product_data][name]": "Agent Readback test payment",
            "line_items[0][quantity]": 1,
            "metadata[agent_readback_demo]": MARKER["agent_readback_demo"],
            "success_url": f"{BASE_URL}/success",
            "cancel_url": f"{BASE_URL}/cancel",
        },
    )


def paid_checkout_intent(writer: httpx.Client, session_id: str) -> str:
    if not session_id.startswith("cs_test_") or not session_id.removeprefix("cs_test_").isalnum():
        raise ValueError("Provide a test Checkout Session ID (cs_test_...).")
    session = stripe_object(writer, "GET", f"/v1/checkout/sessions/{session_id}")
    intent = session.get("payment_intent")
    if (
        session.get("metadata", {}).get("agent_readback_demo") != MARKER["agent_readback_demo"]
        or session.get("mode") != "payment"
        or session.get("payment_status") != "paid"
        or session.get("amount_total") != AMOUNT
        or session.get("currency") != CURRENCY
        or not isinstance(intent, str)
        or not intent.startswith("pi_")
    ):
        raise ValueError("Complete payment for a Checkout Session created by this demo first.")
    return intent


def verify_refund(writer: httpx.Client, reader: httpx.Client, intent: str) -> Verdict:
    claim = Claim(CREATE, "Refunded the test payment.", {
        "payment_intent": intent, "amount": AMOUNT, "currency": CURRENCY, "status": "succeeded",
    })
    # Confirm the restricted key can see this payment before making any change.
    payment = stripe_object(reader, "GET", f"/v1/payment_intents/{intent}")
    if (
        payment.get("status") != "succeeded"
        or payment.get("amount_received") != AMOUNT
        or payment.get("currency") != CURRENCY
    ):
        raise ValueError("Expected a paid test PaymentIntent for the demo amount.")
    verifier = StripeRefundVerifier(reader)
    before = verifier.snapshot(claim)
    if before is None:
        raise ValueError("Refund snapshot failed. Check the restricted key's read access.")
    if before:
        raise ValueError("This payment already has a refund. Start with a fresh test payment.")
    refund = stripe_object(
        writer, "POST", "/v1/refunds",
        data={"payment_intent": intent, "amount": AMOUNT},
        idempotency_key=f"readback-refund-{intent}", is_refund=True,
    )
    expected = {**claim.expected, "id": refund["id"]}
    return verifier.check(Claim(claim.action, claim.agent_said, expected), before)


def webhook_event(payload: bytes, signature: str, secret: str) -> str | None:
    event = stripe.Webhook.construct_event(payload, signature, secret)
    if getattr(event, "livemode", None) is not False:
        raise ValueError("Expected a test-mode webhook event.")
    if event.type == "checkout.session.completed":
        session = event.data.object
        metadata = getattr(session, "metadata", None)
        if (
            getattr(metadata, "agent_readback_demo", None) == MARKER["agent_readback_demo"]
            and getattr(session, "payment_status", None) == "paid"
        ):
            return "Received a paid demo Checkout event."
    if event.type in {"refund.created", "refund.updated", "refund.failed"}:
        return f"Received test event {event.type}."
    return None


def serve_webhooks(secret: str) -> None:
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, message: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(message.encode())

        def do_GET(self) -> None:
            pages = {
                "/success": "Checkout returned. Run the refund command to confirm payment with Stripe.",
                "/cancel": "Checkout canceled.",
            }
            if self.path in pages:
                self.respond(200, pages[self.path])
            else:
                self.respond(404, "Not found.")

        def do_POST(self) -> None:
            if self.path != "/webhook":
                self.respond(404, "Not found.")
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 1024 * 1024:
                    raise ValueError("Invalid payload size.")
                message = webhook_event(
                    self.rfile.read(size), self.headers.get("Stripe-Signature", ""), secret,
                )
            except (ValueError, KeyError, AttributeError, TypeError, stripe.SignatureVerificationError):
                self.respond(400, "Invalid test webhook.")
                return
            if message:
                print(message, flush=True)
            self.respond(200, "Received.")

        def log_message(self, format: str, *args) -> None:
            # Keep request details out of the local demo logs.
            pass

    with ThreadingHTTPServer(("127.0.0.1", PORT), Handler) as server:
        print(f"Listening on {BASE_URL}/webhook", flush=True)
        server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("checkout")
    commands.add_parser("webhook")
    commands.add_parser("refund").add_argument("session_id")
    args = parser.parse_args()
    try:
        if args.command == "webhook":
            serve_webhooks(test_key("STRIPE_WEBHOOK_SECRET", "whsec_"))
            return 0
        writer_key = test_key("STRIPE_TEST_SECRET_KEY", "sk_test_", "rk_test_")
        with stripe_client(writer_key) as writer:
            if args.command == "checkout":
                session = create_checkout(writer)
                print(session["id"])
                print(session["url"])
                return 0
            reader_key = test_key("STRIPE_TEST_READ_ONLY_KEY", "rk_test_")
            if writer_key == reader_key:
                raise ValueError("Use a separate restricted key for refund read-back.")
            with stripe_client(reader_key) as reader:
                verdict = verify_refund(writer, reader, paid_checkout_intent(writer, args.session_id))
                print(f"Refund verification: {verdict.status.value}")
                for finding in verdict.findings:
                    print(finding.detail)
                return 0 if verdict.status is Status.VERIFIED else 1
    except httpx.HTTPStatusError as error:
        print(f"Stripe API returned HTTP {error.response.status_code}. Check the test account and key permissions.")
        return 1
    except httpx.RequestError:
        print("Could not reach the Stripe API.")
        return 1
    except (KeyError, TypeError):
        print("Stripe returned an unexpected response.")
        return 1
    except ValueError as error:
        print(error)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
