import json
from urllib.parse import parse_qs

import httpx
import pytest

from agent_readback import EvidenceLog
from examples.stripe_sandbox import run, test_keys as load_test_keys


@pytest.mark.parametrize("writer,reader", [("sk_live_x", "rk_test_x"), ("sk_test_x", "rk_live_x"), ("sk_test_x", "sk_test_y"), ("", "")])
def test_sandbox_rejects_non_test_or_unrestricted_keys(monkeypatch, writer, reader):
    monkeypatch.setenv("STRIPE_TEST_SECRET_KEY", writer)
    monkeypatch.setenv("STRIPE_TEST_READ_ONLY_KEY", reader)
    with pytest.raises(ValueError):
        load_test_keys()


def test_sandbox_scenarios_and_redacted_evidence(tmp_path):
    refunds = []
    payments = []

    def write(request):
        assert request.method == "POST"
        data = parse_qs(request.content.decode())
        if request.url.path == "/v1/payment_intents":
            payment = {"id": f"pi_{len(payments)}", "status": "succeeded", "livemode": False}
            payments.append(payment)
            return httpx.Response(200, json=payment)
        refund = {"id": f"re_{len(refunds)}", "payment_intent": data["payment_intent"][0],
                  "amount": int(data["amount"][0]), "currency": "usd", "status": "succeeded"}
        refunds.append(refund)
        return httpx.Response(200, json=refund)

    def read(request):
        assert request.method == "GET"
        wanted = request.url.params.get("payment_intent")
        return httpx.Response(200, json={"data": [r for r in refunds if r["payment_intent"] == wanted], "has_more": False})

    path = tmp_path / "evidence.jsonl"
    with httpx.Client(base_url="https://stripe.test", transport=httpx.MockTransport(write)) as writer, \
         httpx.Client(base_url="https://stripe.test", transport=httpx.MockTransport(read)) as reader:
        summary = run(writer, reader, EvidenceLog(path))
    assert summary["passed"]
    assert len(summary["results"]) == 4
    assert [r["status"] for r in summary["results"]] == ["verified", "failed", "failed", "failed"]
    assert all(json.loads(line)["body"]["observed"] is None for line in path.read_text().splitlines())
