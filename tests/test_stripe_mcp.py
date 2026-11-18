import asyncio
import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("mcp")
pytest.importorskip("stripe")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_readback import stripe_mcp


def test_stdio_lists_tools_and_rejects_live_key():
    async def exercise():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "agent_readback.stripe_mcp"],
            cwd=Path(__file__).resolve().parents[1],
            env={"STRIPE_TEST_SECRET_KEY": "sk_live_fixture"},
        )
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                assert set(tools) == {"create_test_checkout", "refund_test_checkout"}
                assert tools["refund_test_checkout"].inputSchema["required"] == ["session_id"]
                result = await session.call_tool("create_test_checkout")
                assert result.isError
                assert "STRIPE_TEST_SECRET_KEY" in result.content[0].text
                assert "sk_live_fixture" not in result.content[0].text

    asyncio.run(exercise())


def test_refund_tool_uses_stripe_readback(monkeypatch):
    monkeypatch.setenv("STRIPE_TEST_SECRET_KEY", "sk_test_writer_fixture")
    monkeypatch.setenv("STRIPE_TEST_READ_ONLY_KEY", "rk_test_reader_fixture")
    calls = []
    refund = {"object": "refund", "id": "re_demo", "payment_intent": "pi_demo",
              "amount": 500, "currency": "usd", "status": "succeeded"}

    def fake_client(key):
        def respond(request):
            calls.append((key, request.method, request.url.path))
            match request.url.path:
                case "/v1/checkout/sessions/cs_test_demo":
                    return httpx.Response(200, json={
                        "livemode": False, "metadata": {"agent_readback_demo": "true"},
                        "mode": "payment", "payment_status": "paid", "amount_total": 500,
                        "currency": "usd", "payment_intent": "pi_demo",
                    })
                case "/v1/payment_intents/pi_demo":
                    return httpx.Response(200, json={
                        "livemode": False, "status": "succeeded", "amount_received": 500, "currency": "usd",
                    })
                case "/v1/refunds" if request.method == "POST":
                    return httpx.Response(200, json=refund)
                case "/v1/refunds":
                    data = [refund] if any(method == "POST" for _, method, _ in calls) else []
                    return httpx.Response(200, json={"data": data, "has_more": False})
            raise AssertionError("Unexpected Stripe request")

        return httpx.Client(base_url="https://stripe.test", transport=httpx.MockTransport(respond))

    monkeypatch.setattr(stripe_mcp, "stripe_client", fake_client)
    assert stripe_mcp.refund_test_checkout("cs_test_demo") == {"status": "verified", "findings": []}
    assert [key for key, method, path in calls if method == "GET" and path == "/v1/refunds"] == [
        "rk_test_reader_fixture", "rk_test_reader_fixture",
    ]
