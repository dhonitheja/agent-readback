"""Local stdio MCP server for Stripe test-mode Checkout and refund verification."""

from __future__ import annotations

from typing import TypedDict

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from .stripe_test_mode import create_checkout, paid_checkout_intent, stripe_client, test_key, verify_refund

server = FastMCP("agent-readback-stripe-test")


class CheckoutResult(TypedDict):
    session_id: str
    checkout_url: str


class RefundResult(TypedDict):
    status: str
    findings: list[str]


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                         idempotentHint=False, openWorldHint=True))
def create_test_checkout() -> CheckoutResult:
    """Create a USD 5.00 Stripe test Checkout Session. Return its hosted URL and session ID."""
    try:
        with stripe_client(test_key("STRIPE_TEST_SECRET_KEY", "sk_test_", "rk_test_")) as writer:
            session = create_checkout(writer)
            return {"session_id": session["id"], "checkout_url": session["url"]}
    except httpx.HTTPError:
        raise ToolError("Stripe Checkout API request failed. Check test-mode access.") from None
    except ValueError as error:
        raise ToolError(str(error)) from None
    except (KeyError, TypeError, AttributeError):
        raise ToolError("Stripe returned an unexpected Checkout response.") from None


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                         idempotentHint=True, openWorldHint=True))
def refund_test_checkout(session_id: str) -> RefundResult:
    """Refund a paid Checkout Session from this test demo and return an independent read-back verdict."""
    try:
        writer_key = test_key("STRIPE_TEST_SECRET_KEY", "sk_test_", "rk_test_")
        reader_key = test_key("STRIPE_TEST_READ_ONLY_KEY", "rk_test_")
        if writer_key == reader_key:
            raise ValueError("Use a separate restricted key for refund read-back.")
        with stripe_client(writer_key) as writer, stripe_client(reader_key) as reader:
            intent = paid_checkout_intent(writer, session_id)
            verdict = verify_refund(writer, reader, intent)
        return {"status": verdict.status.value, "findings": [item.kind.value for item in verdict.findings]}
    except httpx.HTTPError:
        raise ToolError("Stripe refund API request failed. Check test-mode access.") from None
    except ValueError as error:
        raise ToolError(str(error)) from None
    except (KeyError, TypeError, AttributeError):
        raise ToolError("Stripe returned an unexpected refund response.") from None


if __name__ == "__main__":
    server.run(transport="stdio")
