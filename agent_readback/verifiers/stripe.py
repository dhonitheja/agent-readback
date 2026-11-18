"""Read-back verifier for Stripe refunds.

Action:
  stripe.refund.create   expected: payment_intent (required), amount (integer,
                         smallest currency unit), currency, and optionally status

It lists refunds for the payment intent before and after the action. A refund
that was claimed but is absent is `missing`; a wrong amount or currency is
`wrong_value`; a second new refund is `extra_effect` (a double refund).

Build the client with a restricted, read-only Stripe key, for example:
    httpx.Client(base_url="https://api.stripe.com", auth=(RESTRICTED_KEY, ""))
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core import Claim, Finding, FindingKind, Status, Verdict, compare_fields

CREATE = "stripe.refund.create"
FIELDS = ("id", "amount", "currency", "status", "payment_intent", "charge")


class StripeRefundVerifier:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client

    def _refunds(self, payment_intent: str) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        params: dict[str, Any] = {"payment_intent": payment_intent, "limit": 100}
        cursors: set[str] = set()
        while True:
            response = self.client.get("/v1/refunds", params=params)
            response.raise_for_status()
            page = response.json()
            if not isinstance(page, dict):
                raise ValueError("invalid Stripe refund page")
            items = page.get("data")
            has_more = page.get("has_more")
            if not isinstance(items, list) or not isinstance(has_more, bool):
                raise ValueError("invalid Stripe refund page")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                    raise ValueError("invalid Stripe refund")
                found[item["id"]] = {name: item.get(name) for name in FIELDS}
            if not has_more:
                return found
            if not items or items[-1]["id"] in cursors:
                raise ValueError("Stripe refund pagination did not advance")
            cursor = items[-1]["id"]
            cursors.add(cursor)
            params["starting_after"] = cursor

    def snapshot(self, claim: Claim) -> set[str] | None:
        try:
            return set(self._refunds(claim.expected["payment_intent"]))
        except (httpx.HTTPError, KeyError, ValueError):
            return None

    def check(self, claim: Claim, before: set[str] | None) -> Verdict:
        unreachable = lambda why: Verdict(  # noqa: E731
            Status.UNVERIFIED, claim, (Finding(FindingKind.UNREACHABLE, why),)
        )
        if before is None:
            return unreachable("no snapshot was taken before the action")
        if claim.action != CREATE:
            return unreachable(f"unknown action {claim.action!r}")
        try:
            now = self._refunds(claim.expected["payment_intent"])
        except (httpx.HTTPError, KeyError, ValueError) as error:
            return unreachable(f"could not read Stripe: {error}")

        created = [item for key, item in now.items() if key not in before]
        if not created:
            finding = Finding(FindingKind.MISSING, "no new refund exists for this payment")
            return Verdict(Status.FAILED, claim, (finding,), {"created": []})
        ranked = sorted(created, key=lambda item: len(compare_fields(claim.expected, item)))
        best, others = ranked[0], ranked[1:]
        findings = compare_fields(claim.expected, best)
        if "status" not in claim.expected and best.get("status") in ("failed", "canceled"):
            findings.append(
                Finding(FindingKind.WRONG_VALUE, f"refund status is {best['status']!r}", "status", "succeeded", best["status"])
            )
        findings += [
            Finding(FindingKind.EXTRA_EFFECT, f"unclaimed refund {other['id']} was also created", actual=other)
            for other in others
        ]
        status = Status.VERIFIED if not findings else Status.FAILED
        return Verdict(status, claim, tuple(findings), {"created": created})
