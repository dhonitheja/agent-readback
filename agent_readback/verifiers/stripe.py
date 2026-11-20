"""Read-back verifier for Stripe refunds.

Action:
  stripe.refund.create   expected: payment_intent (required), amount (integer,
                         smallest currency unit), currency, and optionally status

It lists refunds for the payment intent before and after the action. A refund
that was claimed but is absent is `missing`; a wrong amount or currency is
`wrong_value`; a second new refund is `extra_effect` (a double refund). A refund
that matches but is still `pending` with the bank is `unverified` with a
`pending` finding; pass that verdict to `agent_readback.recheck` once the bank
has had time to settle it.

Build the client with a restricted, read-only Stripe key, for example:
    httpx.Client(base_url="https://api.stripe.com", auth=(RESTRICTED_KEY, ""))
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core import Claim, Finding, FindingKind, Status, Verdict, compare_fields

CREATE = "stripe.refund.create"
FIELDS = ("id", "amount", "currency", "status", "payment_intent", "charge")
MAX_PAGES = 50  # 5000 refunds on one payment intent; a server that pages forever gets `unverified`, not a hang


class StripeRefundVerifier:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client

    def _refunds(self, payment_intent: str) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        params: dict[str, Any] = {"payment_intent": payment_intent, "limit": 100}
        for _ in range(MAX_PAGES):
            response = self.client.get("/v1/refunds", params=params)
            response.raise_for_status()
            page = response.json()
            for item in page.get("data", []):
                found[item["id"]] = {name: item.get(name) for name in FIELDS}
            if not page.get("has_more") or not page.get("data"):
                return found
            params["starting_after"] = page["data"][-1]["id"]
        raise ValueError(f"more than {MAX_PAGES} pages of refunds; refusing to continue")

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
        if "status" not in claim.expected and best.get("status") == "pending" and not findings and not others:
            # Not yet settled by the bank: neither proven nor contradicted. Re-check later.
            pending = Finding(FindingKind.PENDING, f"refund {best['id']} is still pending; re-check later")
            return Verdict(Status.UNVERIFIED, claim, (pending,), {"created": created})
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

    def recheck(self, claim: Claim, observed: dict[str, Any]) -> Verdict:
        """Judge the refunds seen at the first check again; refunds created since then are not counted."""
        try:
            first = {item["id"] for item in observed["created"]}
            now = set(self._refunds(claim.expected["payment_intent"]))
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
            return Verdict(Status.UNVERIFIED, claim, (Finding(FindingKind.UNREACHABLE, f"could not re-check Stripe: {error}"),))
        return self.check(claim, now - first)
