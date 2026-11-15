"""Send failed and unverified verdicts to a webhook."""

from __future__ import annotations

import httpx

from .core import Status, Verdict


class WebhookAlert:
    """Callable for `watch(..., on_verdict=[WebhookAlert(url)])`.

    Posts a small JSON summary with no field values. A delivery error is
    swallowed so that alerting can never break the agent's own flow; check
    `last_error` if you need to know.
    """

    def __init__(self, url: str, client: httpx.Client | None = None) -> None:
        self.url = url
        self.client = client or httpx.Client(timeout=5.0)
        self.last_error: Exception | None = None

    def __call__(self, verdict: Verdict) -> None:
        if verdict.status is Status.VERIFIED:
            return
        payload = {
            "status": verdict.status.value,
            "action": verdict.claim.action,
            "context": verdict.claim.context,
            "findings": [{"kind": f.kind.value, "field": f.field} for f in verdict.findings],
            "checked_at": verdict.checked_at,
        }
        try:
            self.client.post(self.url, json=payload).raise_for_status()
            self.last_error = None
        except httpx.HTTPError as error:
            self.last_error = error
