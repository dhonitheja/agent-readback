"""Send failed and unverified verdicts to a webhook."""

from __future__ import annotations

import hashlib
import hmac
import json
import os

import httpx

from .core import Status, Verdict
from .evidence import KEY_ENV


class WebhookAlert:
    """Callable for `watch(..., on_verdict=[WebhookAlert(url)])`.

    Posts a small JSON summary with no field values. A delivery error is
    swallowed so that alerting can never break the agent's own flow; check
    `last_error` if you need to know.

    With a key (`key=` or the `READBACK_LOG_KEY` environment variable) every
    request carries `X-Readback-Signature: sha256=<HMAC-SHA256 of the body>`
    so the receiver can reject alerts that did not come from this process.
    Use an https URL; the client verifies certificates by default.
    """

    def __init__(self, url: str, client: httpx.Client | None = None, key: bytes | str | None = None) -> None:
        self.url = url
        self.client = client or httpx.Client(timeout=5.0)
        key = os.environ.get(KEY_ENV) if key is None else key
        self.key = key.encode() if isinstance(key, str) else key
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
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["X-Readback-Signature"] = "sha256=" + hmac.new(self.key, body, hashlib.sha256).hexdigest()
        try:
            self.client.post(self.url, content=body, headers=headers).raise_for_status()
            self.last_error = None
        except Exception as error:  # bad URL, transport error, HTTP error: never break the agent
            self.last_error = error
