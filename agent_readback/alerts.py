"""Send failed and unverified verdicts to a webhook."""

from __future__ import annotations

import hashlib
import hmac
import json
import os

import httpx

from .core import Status, Verdict
from .evidence import KEY_ENV as LOG_KEY_ENV
from .evidence import is_log_key

# Separate from READBACK_LOG_KEY on purpose: the receiver needs this key to check
# signatures, and must never hold the key that can rewrite the evidence log.
ALERT_KEY_ENV = "READBACK_ALERT_KEY"

# Fingerprints of the keys WebhookAlerts in this process sign with, so the
# receipt key can refuse an alert key given only as key= (not in the env).
_ALERT_KEY_FINGERPRINTS: set[str] = set()


def _alert_fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"readback-alert-key:" + key).hexdigest()


def is_alert_key(key: bytes) -> bool:
    """True if `key` is READBACK_ALERT_KEY or a key a WebhookAlert in this process signs with."""
    env = os.environ.get(ALERT_KEY_ENV, "").encode()
    return bool(key) and ((bool(env) and hmac.compare_digest(key, env)) or _alert_fingerprint(key) in _ALERT_KEY_FINGERPRINTS)


class WebhookAlert:
    """Callable for `watch(..., on_verdict=[WebhookAlert(url)])`.

    Posts a small JSON summary with no field values. A delivery error is
    swallowed so that alerting can never break the agent's own flow; check
    `last_error` if you need to know.

    With a key (`key=` or the `READBACK_ALERT_KEY` environment variable) every
    request carries `X-Readback-Signature: sha256=<HMAC-SHA256 of the body>`
    so the receiver can reject alerts that did not come from this process.
    The evidence-log key is never used here: it must not leave the log writer.
    An alert key equal to READBACK_LOG_KEY, or to a key any EvidenceLog in this
    process uses, is refused at creation and again before each send (keys used
    only in other processes cannot be seen). An empty key means unsigned.
    Use an https URL; the client verifies certificates by default.
    """

    def __init__(self, url: str, client: httpx.Client | None = None, key: bytes | str | None = None) -> None:
        self.url = url
        self.client = client or httpx.Client(timeout=5.0)
        key = os.environ.get(ALERT_KEY_ENV) if key is None else key
        self.key = key.encode() if isinstance(key, str) else key or None
        if self.key and is_log_key(self.key):
            raise ValueError(f"the alert key must differ from {LOG_KEY_ENV}: the alert receiver must not hold the log key")
        if self.key:
            _ALERT_KEY_FINGERPRINTS.add(_alert_fingerprint(self.key))
        self.last_error: Exception | None = None

    def __call__(self, verdict: Verdict) -> None:
        if verdict.status is Status.VERIFIED:
            return
        if self.key and is_log_key(self.key):  # a log may have started using this key after creation
            self.last_error = ValueError(f"alert key is also an evidence-log key; alert not sent")
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
