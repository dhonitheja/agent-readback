"""Readback: check what an agent says it did against the system of record."""

from .adapters import OutcomeNotVerified, mcp_text, receipted, watched
from .alerts import WebhookAlert
from .core import Claim, Finding, FindingKind, Status, Verdict, Verifier, compare_fields, recheck, watch
from .evidence import EvidenceLog, FileAnchor
from .ratelimit import RateLimit, RateLimitTimeout, limit_reads
from .receipts import (
    Receipt, ReceiptKeyError, ReceiptLog, ReceiptVerdict, issue_receipt, load_public_key, load_signing_key,
    verify_receipt, verify_signed_receipts,
)

__version__ = "0.3.1"
__all__ = [
    "Claim",
    "EvidenceLog",
    "FileAnchor",
    "Finding",
    "FindingKind",
    "OutcomeNotVerified",
    "RateLimit",
    "RateLimitTimeout",
    "Receipt",
    "ReceiptKeyError",
    "ReceiptLog",
    "ReceiptVerdict",
    "Status",
    "Verdict",
    "Verifier",
    "WebhookAlert",
    "compare_fields",
    "issue_receipt",
    "limit_reads",
    "mcp_text",
    "receipted",
    "recheck",
    "verify_receipt", "verify_signed_receipts", "load_signing_key", "load_public_key",
    "watch",
    "watched",
]
