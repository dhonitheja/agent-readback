"""Readback: check what an agent says it did against the system of record."""

from .adapters import mcp_text, watched
from .alerts import WebhookAlert
from .core import Claim, Finding, FindingKind, Status, Verdict, Verifier, compare_fields, recheck, watch
from .evidence import EvidenceLog, FileAnchor
from .ratelimit import RateLimit, RateLimitTimeout, limit_reads

__version__ = "0.3.0"
__all__ = [
    "Claim",
    "EvidenceLog",
    "FileAnchor",
    "Finding",
    "FindingKind",
    "RateLimit",
    "RateLimitTimeout",
    "Status",
    "Verdict",
    "Verifier",
    "WebhookAlert",
    "compare_fields",
    "limit_reads",
    "mcp_text",
    "recheck",
    "watch",
    "watched",
]
