"""Readback: check what an agent says it did against the system of record."""

from .adapters import mcp_text, watched
from .alerts import WebhookAlert
from .core import Claim, Finding, FindingKind, Status, Verdict, Verifier, compare_fields, watch
from .evidence import EvidenceLog

__version__ = "0.2.1"
__all__ = [
    "Claim",
    "EvidenceLog",
    "Finding",
    "FindingKind",
    "Status",
    "Verdict",
    "Verifier",
    "WebhookAlert",
    "compare_fields",
    "mcp_text",
    "watch",
    "watched",
]
