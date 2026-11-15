"""Summarise an evidence log."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_action: dict[str, Counter[str]] = defaultdict(Counter)
    kinds: Counter[str] = Counter()
    for record in records:
        body = record["body"]
        by_action[body["claim"]["action"]][body["status"]] += 1
        for finding in body["findings"]:
            kinds[finding["kind"]] += 1
    total = len(records)
    failed = sum(counts["failed"] for counts in by_action.values())
    return {
        "total": total,
        "verified": sum(counts["verified"] for counts in by_action.values()),
        "failed": failed,
        "unverified": sum(counts["unverified"] for counts in by_action.values()),
        "failed_rate": (failed / total) if total else 0.0,
        "by_action": {action: dict(counts) for action, counts in sorted(by_action.items())},
        "finding_kinds": dict(sorted(kinds.items())),
    }


def render(summary: dict[str, Any]) -> str:
    lines = [
        f"Claims checked:  {summary['total']}",
        f"Verified:        {summary['verified']}",
        f"Failed:          {summary['failed']}  ({summary['failed_rate']:.1%})",
        f"Unverified:      {summary['unverified']}",
    ]
    if summary["by_action"]:
        lines.append("By action:")
        for action, counts in summary["by_action"].items():
            parts = ", ".join(f"{name} {count}" for name, count in sorted(counts.items()))
            lines.append(f"  {action}: {parts}")
    if summary["finding_kinds"]:
        lines.append("Findings:")
        for kind, count in summary["finding_kinds"].items():
            lines.append(f"  {kind}: {count}")
    return "\n".join(lines)
