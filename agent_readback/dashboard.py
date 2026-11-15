"""Render an evidence log as one self-contained HTML page."""

from __future__ import annotations

from html import escape
from typing import Any

from .report import summarise

STYLE = """
:root{color-scheme:light dark;--bg:#fbfaf7;--fg:#1c1b18;--mut:#6b675f;--line:#dedad0;--ok:#1f7a4d;--bad:#b3261e;--warn:#9a6700;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#161512;--fg:#ece9e1;--mut:#a39e92;--line:#34322c;--ok:#5fc48f;--bad:#f2867e;--warn:#e0b252;--card:#1f1e1a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:920px;margin:0 auto;padding:28px 18px 60px}h1{font-size:22px;margin:0 0 2px}h2{font-size:15px;margin:30px 0 10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.sub{color:var(--mut);margin:0 0 22px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:28px;line-height:1.1;font-variant-numeric:tabular-nums}
.tile span{color:var(--mut);font-size:13px}.ok b{color:var(--ok)}.bad b{color:var(--bad)}.warn b{color:var(--warn)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}table{border-collapse:collapse;width:100%;min-width:520px}
th,td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums;vertical-align:top}th{font-size:12px;color:var(--mut);font-weight:600}
tr:last-child td{border-bottom:0}code{font:13px ui-monospace,Menlo,Consolas,monospace}.pill{display:inline-block;border-radius:99px;padding:1px 9px;font-size:12px;border:1px solid currentColor}
.chain{margin-top:22px;font-size:13px;color:var(--mut)}
"""


def _tile(css: str, value: str, label: str) -> str:
    return f'<div class="tile {css}"><b>{escape(value)}</b><span>{escape(label)}</span></div>'


def render_html(records: list[dict[str, Any]], chain_intact: bool, title: str = "Readback report") -> str:
    summary = summarise(records)
    tiles = "".join(
        [
            _tile("", str(summary["total"]), "claims checked"),
            _tile("ok", str(summary["verified"]), "verified"),
            _tile("bad", str(summary["failed"]), f"failed ({summary['failed_rate']:.1%})"),
            _tile("warn", str(summary["unverified"]), "could not be checked"),
        ]
    )
    action_rows = "".join(
        f"<tr><td><code>{escape(action)}</code></td><td>{counts.get('verified', 0)}</td>"
        f"<td>{counts.get('failed', 0)}</td><td>{counts.get('unverified', 0)}</td></tr>"
        for action, counts in summary["by_action"].items()
    )
    finding_rows = "".join(
        f"<tr><td>{escape(kind.replace('_', ' '))}</td><td>{count}</td></tr>"
        for kind, count in summary["finding_kinds"].items()
    ) or '<tr><td colspan="2">None</td></tr>'
    problems = [r["body"] for r in records if r["body"]["status"] != "verified"][-50:][::-1]
    problem_rows = "".join(
        "<tr><td>{when}</td><td><code>{action}</code></td><td><span class='pill' style='color:var(--{tone})'>{status}</span></td><td>{why}</td><td>{ctx}</td></tr>".format(
            when=escape(body["checked_at"][:19].replace("T", " ")),
            action=escape(body["claim"]["action"]),
            tone="bad" if body["status"] == "failed" else "warn",
            status=escape(body["status"]),
            why=escape(", ".join(f["kind"].replace("_", " ") + (f" ({f['field']})" if f.get("field") else "") for f in body["findings"])),
            ctx=escape(", ".join(f"{k}={v}" for k, v in body["claim"].get("context", {}).items())),
        )
        for body in problems
    ) or '<tr><td colspan="5">Every claim was verified.</td></tr>'
    chain = "intact" if chain_intact else "BROKEN: a record was edited or deleted"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{STYLE}</style></head><body><main>
<h1>{escape(title)}</h1><p class="sub">What the agent claimed, checked against the system of record.</p>
<div class="tiles">{tiles}</div>
<h2>By action</h2><div class="wrap"><table><tr><th>Action</th><th>Verified</th><th>Failed</th><th>Unverified</th></tr>{action_rows}</table></div>
<h2>Why claims failed</h2><div class="wrap"><table><tr><th>Finding</th><th>Count</th></tr>{finding_rows}</table></div>
<h2>Latest problems</h2><div class="wrap"><table><tr><th>Checked (UTC)</th><th>Action</th><th>Verdict</th><th>Findings</th><th>Context</th></tr>{problem_rows}</table></div>
<p class="chain">Evidence chain: {escape(chain)}. {len(records)} records.</p>
</main></body></html>
"""
