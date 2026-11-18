"""Command line: `readback verify-log FILE`, `readback report FILE`, `readback dashboard FILE -o OUT.html`.

Set READBACK_LOG_KEY to the key the log was written with; without it a keyed
log reports BROKEN.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .dashboard import render_html
from .evidence import EvidenceLog
from .report import render, summarise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="readback", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (
        ("verify-log", "check that no record was edited, deleted or reordered"),
        ("report", "summarise verdicts and the failed rate"),
    ):
        commands.add_parser(name, help=text).add_argument("path")
    page = commands.add_parser("dashboard", help="write the log as a one-file HTML page")
    page.add_argument("path")
    page.add_argument("-o", "--out", default="readback-report.html")
    args = parser.parse_args(argv)
    try:
        log = EvidenceLog(args.path)
        if not log.path.is_file():
            print(f"ERROR: no such file: {args.path}", file=sys.stderr)
            return 2
        intact, bad = log.verify_chain()
        count = len(log.records())
    except ValueError as error:
        print(f"BROKEN: {error}", file=sys.stderr)
        return 1

    if args.command == "verify-log":
        if intact:
            print(f"OK: {count} records, chain intact")
            print(f"head: {log.head}   (store this outside the log; a shorter log with another head was truncated)")
            return 0
        print(f"BROKEN: record {bad} of {count} does not match the chain")
        return 1

    if args.command == "dashboard":
        Path(args.out).write_text(render_html(log.records(), intact), encoding="utf-8")
        print(f"Wrote {args.out}")
        return 0 if intact else 1

    print(render(summarise(log.records())))
    if not intact:
        print(f"WARNING: chain broken at record {bad}; figures above may not be trustworthy")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
