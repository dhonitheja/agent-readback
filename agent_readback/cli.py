"""Command line: `readback verify-log FILE`, `readback report FILE`, `readback dashboard FILE -o OUT.html`.

Set READBACK_LOG_KEY to the key the log was written with. Without a key the
chain only detects accidental damage: anyone can rebuild an unkeyed chain, so
an unkeyed OK is flagged as not forgery-proof. Pass --require-key to fail
instead (use it in audits).

Exit codes: 0 intact, 1 broken or untrustworthy, 2 bad arguments, 3 file error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .dashboard import render_html
from .evidence import KEY_ENV, EvidenceLog
from .report import render, summarise

OK, BROKEN, USAGE, FILE_ERROR = 0, 1, 2, 3
UNKEYED = f"UNKEYED: detects accidental damage, not forgery; set {KEY_ENV} and pass --require-key to audit"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="readback", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    subs = [
        commands.add_parser("verify-log", help="check that no record was edited, deleted or reordered"),
        commands.add_parser("report", help="summarise verdicts and the failed rate"),
        commands.add_parser("dashboard", help="write the log as a one-file HTML page"),
    ]
    for sub in subs:
        sub.add_argument("path")
        sub.add_argument("--require-key", action="store_true", help=f"fail unless {KEY_ENV} is set")
    subs[2].add_argument("-o", "--out", default="readback-report.html")
    args = parser.parse_args(argv)

    path = Path(args.path)
    if not path.is_file():
        print(f"ERROR: no such file: {args.path}", file=sys.stderr)
        return FILE_ERROR
    try:
        log = EvidenceLog(path)
        if args.require_key and log.key is None:
            print(f"ERROR: --require-key given but {KEY_ENV} is not set", file=sys.stderr)
            return BROKEN
        if log.needs_key():
            print(f"BROKEN: this log was written with a key; set {KEY_ENV} to verify it", file=sys.stderr)
            return BROKEN
        records = log.records()
        intact, bad = log.verify_chain()
    except ValueError as error:
        print(f"BROKEN: {error}", file=sys.stderr)
        return BROKEN
    except OSError as error:
        print(f"ERROR: cannot read {args.path}: {error}", file=sys.stderr)
        return FILE_ERROR
    unkeyed = log.key is None
    if unkeyed and records:
        print(f"WARNING: {UNKEYED}", file=sys.stderr)
    where = f"record {bad} (line {bad + 1})" if bad is not None else ""

    if args.command == "verify-log":
        if intact:
            print(f"OK: {len(records)} records, chain intact" + (" (UNKEYED)" if unkeyed else ""))
            print(f"head: {log.head}   (store this outside the log; a shorter log with another head was truncated)")
            return OK
        print(f"BROKEN: {where} of {len(records)} does not match the chain")
        return BROKEN

    try:
        summary = summarise(records)
        page = render_html(records, intact, unkeyed=unkeyed) if args.command == "dashboard" else None
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        print(f"BROKEN: a record does not have the verdict layout ({type(error).__name__}: {error})", file=sys.stderr)
        return BROKEN

    if args.command == "dashboard":
        out = Path(args.out)
        try:
            # samefile catches hard links to the log; the resolved suffix catches symlinks to any log.
            if out.exists() and (out.samefile(path) or out.suffix.lower() == ".jsonl" or out.resolve().suffix.lower() == ".jsonl"):
                print(f"ERROR: refusing to overwrite {args.out}; an evidence log is never overwritten", file=sys.stderr)
                return FILE_ERROR
            out.write_text(page, encoding="utf-8")
        except OSError as error:
            print(f"ERROR: cannot write {args.out}: {error}", file=sys.stderr)
            return FILE_ERROR
        print(f"Wrote {args.out}")
        return OK if intact else BROKEN

    print(render(summary))
    if not intact:
        print(f"WARNING: chain broken at {where}; figures above may not be trustworthy")
        return BROKEN
    return OK


if __name__ == "__main__":
    sys.exit(main())
