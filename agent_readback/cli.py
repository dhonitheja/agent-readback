"""Command line: `readback verify-log FILE`, `readback report FILE`, `readback dashboard FILE -o OUT.html`,
`readback reconcile OUTCOMES --system stripe|fhir --receipts OUT.jsonl`, `readback verify-receipts FILE`.

Set READBACK_LOG_KEY to the key the log was written with. Without a key the
chain only detects accidental damage: anyone can rebuild an unkeyed chain, so
an unkeyed OK is flagged as not forgery-proof. Pass --require-key to fail
instead (use it in audits).

Exit codes: 0 intact, 1 broken or untrustworthy, 2 bad arguments, 3 file error.
For `reconcile`: 0 every outcome verified, 1 some did not, 2 bad arguments, 3 input or file error.

`reconcile` reads credentials from the environment only, never from flags:
READBACK_STRIPE_KEY (a restricted read-only rk_ key) or READBACK_FHIR_TOKEN
(optional bearer token with read scope), and READBACK_RECEIPT_KEY for receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from .dashboard import render_html
from .evidence import KEY_ENV, EvidenceLog, FileAnchor
from .ratelimit import RateLimit, limit_reads
from .receipts import RECEIPT_KEY_ENV, ReceiptKeyError, ReceiptLog, load_public_key, load_signing_key, verify_signed_receipts
from .reconcile import MAX_ROWS, ExportError, FhirAppointments, StripeRefunds, load_outcomes, parse_since, prior_effects, reconcile
from .reconcile import render as render_reconciliation
from .reconcile import summarise as summarise_reconciliation
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
    anchored = subs[0].add_mutually_exclusive_group()
    anchored.add_argument("--anchor", metavar="FILE", help="fail unless the log still holds the head recorded by FileAnchor")
    anchored.add_argument("--head", metavar="HASH", help="fail unless the log still holds this head hash (from an earlier verify-log)")

    rec = commands.add_parser("reconcile", help="read back every outcome in an export and write one receipt each")
    rec.add_argument("outcomes", help="CSV (outcome_id, action, expected fields) or JSONL outcome export")
    rec.add_argument("--system", required=True, choices=("stripe", "fhir"))
    rec.add_argument("--receipts", required=True, metavar="FILE", help="receipt log to create or append to")
    rec.add_argument("--base-url", help="system of record (https; Stripe defaults to https://api.stripe.com)")
    rec.add_argument("--since", help="Stripe: ignore refunds created before this date (e.g. 2026-11-01)")
    rec.add_argument("--prior", action="append", default=[], metavar="FILE",
                     help="earlier receipt log; effects it billed cannot back a new outcome (repeatable)")
    rec.add_argument("--json", action="store_true", help="print the summary as JSON")
    rec.add_argument("--max-rate", type=float, default=20.0, help="reads per second (default 20; Stripe allows 25)")
    rec.add_argument("--max-rows", type=int, default=MAX_ROWS, help=f"refuse exports with more outcomes (default {MAX_ROWS})")
    rec.add_argument("--keep-outcome-ids", action="store_true",
                     help="store outcome ids in receipts as given (default: a keyed oid_ stand-in; the report still shows yours)")
    rec.add_argument("--match-metadata", metavar="KEY",
                     help="Stripe: a refund only counts if its metadata[KEY] equals the outcome id")
    rec.add_argument("--signing-key", metavar="FILE",
                     help=f"also sign receipts with this Ed25519 PEM private key (owner-only; password in {SIGNING_PASSWORD_ENV})")

    ver = commands.add_parser("verify-receipts", help="check a receipt log's chain and every receipt's MAC")
    ver.add_argument("path")
    anchored = ver.add_mutually_exclusive_group()
    anchored.add_argument("--anchor", metavar="FILE", help="fail unless the log still holds the head recorded by FileAnchor")
    anchored.add_argument("--head", metavar="HASH", help="fail unless the log still holds this head hash")
    ver.add_argument("--public-key", metavar="FILE",
                     help=f"check Ed25519 signatures with the issuer's public key; without {RECEIPT_KEY_ENV} only signatures and links are checked")
    args = parser.parse_args(argv)

    if args.command == "reconcile":
        return reconcile_main(args)
    if args.command == "verify-receipts":
        return verify_receipts_main(args)

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
        anchor_note = ""
        if intact and (args.anchor or args.head):
            if args.anchor:
                try:
                    count, head = FileAnchor(args.anchor).read()
                except OSError as error:
                    print(f"ERROR: cannot read anchor {args.anchor}: {error}", file=sys.stderr)
                    return FILE_ERROR
                except ValueError as error:
                    print(f"ERROR: {error}", file=sys.stderr)
                    return FILE_ERROR
            else:
                wanted = args.head.strip().lower()
                found = [i for i, record in enumerate(records) if record["hash"] == wanted]
                count, head = (found[0] + 1, wanted) if found else (0, wanted)
            problem = log.check_anchor(count, head) if count else (
                "the given head is not in the log: newest records were dropped or the log was rewritten")
            if problem:
                print(f"BROKEN: {problem}")
                return BROKEN
            later = len(records) - count
            anchor_note = f"; anchored head found at record {count - 1}" + (f", {later} record(s) after it" if later else "")
        if intact:
            print(f"OK: {len(records)} records, chain intact" + (" (UNKEYED)" if unkeyed else "") + anchor_note)
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


STRIPE_KEY_ENV = "READBACK_STRIPE_KEY"
FHIR_TOKEN_ENV = "READBACK_FHIR_TOKEN"  # nosec B105 - name of an environment variable, not a secret
SIGNING_PASSWORD_ENV = "READBACK_SIGNING_KEY_PASSWORD"  # nosec B105 - name of an environment variable, not a secret  # pragma: allowlist secret
STRIPE_HOST = "api.stripe.com"
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_transport: httpx.BaseTransport | None = None  # tests swap in httpx.MockTransport


def _base_url(raw: str) -> httpx.URL:
    try:
        url = httpx.URL(raw)
    except httpx.InvalidURL:
        raise ValueError("--base-url is not a valid URL") from None
    if url.userinfo:
        raise ValueError("--base-url must not contain credentials; use the environment variables")
    if url.query or url.fragment:
        raise ValueError("--base-url must not have a query or fragment")
    if not url.host or not (url.scheme == "https" or (url.scheme == "http" and url.host in _LOOPBACK)):
        raise ValueError("--base-url must be https (plain http only for localhost)")
    return url


def _client(system: str, base_url: str | None) -> httpx.Client:
    """A read-only client with credentials from the environment. Never prints them."""
    if system == "stripe":
        key = os.environ.get(STRIPE_KEY_ENV, "").strip()
        if not key.startswith("rk_"):
            raise ValueError(f"set {STRIPE_KEY_ENV} to a restricted read-only Stripe key (rk_...); secret keys are refused")
        url = _base_url(base_url or f"https://{STRIPE_HOST}")
        if url.host != STRIPE_HOST and url.host not in _LOOPBACK:
            # The key is sent to this host: only Stripe itself, or a local stripe-mock.
            raise ValueError(f"--base-url for Stripe must be https://{STRIPE_HOST} or a localhost stripe-mock")
        return httpx.Client(base_url=url, auth=(key, ""), timeout=10.0, transport=_transport)
    if not base_url:
        raise ValueError("--base-url is required for --system fhir")
    headers = {"Accept": "application/fhir+json"}
    token = os.environ.get(FHIR_TOKEN_ENV, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=_base_url(base_url), headers=headers, timeout=10.0, transport=_transport)


def reconcile_main(args: argparse.Namespace) -> int:
    from .verifiers import FhirAppointmentVerifier, StripeRefundVerifier

    try:
        if not args.max_rate > 0 or args.max_rows < 1:
            raise ValueError("--max-rate and --max-rows must be positive")
        since = parse_since(args.since) if args.since else None
        if since is not None and args.system != "stripe":
            raise ValueError("--since applies to --system stripe only")
        if args.match_metadata and args.system != "stripe":
            raise ValueError("--match-metadata applies to --system stripe only")
        signing_key = None
        if args.signing_key:
            password = os.environ.get(SIGNING_PASSWORD_ENV)
            signing_key = load_signing_key(args.signing_key, password.encode() if password else None)
        client = _client(args.system, args.base_url)
    except ImportError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return USAGE
    except OSError as error:
        print(f"ERROR: cannot read the signing key: {error.strerror or error}", file=sys.stderr)
        return FILE_ERROR
    except (ValueError, TypeError, ReceiptKeyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return USAGE
    with client:
        try:
            outcomes = load_outcomes(args.outcomes, system=args.system, max_rows=args.max_rows)
            prior = prior_effects(args.prior, public_key=signing_key.public_key() if signing_key else None)
            receipts = ReceiptLog(args.receipts, signing_key=signing_key)
        except ReceiptKeyError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return USAGE
        except (ExportError, ValueError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return FILE_ERROR
        except OSError as error:
            print(f"ERROR: cannot open a receipt log: {error.strerror or error}", file=sys.stderr)
            return FILE_ERROR
        limit_reads(client, RateLimit(args.max_rate))
        origin = client.base_url.copy_with(path="/")
        print(f"reading {args.system} at {origin} with {'a read-only key' if args.system == 'stripe' else 'the configured token'}",
              file=sys.stderr)
        if args.system == "stripe":
            finder = StripeRefunds(StripeRefundVerifier(client), since=since, match_metadata=args.match_metadata)
        else:
            finder = FhirAppointments(FhirAppointmentVerifier(client))
        labels: dict[str, str] = {}
        made = reconcile(outcomes, finder, receipts.key, prior=prior, receipts=receipts,
                         keep_outcome_ids=args.keep_outcome_ids, labels=labels)
    summary = summarise_reconciliation(made, labels)
    print(json.dumps(summary, indent=2) if args.json else render_reconciliation(summary))
    print(f"{len(made)} receipt(s) appended to {args.receipts}; head: {receipts.head}", file=sys.stderr)
    return OK if summary["verified"] == summary["billed"] else BROKEN


def verify_receipts_main(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        print(f"ERROR: no such file: {args.path}", file=sys.stderr)
        return FILE_ERROR
    public_key = None
    if args.public_key:
        try:
            public_key = load_public_key(args.public_key)
        except ImportError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return USAGE
        except (OSError, ValueError, ReceiptKeyError) as error:
            print(f"ERROR: cannot use public key {args.public_key}: {getattr(error, 'strerror', None) or error}", file=sys.stderr)
            return FILE_ERROR
        if not os.environ.get(RECEIPT_KEY_ENV):
            if args.anchor or args.head:
                print("ERROR: --anchor and --head need the receipt key; without it only signatures are checked", file=sys.stderr)
                return USAGE
            try:
                count, problems = verify_signed_receipts(path, public_key)
            except (OSError, UnicodeDecodeError) as error:
                print(f"ERROR: cannot read {args.path}: {error}", file=sys.stderr)
                return FILE_ERROR
            for problem in problems:
                print(f"BROKEN: {problem}")
            if problems:
                return BROKEN
            print(f"OK: {count} receipts, every signature verifies and the records link up")
            print("note: without the receipt key the keyed chain is not recomputed; use the issuer's anchor to catch dropped receipts")
            return OK
    try:
        log = ReceiptLog(path, public_key=public_key, require_signed=public_key is not None)
        problems = log.verify()
        records = log.records()
    except ReceiptKeyError as error:
        print(f"ERROR: {error} ({RECEIPT_KEY_ENV})", file=sys.stderr)
        return USAGE
    except ValueError as error:
        print(f"BROKEN: {error}", file=sys.stderr)
        return BROKEN
    except OSError as error:
        print(f"ERROR: cannot read {args.path}: {error.strerror or error}", file=sys.stderr)
        return FILE_ERROR
    if problems:
        for problem in problems:
            print(f"BROKEN: {problem}")
        return BROKEN
    if args.anchor or args.head:
        if args.anchor:
            try:
                count, head = FileAnchor(args.anchor).read()
            except (OSError, ValueError) as error:
                print(f"ERROR: cannot use anchor {args.anchor}: {error}", file=sys.stderr)
                return FILE_ERROR
        else:
            wanted = args.head.strip().lower()
            found = [i for i, record in enumerate(records) if record["hash"] == wanted]
            count, head = (found[0] + 1, wanted) if found else (0, wanted)
        problem = log.check_anchor(count, head) if count else "the given head is not in the log: receipts were dropped or rewritten"
        if problem:
            print(f"BROKEN: {problem}")
            return BROKEN
    print(f"OK: {len(records)} receipts, chain intact, every receipt verifies")
    print(f"head: {log.head}")
    return OK


if __name__ == "__main__":
    sys.exit(main())
