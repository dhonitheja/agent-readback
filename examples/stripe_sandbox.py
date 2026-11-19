"""Exercise refund read-back against Stripe test mode using separate credentials.

Run with STRIPE_TEST_SECRET_KEY and STRIPE_TEST_READ_ONLY_KEY in the environment.
Creates four synthetic payments and partial refunds; test objects are retained.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx

from agent_readback import Claim, EvidenceLog
from agent_readback.verifiers import StripeRefundVerifier


def _load_env_file() -> None:
    for candidate in (Path(".env"), Path(__file__).resolve().parent.parent / ".env"):
        if candidate.is_file():
            try:
                for line in candidate.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass


def test_keys() -> tuple[str, str]:
    writer = os.environ.get("STRIPE_TEST_SECRET_KEY", "")
    reader = os.environ.get("STRIPE_TEST_READ_ONLY_KEY", "")
    if not writer.startswith("sk_test_") or not reader.startswith("rk_test_"):
        raise ValueError("Set STRIPE_TEST_SECRET_KEY (sk_test_) and STRIPE_TEST_READ_ONLY_KEY (rk_test_). Live keys are refused.")
    return writer, reader


def run(writer: httpx.Client, reader: httpx.Client, log: EvidenceLog) -> dict:
    verifier = StripeRefundVerifier(reader)
    # Confirm the reader can list refunds before creating any test objects.
    response = reader.get("/v1/refunds", params={"limit": 1})
    response.raise_for_status()
    run_id = uuid4().hex
    results = []
    for scenario, amounts, expected_status, expected_kind in (
        ("success", [100], "verified", None),
        ("missing", [], "failed", "missing"),
        ("wrong_amount", [200], "failed", "wrong_value"),
        ("duplicate", [100, 100], "failed", "extra_effect"),
    ):
        response = writer.post("/v1/payment_intents", data={
            "amount": 1000, "currency": "usd", "payment_method": "pm_card_visa",
            "payment_method_types[]": "card", "confirm": "true",
            "metadata[readback_run]": run_id,
        }, headers={"Idempotency-Key": f"{run_id}-{scenario}-payment"})
        response.raise_for_status()
        payment = response.json()
        if payment.get("livemode") is not False or payment.get("status") != "succeeded":
            raise ValueError("Expected a successful test-mode payment; stopping before refunds.")
        claim = Claim("stripe.refund.create", "DONE: refunded 100 cents.", {
            "payment_intent": payment["id"], "amount": 100, "currency": "usd",
        }, {"scenario": scenario, "run": run_id})
        before = verifier.snapshot(claim)
        if before is None:
            raise ValueError("Refund snapshot unavailable; stopping before refunds.")
        for index, amount in enumerate(amounts):
            response = writer.post("/v1/refunds", data={
                "payment_intent": payment["id"], "amount": amount,
            }, headers={"Idempotency-Key": f"{run_id}-{scenario}-refund-{index}"})
            response.raise_for_status()
        verdict = verifier.check(claim, before)
        log.append(verdict)
        kinds = sorted({finding.kind.value for finding in verdict.findings})
        results.append({
            "scenario": scenario, "payment_intent": payment["id"],
            "status": verdict.status.value, "finding_kinds": kinds,
            "passed": verdict.status.value == expected_status and (
                expected_kind is None or expected_kind in kinds),
        })
    intact, _ = log.verify_chain()
    return {"run": run_id, "environment": "Stripe test mode", "results": results,
            "chain_intact": intact, "passed": intact and all(item["passed"] for item in results)}


def main() -> None:
    _load_env_file()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.log.exists() or args.out.exists():
        parser.error("Use fresh --log and --out paths; existing results are never overwritten.")
    try:
        writer_key, reader_key = test_keys()
    except ValueError as error:
        parser.error(str(error))
    with httpx.Client(base_url="https://api.stripe.com", auth=(writer_key, ""), timeout=30) as writer, \
         httpx.Client(base_url="https://api.stripe.com", auth=(reader_key, ""), timeout=30) as reader:
        summary = run(writer, reader, EvidenceLog(args.log))
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
