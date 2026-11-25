"""Reconciliation: outcome exports read back against Stripe and FHIR, plus the CLI.

Fixtures use fake ids and test values only.
"""

import json

import httpx
import pytest

from agent_readback import ReceiptLog, issue_receipt, verify_receipt
from agent_readback import cli
from agent_readback.cli import main
from agent_readback.reconcile import (
    ExportError, FhirAppointments, StripeRefunds, load_outcomes, parse_since, prior_effects, reconcile, render, summarise,
)
from agent_readback.receipts import RECEIPT_KEY_ENV
from agent_readback.verifiers import FhirAppointmentVerifier, StripeRefundVerifier
from tests.conftest import DOCTOR, END, PATIENT, START
from tests.test_stripe_sql_alerts import MockStripe

KEY = "test-receipt-key-0123456789abcdef-not-a-real-secret"
FAKE_RK = "rk_test_FAKE_not_a_real_key_0000"
HEADER = "outcome_id,action,payment_intent,amount,currency\n"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (RECEIPT_KEY_ENV, "READBACK_LOG_KEY", "READBACK_ALERT_KEY", "READBACK_STRIPE_KEY", "READBACK_FHIR_TOKEN"):
        monkeypatch.delenv(name, raising=False)


class Stripe(MockStripe):
    """MockStripe with creation times and a record of every request method."""

    def __init__(self):
        super().__init__()
        self.methods = []

    def refund(self, payment_intent, amount, currency="usd", status="succeeded", created=1_764_000_000):
        super().refund(payment_intent, amount, currency, status)
        self.refunds[-1]["created"] = created

    def _handle(self, request):
        self.methods.append(request.method)
        return super()._handle(request)

    def transport(self):
        return httpx.MockTransport(self._handle)


def csv_file(tmp_path, rows, name="outcomes.csv", header=HEADER):
    path = tmp_path / name
    path.write_text(header + "".join(row + "\n" for row in rows), encoding="utf-8")
    return path


def run_stripe(stripe, path, **kwargs):
    finder = StripeRefunds(StripeRefundVerifier(stripe.client()), since=kwargs.pop("since", None))
    return reconcile(load_outcomes(path, system="stripe"), finder, KEY, **kwargs)


# -- Stripe (FR-7, FR-9, FR-10) -------------------------------------------------------

def test_billed_vs_verified(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    stripe.refund("pi_B2", 1000, status="pending")
    stripe.refund("pi_C3", 700, status="failed")
    stripe.refund("pi_E5", 999)
    path = csv_file(tmp_path, [
        "fin-1,stripe.refund.create,pi_A1,2500,usd",   # verified
        "fin-2,stripe.refund.create,pi_B2,1000,usd",   # pending at the bank
        "fin-3,stripe.refund.create,pi_C3,700,usd",    # refund failed
        "fin-4,stripe.refund.create,pi_D4,300,usd",    # never happened
        "fin-5,stripe.refund.create,pi_E5,1000,usd",   # a refund exists, but not this one
    ])
    receipts = run_stripe(stripe, path)
    assert [r.verdict for r in receipts] == ["verified", "pending", "contradicted", "missing", "missing"]
    summary = summarise(receipts)
    assert (summary["billed"], summary["verified"], summary["verified_rate"]) == (5, 1, 0.2)
    assert render(summary).splitlines()[0] == "5 billed, 1 verified (20.0%)"
    assert all(verify_receipt(r.to_dict(), KEY) is None for r in receipts)


def test_one_refund_cannot_back_two_outcomes(tmp_path):
    """T3: the vendor bills twice for one refund."""
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd", "fin-2,stripe.refund.create,pi_A1,2500,usd"])
    first, second = run_stripe(stripe, path)
    assert first.verdict == "verified"
    assert second.verdict == "contradicted" and second.to_dict()["reasons"] == [{"kind": "duplicate_effect", "field": None}]


def test_two_real_refunds_back_two_outcomes(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    stripe.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd", "fin-2,stripe.refund.create,pi_A1,2500,usd"])
    assert [r.verdict for r in run_stripe(stripe, path)] == ["verified", "verified"]
    assert len({r.effect_digest for r in run_stripe(stripe, path)}) == 2


def test_a_repeated_outcome_id_is_contradicted(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    stripe.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd", "fin-1,stripe.refund.create,pi_A1,2500,usd"])
    receipts = run_stripe(stripe, path)
    assert [r.verdict for r in receipts] == ["verified", "contradicted"]
    assert receipts[1].reasons == ({"kind": "duplicate_outcome", "field": None},)


def test_an_effect_billed_last_month_cannot_be_billed_again(tmp_path):
    """T3 across periods: --prior receipt logs."""
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    october = ReceiptLog(tmp_path / "october.jsonl", key=KEY)
    run_stripe(stripe, csv_file(tmp_path, ["oct-1,stripe.refund.create,pi_A1,2500,usd"]), receipts=october)
    prior = prior_effects([october.path], KEY)
    again = run_stripe(stripe, csv_file(tmp_path, ["nov-1,stripe.refund.create,pi_A1,2500,usd"], name="nov.csv"), prior=prior)
    assert again[0].verdict == "contradicted" and again[0].reasons == ({"kind": "already_billed", "field": None},)


def test_runtime_receipts_count_as_prior_too(tmp_path):
    """A refund verified by receipted() at runtime has the same effect digest as in reconciliation."""
    from agent_readback import Claim, watch

    stripe = Stripe()
    claim = Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": 2500, "currency": "usd"})
    with watch(StripeRefundVerifier(stripe.client()), claim) as w:
        stripe.refund("pi_A1", 2500)
    runtime = ReceiptLog(tmp_path / "runtime.jsonl", key=KEY)
    runtime.append(issue_receipt(w.verdict, KEY))
    receipts = run_stripe(stripe, csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"]),
                          prior=prior_effects([runtime.path], KEY))
    assert receipts[0].reasons == ({"kind": "already_billed", "field": None},)


def test_a_tampered_prior_log_is_refused(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    october = ReceiptLog(tmp_path / "october.jsonl", key=KEY)
    run_stripe(stripe, csv_file(tmp_path, ["oct-1,stripe.refund.create,pi_A1,2500,usd"]), receipts=october)
    text = october.path.read_text().replace('"verified"', '"missing"', 1)
    october.path.write_text(text)
    with pytest.raises(ValueError, match="does not verify"):
        prior_effects([october.path], KEY)


def test_since_ignores_refunds_from_before_the_period(tmp_path):
    """T4: an old refund cannot verify a new outcome."""
    stripe = Stripe()
    stripe.refund("pi_A1", 2500, created=parse_since("2026-10-15"))
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"])
    assert run_stripe(stripe, path)[0].verdict == "verified"
    assert run_stripe(stripe, path, since=parse_since("2026-11-01"))[0].verdict == "missing"


def test_since_without_creation_times_is_unverifiable(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500, created=None)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"])
    assert run_stripe(stripe, path, since=0)[0].verdict == "unverifiable"


def test_an_unreachable_server_is_unverifiable_and_read_once(tmp_path):
    stripe = Stripe()
    stripe.down = True
    path = csv_file(tmp_path, [f"fin-{n},stripe.refund.create,pi_A1,2500,usd" for n in range(5)])
    assert {r.verdict for r in run_stripe(stripe, path)} == {"unverifiable"}
    assert len(stripe.methods) == 1  # cached per payment intent, errors included


def test_only_get_requests_are_made(tmp_path):
    """SEC-1 / E1."""
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    run_stripe(stripe, csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd", "fin-2,stripe.refund.create,pi_Z9,1,usd"]))
    assert stripe.methods and set(stripe.methods) == {"GET"}


def test_receipts_and_report_hold_no_identifiers_or_values(tmp_path):
    """SEC-2 / I1."""
    stripe = Stripe()
    stripe.refund("pi_SECRET1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_SECRET1,2500,usd", "fin-2,stripe.refund.create,pi_SECRET2,4321,usd"])
    receipts = run_stripe(stripe, path)
    text = json.dumps([r.to_dict() for r in receipts]) + render(summarise(receipts)) + json.dumps(summarise(receipts))
    for leaked in ("pi_SECRET1", "pi_SECRET2", "re_1", "2500", "4321", "usd"):
        assert leaked not in text


def test_server_error_text_never_reaches_a_receipt(tmp_path):
    """I3: httpx errors quote the URL, which holds the payment intent."""
    def leaky(request):
        return httpx.Response(500, json={"error": f"boom for {request.url}"})

    client = httpx.Client(transport=httpx.MockTransport(leaky), base_url="https://stripe.test")
    receipts = reconcile(load_outcomes(csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_SECRET9,1,usd"])),
                         StripeRefunds(StripeRefundVerifier(client)), KEY)
    assert receipts[0].verdict == "unverifiable"
    assert "pi_SECRET9" not in json.dumps(receipts[0].to_dict())


def test_a_stripe_secret_key_is_still_refused():
    client = httpx.Client(base_url="https://stripe.test", auth=("sk_test_FAKE", ""))
    with pytest.raises(ValueError, match="restricted read-only key"):
        StripeRefunds(StripeRefundVerifier(client))


# -- FHIR (FR-7) -------------------------------------------------------------------------

FHIR_HEADER = "outcome_id,action,id,patient,practitioner,start,end,status\n"


def test_fhir_create_update_cancel(tmp_path, server, tools):
    first = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    second = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    tools["cancel_appointment"](second)
    rows = [
        f"b-1,fhir.appointment.create,,{PATIENT},{DOCTOR},{START},{END},booked",     # verified (first)
        f"b-2,fhir.appointment.create,,{PATIENT},{DOCTOR},{START},{END},booked",     # only booking left is used: contradicted
        f"c-1,fhir.appointment.cancel,{second},{PATIENT},,,,",                        # verified
        f"c-2,fhir.appointment.cancel,{first},{PATIENT},,,,",                         # not cancelled: contradicted
        f"c-3,fhir.appointment.cancel,{second},{PATIENT},,,,",                        # same cancel billed twice
        f"u-1,fhir.appointment.update,404,{PATIENT},,,,booked",                       # gone: missing
        f"b-3,fhir.appointment.create,,Patient/2,{DOCTOR},{START},{END},booked",      # never booked
    ]
    path = csv_file(tmp_path, rows, header=FHIR_HEADER)
    receipts = reconcile(load_outcomes(path, system="fhir"), FhirAppointments(FhirAppointmentVerifier(server.client())), KEY)
    assert [r.verdict for r in receipts] == ["verified", "contradicted", "verified", "contradicted", "contradicted", "missing", "missing"]
    assert receipts[1].reasons == ({"kind": "duplicate_effect", "field": None},)
    assert receipts[3].reasons == ({"kind": "wrong_value", "field": "status"},)
    assert receipts[4].reasons == ({"kind": "duplicate_effect", "field": None},)
    text = json.dumps([r.to_dict() for r in receipts])
    assert PATIENT not in text and DOCTOR not in text and "2027-01-04" not in text


def test_fhir_id_cannot_walk_the_path(server):
    """A claimed id like 1/../2 must never make the verifier read another resource with its token."""
    verifier = FhirAppointmentVerifier(server.client())
    for bad in ("1/../2", "..", "a?x=1", "1\n", "x" * 65):
        with pytest.raises(ValueError, match="not a valid FHIR id"):
            verifier._one(bad)


# -- input parsing (FR-8, SEC-7) ---------------------------------------------------------

@pytest.mark.parametrize("row, problem", [
    ("fin-1,stripe.refund.create,pi_A1,25.00,usd", "whole number"),
    ("fin-1,stripe.refund.create,pi_A1,1e3,usd", "whole number"),
    ("fin-1,stripe.refund.create,pi_A1,-5,usd", "whole number"),
    ("fin-1,stripe.refund.create,pi_A1,,usd", "needs amount"),
    ("fin-1,stripe.refund.create,not-a-pi,1,usd", "payment_intent"),
    ("fin-1,stripe.refund.create,pi_A1,1,USD", "currency"),
    ("=cmd|' /C calc'!A0,stripe.refund.create,pi_A1,1,usd", "outcome_id"),
    ("fin-1,stripe.charge.create,pi_A1,1,usd", "unknown action"),
    ("fin-1,fhir.appointment.create,pi_A1,1,usd", "not a stripe action"),
    ("fin-1,stripe.refund.create,pi_A1,1", "expected 5 cells"),
])
def test_bad_rows_are_refused_without_echoing_values(tmp_path, row, problem):
    with pytest.raises(ExportError, match=problem) as raised:
        load_outcomes(csv_file(tmp_path, [row]), system="stripe")
    assert "pi_A1" not in str(raised.value) and "calc" not in str(raised.value)


def test_unknown_columns_are_refused(tmp_path):
    with pytest.raises(ExportError, match="header"):
        load_outcomes(csv_file(tmp_path, ["fin-1,x"], header="outcome_id,customer_email\n"))


def test_fields_an_action_does_not_use_are_refused(tmp_path):
    path = csv_file(tmp_path, [f"fin-1,stripe.refund.create,pi_A1,1,usd,{PATIENT}"],
                    header="outcome_id,action,payment_intent,amount,currency,patient\n")
    with pytest.raises(ExportError, match="fields not used"):
        load_outcomes(path)


def test_row_and_size_caps(tmp_path, monkeypatch):
    path = csv_file(tmp_path, [f"fin-{n},stripe.refund.create,pi_A1,1,usd" for n in range(3)])
    with pytest.raises(ExportError, match="more than 2"):
        load_outcomes(path, max_rows=2)
    from agent_readback import reconcile as module

    monkeypatch.setattr(module, "MAX_FILE_BYTES", 10)
    with pytest.raises(ExportError, match="larger than"):
        load_outcomes(path)


def test_jsonl_export(tmp_path):
    path = tmp_path / "outcomes.jsonl"
    path.write_text(json.dumps({"outcome_id": "fin-1", "action": "stripe.refund.create",
                                "expected": {"payment_intent": "pi_A1", "amount": 2500, "currency": "usd"}}) + "\n")
    assert load_outcomes(path)[0].claim.expected["amount"] == 2500


@pytest.mark.parametrize("line, problem", [
    ('{"outcome_id": "fin-1", "action": "stripe.refund.create", "expected": {"payment_intent": "pi_A1", "amount": 25.5, "currency": "usd"}}', "whole number"),
    ('{"outcome_id": "fin-1", "action": "stripe.refund.create", "expected": {"payment_intent": "pi_A1", "amount": true, "currency": "usd"}}', "whole number"),
    ('{"outcome_id": "fin-1", "action": "stripe.refund.create", "expected": {"payment_intent": "pi_A1", "amount": NaN, "currency": "usd"}}', "not a JSON object"),
    ('{"outcome_id": "fin-1", "action": "stripe.refund.create", "expected": {}, "extra": 1}', "exactly"),
    ('[1, 2]', "exactly"),
    ('{"outcome_id": ' * 5000, "longer than"),
    ('[' * 30000 + ']' * 30000, "not a JSON object"),  # deep nesting, no crash
])
def test_bad_jsonl_is_refused(tmp_path, line, problem):
    path = tmp_path / "outcomes.jsonl"
    path.write_text(line + "\n")
    with pytest.raises(ExportError, match=problem):
        load_outcomes(path)


def test_empty_export_is_refused(tmp_path):
    with pytest.raises(ExportError, match="no outcomes"):
        load_outcomes(csv_file(tmp_path, []))


# -- CLI (FR-13, SEC-5, SEC-6, SEC-9, SEC-10) -------------------------------------------

@pytest.fixture
def stripe_cli(monkeypatch):
    stripe = Stripe()
    monkeypatch.setattr(cli, "_transport", stripe.transport())
    monkeypatch.setenv("READBACK_STRIPE_KEY", FAKE_RK)
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    return stripe


def test_cli_reconcile_and_verify_receipts(tmp_path, stripe_cli, capsys):
    stripe_cli.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd", "fin-2,stripe.refund.create,pi_B2,1,usd"])
    receipts = tmp_path / "receipts.jsonl"
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(receipts)]) == 1  # one not verified
    out, err = capsys.readouterr()
    assert out.splitlines()[0] == "2 billed, 1 verified (50.0%)" and "fin-2  missing" in out
    assert FAKE_RK not in out + err
    assert main(["verify-receipts", str(receipts)]) == 0
    capsys.readouterr()

    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "again.jsonl"),
                 "--prior", str(receipts), "--json"]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["not_verified"][0] == {"outcome_id": "fin-1", "verdict": "contradicted", "reasons": ["already_billed"]}


def test_cli_all_verified_exits_0(tmp_path, stripe_cli):
    stripe_cli.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl")]) == 0


def test_cli_refuses_a_secret_key_and_takes_no_key_flag(tmp_path, stripe_cli, monkeypatch, capsys):
    monkeypatch.setenv("READBACK_STRIPE_KEY", "sk_test_FAKE_secret")
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl")]) == 2
    err = capsys.readouterr().err
    assert "rk_" in err and "sk_test_FAKE_secret" not in err
    with pytest.raises(SystemExit):
        main(["reconcile", str(path), "--system", "stripe", "--receipts", "r.jsonl", "--key", "rk_x"])


@pytest.mark.parametrize("url", ["http://api.stripe.com", "https://user:pw@api.stripe.com", "https://api.stripe.com/?x=1", "ftp://x"])  # pragma: allowlist secret
def test_cli_refuses_unsafe_base_urls(tmp_path, stripe_cli, url, capsys):
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl"), "--base-url", url]) == 2
    assert "pw" not in capsys.readouterr().err


def test_cli_allows_plain_http_for_localhost(tmp_path, stripe_cli):
    stripe_cli.refund("pi_A1", 1)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl"),
                 "--base-url", "http://127.0.0.1:12111"]) == 0


def test_cli_needs_a_receipt_key(tmp_path, stripe_cli, monkeypatch, capsys):
    monkeypatch.delenv(RECEIPT_KEY_ENV)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl")]) == 2
    assert RECEIPT_KEY_ENV in capsys.readouterr().err
    assert not (tmp_path / "r.jsonl").exists()


def test_cli_never_appends_receipts_to_another_file(tmp_path, stripe_cli, capsys):
    """E3 / SEC-10: an evidence log or any other file is left untouched."""
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    other = tmp_path / "notes.txt"
    other.write_text("keep me\n")
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(other)]) == 3
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(path)]) == 3
    assert other.read_text() == "keep me\n"


def test_cli_rate_limits_its_reads(tmp_path, stripe_cli, monkeypatch):
    limits = []
    real = cli.limit_reads
    monkeypatch.setattr(cli, "limit_reads", lambda client, limit: limits.append(limit) or real(client, limit))
    stripe_cli.refund("pi_A1", 1)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl"), "--max-rate", "5"])
    assert len(limits) == 1 and limits[0].interval == pytest.approx(0.2)


def test_cli_bad_export_exits_3_without_values(tmp_path, stripe_cli, capsys):
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_SECRET1,12.50,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl")]) == 3
    assert "pi_SECRET1" not in capsys.readouterr().err


def test_cli_fhir(tmp_path, server, tools, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_transport", httpx.MockTransport(server._handle))
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    monkeypatch.setenv("READBACK_FHIR_TOKEN", "fake-read-token")
    tools["book_appointment"](PATIENT, DOCTOR, START, END)
    path = csv_file(tmp_path, [f"b-1,fhir.appointment.create,,{PATIENT},{DOCTOR},{START},{END},booked"], header=FHIR_HEADER)
    assert main(["reconcile", str(path), "--system", "fhir", "--base-url", "https://fhir.test/baseR4/",
                 "--receipts", str(tmp_path / "r.jsonl")]) == 0
    assert "fake-read-token" not in "".join(capsys.readouterr())
    assert main(["reconcile", str(path), "--system", "fhir", "--receipts", str(tmp_path / "r.jsonl")]) == 2  # no base URL
