"""Receipts: issue, verify, log, and the receipted() runtime hook.

Security tests show each attack failing (forged or edited receipts, reused
keys, leaked identifiers), per the repo convention.
"""

import asyncio
import json
from datetime import datetime, timezone

import pytest

from agent_readback import (
    Claim, EvidenceLog, Finding, FindingKind, OutcomeNotVerified, Receipt, ReceiptKeyError, ReceiptLog,
    ReceiptVerdict, Status, Verdict, issue_receipt, receipted, verify_receipt, watch,
)
from agent_readback.cli import main
from agent_readback.evidence import FileAnchor
from agent_readback.receipts import RECEIPT_KEY_ENV, effect_of
from agent_readback.verifiers import FhirAppointmentVerifier, StripeRefundVerifier
from tests.conftest import DOCTOR, END, PATIENT, START, leak_text
from tests.test_stripe_sql_alerts import MockStripe

KEY = "test-receipt-key-0123456789abcdef-not-a-real-secret"
OTHER_KEY = "another-test-receipt-key-0123456789abcdef-not-real"
LOG_KEY = "test-evidence-log-key-0123456789abcdef-not-real"  # only ever used as a log key
REFUND = Claim("stripe.refund.create", "DONE: refunded $25", {"payment_intent": "pi_SECRET42", "amount": 2500, "currency": "usd"})
ARGS = {"patient": PATIENT, "practitioner": DOCTOR, "start": START, "end": END}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (RECEIPT_KEY_ENV, "READBACK_LOG_KEY", "READBACK_ALERT_KEY"):
        monkeypatch.delenv(name, raising=False)


def refund_verdict(action=lambda s: s.refund("pi_SECRET42", 2500)):
    stripe = MockStripe()
    with watch(StripeRefundVerifier(stripe.client()), REFUND) as w:
        action(stripe)
    return w.verdict


# -- verdict mapping (FR-2, FR-3) ------------------------------------------------------

@pytest.mark.parametrize("status, kinds, expected", [
    (Status.VERIFIED, [], ReceiptVerdict.VERIFIED),
    (Status.FAILED, [FindingKind.MISSING], ReceiptVerdict.MISSING),
    (Status.FAILED, [FindingKind.MISSING, FindingKind.EXTRA_EFFECT], ReceiptVerdict.MISSING),
    (Status.FAILED, [FindingKind.WRONG_VALUE], ReceiptVerdict.CONTRADICTED),
    (Status.FAILED, [FindingKind.EXTRA_EFFECT], ReceiptVerdict.CONTRADICTED),
    (Status.FAILED, [], ReceiptVerdict.CONTRADICTED),
    (Status.UNVERIFIED, [FindingKind.PENDING], ReceiptVerdict.PENDING),
    (Status.UNVERIFIED, [FindingKind.UNREACHABLE], ReceiptVerdict.UNVERIFIABLE),
    (Status.UNVERIFIED, [], ReceiptVerdict.UNVERIFIABLE),
])
def test_every_readback_verdict_maps_to_one_receipt_verdict(status, kinds, expected):
    verdict = Verdict(status, REFUND, tuple(Finding(kind, "x") for kind in kinds), {"created": [{"id": "re_1", "status": "succeeded"}]})
    receipt = issue_receipt(verdict, KEY)
    assert receipt.verdict == expected.value
    assert receipt.billable is (expected is ReceiptVerdict.VERIFIED)  # pending is never billable


def test_receipt_fields_for_a_verified_refund():
    verdict = refund_verdict()
    fixed = datetime(2026, 11, 24, 23, 59, tzinfo=timezone.utc)
    receipt = issue_receipt(verdict, KEY, outcome_id="fin-00412", now=lambda: fixed)
    data = receipt.to_dict()
    assert data["receipt_version"] == 1 and data["mac_alg"] == "hmac-sha256"
    assert data["receipt_id"].startswith("rcpt_") and len(data["receipt_id"]) == 37
    assert (data["action"], data["system"], data["verdict"], data["billable"]) == ("stripe.refund.create", "stripe", "verified", True)
    assert data["query"] == "GET /v1/refunds?payment_intent={subject}"
    assert data["checked_at"] == verdict.checked_at and data["issued_at"] == fixed.isoformat()
    for name in ("claim_digest", "subject_digest", "observed_digest", "effect_digest", "mac"):
        assert len(data[name]) == 64
    assert effect_of(verdict) == "stripe:refund:re_1"
    assert verify_receipt(data, KEY) is None


def test_reasons_carry_kinds_and_field_names_only():
    verdict = refund_verdict(lambda s: s.refund("pi_SECRET42", 999))
    receipt = issue_receipt(verdict, KEY)
    assert receipt.verdict == "contradicted"
    assert receipt.to_dict()["reasons"] == [{"kind": "wrong_value", "field": "amount"}]


def test_receipt_holds_no_identifiers_or_values():
    """SEC-2: no payment intent, refund id, amount or agent text anywhere in the receipt."""
    verdict = refund_verdict()
    text = leak_text(issue_receipt(verdict, KEY, outcome_id="fin-1").to_dict())
    for leaked in ("pi_SECRET42", "re_1", "2500", "refunded", "usd", "ch_1"):
        assert leaked not in text


def test_digests_are_keyed_so_guessing_an_id_needs_the_key():
    """I2: the same subject gives a different digest under another key, and never the plain SHA-256."""
    import hashlib

    verdict = refund_verdict()
    a, b = issue_receipt(verdict, KEY), issue_receipt(verdict, OTHER_KEY)
    assert a.subject_digest != b.subject_digest
    assert a.subject_digest != hashlib.sha256(b'{"payment_intent":"pi_SECRET42"}').hexdigest()
    assert issue_receipt(verdict, KEY).subject_digest == a.subject_digest  # stable, so key holders can match records


def test_override_can_downgrade_but_never_upgrade():
    failed = Verdict(Status.FAILED, REFUND, (Finding(FindingKind.MISSING, "x"),))
    with pytest.raises(ValueError, match="only be verified"):
        issue_receipt(failed, KEY, override=ReceiptVerdict.VERIFIED)
    receipt = issue_receipt(refund_verdict(), KEY, override=ReceiptVerdict.CONTRADICTED, extra_reasons=["duplicate_effect"])
    assert (receipt.verdict, receipt.billable) == ("contradicted", False)
    assert receipt.to_dict()["reasons"] == [{"kind": "duplicate_effect", "field": None}]


@pytest.mark.parametrize("bad", ["", "-1+2", "=HYPERLINK(1)", "@cmd", "a" * 129, "has space", "x\n", "a@b.com"])
def test_outcome_ids_that_could_carry_formulas_or_personal_data_are_refused(bad):
    with pytest.raises(ValueError, match="outcome_id"):
        issue_receipt(refund_verdict(), KEY, outcome_id=bad)


# -- keys (SEC-3) ------------------------------------------------------------------------

def test_no_key_means_no_receipt():
    with pytest.raises(ReceiptKeyError, match="required"):
        issue_receipt(refund_verdict())


def test_short_key_is_refused():
    with pytest.raises(ReceiptKeyError, match="32 bytes"):
        issue_receipt(refund_verdict(), "short-key")


def test_key_from_environment(monkeypatch):
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    assert verify_receipt(issue_receipt(refund_verdict()).to_dict()) is None


def test_receipt_key_equal_to_the_log_key_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("READBACK_LOG_KEY", KEY)
    with pytest.raises(ReceiptKeyError, match="READBACK_LOG_KEY"):
        issue_receipt(refund_verdict(), KEY)
    monkeypatch.delenv("READBACK_LOG_KEY")
    EvidenceLog(tmp_path / "e.jsonl", key=LOG_KEY)  # a log in this process using the key also counts
    with pytest.raises(ReceiptKeyError, match="READBACK_LOG_KEY"):
        ReceiptLog(tmp_path / "r.jsonl", key=LOG_KEY)


def test_receipt_key_equal_to_the_alert_key_is_refused(monkeypatch):
    monkeypatch.setenv("READBACK_ALERT_KEY", KEY)
    with pytest.raises(ReceiptKeyError, match="READBACK_ALERT_KEY"):
        issue_receipt(refund_verdict(), KEY)


def test_a_receipt_log_key_is_not_registered_as_a_log_key(tmp_path):
    from agent_readback import WebhookAlert

    ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    WebhookAlert("https://alerts.test", key=KEY)  # the receipt log did not mark its key as a log key
    with pytest.raises(ReceiptKeyError, match="READBACK_ALERT_KEY"):
        issue_receipt(refund_verdict(), KEY)  # but an alert now signs with it, so it is no receipt key


# -- verify one receipt (FR-5, SEC-4) ---------------------------------------------------

def signed():
    return issue_receipt(refund_verdict(lambda s: None), KEY, outcome_id="fin-7").to_dict()


@pytest.mark.parametrize("field, value", [
    ("verdict", "verified"),
    ("outcome_id", "fin-8"),
    ("checked_at", "2020-01-01T00:00:00+00:00"),
    ("reasons", []),
    ("effect_digest", "0" * 64),
])
def test_editing_any_field_breaks_the_mac(field, value):
    receipt = signed()
    receipt[field] = value
    if field == "verdict":
        receipt["billable"] = True  # a careful forger keeps the layout consistent
    assert "MAC" in verify_receipt(receipt, KEY)


def test_a_receipt_made_with_another_key_does_not_verify():
    forged = issue_receipt(refund_verdict(), OTHER_KEY).to_dict()
    assert "MAC" in verify_receipt(forged, KEY)


def test_a_receipt_recomputed_with_a_guessed_mac_scheme_does_not_verify():
    """The MAC is domain-separated: a plain HMAC over the JSON is not accepted."""
    import hashlib
    import hmac

    receipt = signed()
    receipt.update(verdict="verified", billable=True, reasons=[])
    unsigned = {k: v for k, v in receipt.items() if k != "mac"}
    receipt["mac"] = hmac.new(KEY.encode(), json.dumps(unsigned, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    assert verify_receipt(receipt, KEY) is not None


@pytest.mark.parametrize("mutate, problem", [
    (lambda r: r.pop("mac"), "missing"),
    (lambda r: r.update(extra=1), "unexpected"),
    (lambda r: r.update(receipt_version=True), "wrong type"),
    (lambda r: r.update(receipt_version=2), "receipt_version"),
    (lambda r: r.update(mac_alg="none"), "mac_alg"),
    (lambda r: r.update(verdict="maybe"), "unknown verdict"),
    (lambda r: r.update(billable=True), "billable"),
    (lambda r: r.update(mac="Z" * 64), "64 lowercase hex"),
    (lambda r: r.update(mac=["not", "a", "string"]), "wrong type"),
    (lambda r: r.update(receipt_id="rcpt_x"), "receipt_id"),
])
def test_malformed_receipts_are_reported_not_crashed_on(mutate, problem):
    receipt = signed()
    mutate(receipt)
    assert problem in verify_receipt(receipt, KEY)


def test_non_object_is_not_a_receipt():
    assert verify_receipt(["not", "a", "receipt"], KEY) == "not a receipt object"


# -- receipt log (FR-6, SEC-10) ---------------------------------------------------------

def test_receipt_log_round_trip_and_cli(tmp_path, monkeypatch, capsys):
    path = tmp_path / "receipts.jsonl"
    anchor = FileAnchor(tmp_path / "anchor.json")
    log = ReceiptLog(path, key=KEY, anchor=anchor)
    for n in range(3):  # three refunds: a log bills each effect once
        log.append(issue_receipt(refund_verdict(), KEY, effect=f"stripe:refund:re_{n}"))
    assert log.verify() == [] and len(ReceiptLog(path, key=KEY).receipts()) == 3

    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    assert main(["verify-receipts", str(path), "--anchor", str(tmp_path / "anchor.json")]) == 0
    assert "3 receipts, chain intact" in capsys.readouterr().out


def test_receipt_log_cli_needs_the_key(tmp_path, capsys):
    path = tmp_path / "receipts.jsonl"
    ReceiptLog(path, key=KEY).append(issue_receipt(refund_verdict(), KEY))
    assert main(["verify-receipts", str(path)]) == 2
    assert RECEIPT_KEY_ENV in capsys.readouterr().err


def test_an_edited_receipt_in_the_log_is_reported(tmp_path, monkeypatch, capsys):
    path = tmp_path / "receipts.jsonl"
    log = ReceiptLog(path, key=KEY)
    log.append(issue_receipt(refund_verdict(lambda s: None), KEY))
    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["body"]["verdict"], record["body"]["billable"] = "verified", True
    path.write_text(json.dumps(record) + "\n")
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    assert main(["verify-receipts", str(path)]) == 1
    out = capsys.readouterr().out
    assert "chain broken at record 0" in out and "record 0: the MAC does not match" in out


def test_a_dropped_missing_receipt_is_caught_by_the_anchor(tmp_path, monkeypatch, capsys):
    path, anchor_path = tmp_path / "receipts.jsonl", tmp_path / "anchor.json"
    log = ReceiptLog(path, key=KEY, anchor=FileAnchor(anchor_path))
    log.append(issue_receipt(refund_verdict(), KEY))
    log.append(issue_receipt(refund_verdict(lambda s: None), KEY))  # the "missing" one a vendor would like gone
    path.write_text(path.read_text().splitlines()[0] + "\n")
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    assert main(["verify-receipts", str(path)]) == 0  # the file alone cannot show truncation
    assert main(["verify-receipts", str(path), "--anchor", str(anchor_path)]) == 1
    assert "dropped" in capsys.readouterr().out


def test_receipt_log_refuses_an_evidence_log(tmp_path):
    path = tmp_path / "evidence.jsonl"
    EvidenceLog(path, key=LOG_KEY).append(refund_verdict())
    with pytest.raises(ValueError, match="not a receipt log"):
        ReceiptLog(path, key=KEY)


def test_receipt_log_refuses_a_receipt_made_with_another_key(tmp_path):
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    with pytest.raises(ValueError, match="does not verify"):
        log.append(issue_receipt(refund_verdict(), OTHER_KEY))
    with pytest.raises(TypeError):
        log.append(refund_verdict())  # a verdict is not a receipt


def test_receipt_log_is_owner_only(tmp_path):
    import os
    import stat

    path = tmp_path / "r.jsonl"
    ReceiptLog(path, key=KEY).append(issue_receipt(refund_verdict(), KEY))
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_report_and_dashboard_refuse_a_receipt_log(tmp_path, monkeypatch):
    path = tmp_path / "r.jsonl"
    ReceiptLog(path, key=KEY).append(issue_receipt(refund_verdict(), KEY))
    monkeypatch.setenv("READBACK_LOG_KEY", LOG_KEY)  # wrong key for that chain
    assert main(["report", str(path)]) == 1


# -- runtime hook (FR-12) ---------------------------------------------------------------

def booking_claim(patient, practitioner, start, end):
    expected = {"patient": patient, "practitioner": practitioner, "start": start, "end": end, "status": "booked"}
    return Claim("fhir.appointment.create", "", expected)


def test_receipted_call_returns_only_when_verified(server, tools, tmp_path):
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    seen = []
    book = receipted(tools["book_appointment"], FhirAppointmentVerifier(server.client()), booking_claim, log,
                     outcome_id=lambda **a: "booking-1", on_receipt=[seen.append])
    assert book(**ARGS)["ok"] is True
    assert seen[0].verdict == "verified" and seen[0].outcome_id == "booking-1"

    server.fault = "drop"  # the server says 201 but stores nothing
    with pytest.raises(OutcomeNotVerified, match="outcome not verified: missing") as raised:
        book(**ARGS)
    assert isinstance(raised.value.receipt, Receipt) and raised.value.receipt.verdict == "missing"
    assert [r["verdict"] for r in log.receipts()] == ["verified", "missing"]  # logged before the raise
    assert log.verify() == []


def test_receipted_message_carries_no_values(server, tools, tmp_path):
    book = receipted(tools["book_appointment"], FhirAppointmentVerifier(server.client()), booking_claim,
                     ReceiptLog(tmp_path / "r.jsonl", key=KEY))
    server.fault = "wrong_practitioner"
    with pytest.raises(OutcomeNotVerified) as raised:
        book(**ARGS)
    message = str(raised.value)
    assert message == "outcome not verified: contradicted (wrong_value)"
    assert "Practitioner" not in message and "Patient" not in message


def test_receipted_writes_evidence_too_and_skips_unchecked_calls(server, tools, tmp_path):
    evidence = EvidenceLog(tmp_path / "e.jsonl", key=LOG_KEY)
    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    book = receipted(tools["book_appointment"], FhirAppointmentVerifier(server.client()),
                     lambda **a: booking_claim(**a) if a["patient"] == PATIENT else None, receipts, log=evidence)
    book(**ARGS)
    book(**{**ARGS, "patient": "Patient/77"})  # to_claim returned None: not checked, no receipt
    assert len(evidence.records()) == 1 and len(receipts.receipts()) == 1


def test_receipted_still_issues_a_receipt_when_the_tool_raises(server, tools, tmp_path):
    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    def books_then_crashes(**args):
        tools["book_appointment"](**args)
        raise RuntimeError("network blip after the write")

    book = receipted(books_then_crashes, FhirAppointmentVerifier(server.client()), booking_claim, receipts)
    with pytest.raises(RuntimeError, match="network blip"):
        book(**ARGS)
    assert [r["verdict"] for r in receipts.receipts()] == ["verified"]


def test_receipted_async(server, tools, tmp_path):
    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    async def book_async(**args):
        return tools["book_appointment"](**args)

    book = receipted(book_async, FhirAppointmentVerifier(server.client()), booking_claim, receipts)
    assert asyncio.run(book(**ARGS))["ok"] is True
    server.fault = "duplicate"
    with pytest.raises(OutcomeNotVerified, match="contradicted"):
        asyncio.run(book(**ARGS))


def test_receipted_refuses_a_log_without_a_valid_key(server, tools):
    class NoKey:
        key = None

    with pytest.raises(ReceiptKeyError):
        receipted(tools["book_appointment"], FhirAppointmentVerifier(server.client()), booking_claim, NoKey())


def test_receipted_parallel_calls_keep_their_own_receipts(server, tools, tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    book = receipted(tools["book_appointment"], FhirAppointmentVerifier(server.client()), booking_claim, receipts)
    patients = [f"Patient/{n}" for n in range(10, 18)]
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(lambda p: book(**{**ARGS, "patient": p}), patients))
    assert all(r["ok"] for r in results)
    assert len(receipts.receipts()) == 8 and receipts.verify() == []


def test_receipted_in_a_langgraph_tool_node_turns_a_false_done_into_an_error(server, tools, tmp_path):
    pytest.importorskip("langgraph")
    pytest.importorskip("langchain_core")
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import START as GRAPH_START
    from langgraph.graph import MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    @tool
    def book(patient: str, practitioner: str, start: str, end: str) -> dict:
        """Book an appointment in the mock FHIR store."""
        return tools["book_appointment"](patient, practitioner, start, end)

    book.func = receipted(book.func, FhirAppointmentVerifier(server.client()), booking_claim, receipts)
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([book], handle_tool_errors=True))
    graph.add_edge(GRAPH_START, "tools")
    app = graph.compile()

    server.fault = "drop"
    message = AIMessage(content="", tool_calls=[{"name": book.name, "args": ARGS, "id": "call_1"}])
    reply = app.invoke({"messages": [message]})["messages"][-1]
    assert reply.status == "error" and "outcome not verified: missing" in reply.content
    assert [r["verdict"] for r in receipts.receipts()] == ["missing"]
