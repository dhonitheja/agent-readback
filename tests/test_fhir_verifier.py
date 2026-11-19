import pytest
import httpx

from agent_readback import Claim, FindingKind, Status, watch
from agent_readback.verifiers import FhirAppointmentVerifier
from agent_readback.verifiers.fhir import normalize_instant

from .conftest import DOCTOR, END, LATER, LATER_END, PATIENT, START, create_claim


def kinds(verdict):
    return [finding.kind for finding in verdict.findings]


def test_readback_bypasses_cached_prewrite_search(server, tools):
    cached = None

    def handle(request):
        nonlocal cached
        fresh = server._handle(request)
        if request.url.path.endswith("/Appointment"):
            if cached is None:
                cached = fresh.json()
            if request.headers.get("Cache-Control") != "no-cache":
                return httpx.Response(200, json=cached)
        return fresh

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        claim = create_claim()
        before = verifier.snapshot(claim)
        tools["book_appointment"](PATIENT, DOCTOR, START, END)
        assert verifier.check(claim, before).status is Status.VERIFIED


def test_incomplete_pagination_is_unverified():
    def handle(request):
        return httpx.Response(200, json={
            "entry": [],
            "link": [{"relation": "next", "url": "Appointment?page=next"}],
        })

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        assert verifier.snapshot(create_claim()) is None
        assert verifier.check(create_claim(), set()).status is Status.UNVERIFIED


def book(server, tools, fault="ok", claim=None):
    verifier = FhirAppointmentVerifier(server.client())
    server.fault = fault
    with watch(verifier, claim or create_claim()) as watched:
        result = tools["book_appointment"](PATIENT, DOCTOR, START, END)
    server.fault = "ok"
    return result, watched.verdict


def test_correct_booking_is_verified(server, tools):
    result, verdict = book(server, tools)
    assert result["ok"] and verdict.status is Status.VERIFIED and verdict.findings == ()


def test_dropped_write_is_caught_although_the_tool_reported_success(server, tools):
    result, verdict = book(server, tools, "drop")
    assert result["ok"]
    assert verdict.status is Status.FAILED and kinds(verdict) == [FindingKind.MISSING]


@pytest.mark.parametrize("fault, field", [("wrong_time", "start"), ("wrong_practitioner", "practitioner")])
def test_wrong_field_is_caught(server, tools, fault, field):
    _, verdict = book(server, tools, fault)
    assert verdict.status is Status.FAILED
    assert [f.field for f in verdict.findings if f.kind is FindingKind.WRONG_VALUE] == [field]


def test_duplicate_booking_is_an_extra_effect(server, tools):
    _, verdict = book(server, tools, "duplicate")
    assert verdict.status is Status.FAILED and kinds(verdict) == [FindingKind.EXTRA_EFFECT]


def test_same_instant_in_another_notation_still_verifies(server, tools):
    claim = create_claim(start="2027-01-04T09:00:00-06:00", end="2027-01-04T15:30:00Z")
    _, verdict = book(server, tools, claim=claim)
    assert verdict.status is Status.VERIFIED


def test_time_without_a_zone_is_not_silently_accepted():
    assert normalize_instant("2027-01-04T15:00:00") == "2027-01-04T15:00:00"
    assert normalize_instant("2027-01-04T15:00:00Z") == "2027-01-04T15:00:00+00:00"


def test_unreadable_server_is_unverified_not_failed(server, tools):
    verifier = FhirAppointmentVerifier(server.client())
    with watch(verifier, create_claim()) as watched:
        tools["book_appointment"](PATIENT, DOCTOR, START, END)
        server.down = True
    assert watched.verdict.status is Status.UNVERIFIED
    assert kinds(watched.verdict) == [FindingKind.UNREACHABLE]


def test_existing_appointments_are_not_mistaken_for_new_ones(server, tools):
    tools["book_appointment"](PATIENT, DOCTOR, START, END)
    _, verdict = book(server, tools, "drop")
    assert verdict.status is Status.FAILED and kinds(verdict) == [FindingKind.MISSING]


def update_claim(appointment_id):
    expected = {"id": appointment_id, "patient": PATIENT, "start": LATER, "end": LATER_END, "status": "booked"}
    return Claim("fhir.appointment.update", "DONE", expected)


def test_reschedule_is_verified(server, tools):
    appointment_id = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    verifier = FhirAppointmentVerifier(server.client())
    with watch(verifier, update_claim(appointment_id)) as watched:
        tools["reschedule_appointment"](appointment_id, LATER, LATER_END)
    assert watched.verdict.status is Status.VERIFIED


def test_reschedule_that_did_not_stick_is_caught(server, tools):
    appointment_id = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    verifier = FhirAppointmentVerifier(server.client())
    server.fault = "drop"
    with watch(verifier, update_claim(appointment_id)) as watched:
        result = tools["reschedule_appointment"](appointment_id, LATER, LATER_END)
    assert result["ok"]
    assert watched.verdict.status is Status.FAILED
    assert {f.field for f in watched.verdict.findings} == {"start", "end"}


def test_booking_a_new_slot_instead_of_moving_the_old_one_is_caught(server, tools):
    appointment_id = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    verifier = FhirAppointmentVerifier(server.client())
    with watch(verifier, update_claim(appointment_id)) as watched:
        tools["book_appointment"](PATIENT, DOCTOR, LATER, LATER_END)  # the wrong tool
    assert watched.verdict.status is Status.FAILED
    assert FindingKind.EXTRA_EFFECT in kinds(watched.verdict)
    assert FindingKind.WRONG_VALUE in kinds(watched.verdict)


def test_cancel_is_verified_and_cancelling_the_wrong_one_is_caught(server, tools):
    target = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    other = tools["book_appointment"](PATIENT, DOCTOR, LATER, LATER_END)["id"]
    verifier = FhirAppointmentVerifier(server.client())
    claim = Claim("fhir.appointment.cancel", "DONE", {"id": target, "patient": PATIENT})
    with watch(verifier, claim) as watched:
        tools["cancel_appointment"](other)
    assert watched.verdict.status is Status.FAILED
    assert [f.field for f in watched.verdict.findings] == ["status"]
    with watch(verifier, claim) as watched:
        tools["cancel_appointment"](target)
    assert watched.verdict.status is Status.VERIFIED


def test_settle_attempts_rechecks_a_write_that_lands_late(server, tools):
    verifier = FhirAppointmentVerifier(server.client())
    server.fault = "drop"
    naps = []

    def late_write(seconds):
        naps.append(seconds)
        server.fault = "ok"
        tools["book_appointment"](PATIENT, DOCTOR, START, END)  # the delayed write arrives

    with watch(verifier, create_claim(), settle_attempts=3, settle_delay=0.2, sleep=late_write) as watched:
        tools["book_appointment"](PATIENT, DOCTOR, START, END)
    assert watched.verdict.status is Status.VERIFIED and naps == [0.2]


def test_agent_exception_still_produces_a_verdict_and_a_log_record(server, tools, tmp_path):
    from agent_readback import EvidenceLog

    log = EvidenceLog(tmp_path / "e.jsonl")
    verifier = FhirAppointmentVerifier(server.client())
    with pytest.raises(KeyError):
        with watch(verifier, create_claim(), log) as watched:
            tools["book_appointment"](PATIENT, DOCTOR, START, END)
            raise KeyError("malformed model response")
    assert watched.verdict.status is Status.VERIFIED
    assert len(log.records()) == 1


def test_resources_without_an_id_are_not_collapsed():
    from agent_readback.verifiers.fhir import flatten_appointment

    assert flatten_appointment({"status": "booked"})["id"] is None
