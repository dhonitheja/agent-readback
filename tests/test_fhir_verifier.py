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
            "resourceType": "Bundle", "entry": [],
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


def test_appointment_without_an_id_is_a_read_error():
    # Keying id-less entries by position let an unchanged one look new at check time.
    from agent_readback.verifiers.fhir import flatten_appointment

    for bad in ({"resourceType": "Appointment", "status": "booked"}, {"resourceType": "Appointment", "id": ""},
                {"resourceType": "Appointment", "id": "   "}):
        with pytest.raises(ValueError, match="malformed FHIR response"):
            flatten_appointment(bad)


def test_foreign_next_link_never_receives_the_read_only_token():
    hosts = []

    def handle(request):
        hosts.append((request.url.host, request.headers.get("Authorization")))
        return httpx.Response(200, json={
            "resourceType": "Bundle", "entry": [],
            "link": [{"relation": "next", "url": "https://attacker.test/steal?page=2"}],
        })

    headers = {"Authorization": "Bearer READ-ONLY"}
    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test", headers=headers) as client:
        verifier = FhirAppointmentVerifier(client)
        assert verifier.snapshot(create_claim()) is None
        assert verifier.check(create_claim(), set()).status is Status.UNVERIFIED
    assert hosts and all(host == "fhir.test" for host, _ in hosts)


def test_absolute_next_link_on_the_same_server_is_followed():
    pages = []

    def handle(request):
        pages.append(str(request.url))
        if "page=2" in str(request.url):
            return httpx.Response(200, json={"resourceType": "Bundle", "entry": []})
        return httpx.Response(200, json={
            "resourceType": "Bundle", "entry": [],
            "link": [{"relation": "next", "url": "https://fhir.test/Appointment?page=2"}],
        })

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test") as client:
        assert FhirAppointmentVerifier(client).snapshot(create_claim()) == set()
    assert len(pages) == 2


@pytest.mark.parametrize("link", ["//attacker.test/steal", "https:attacker.test/steal", "http://fhir.test/Appointment", "https://fhir.test:8443/x"])
def test_odd_next_links_are_judged_by_where_httpx_sends_them(link):
    hosts = []

    def handle(request):
        hosts.append(str(request.url))
        return httpx.Response(200, json={"resourceType": "Bundle", "entry": [], "link": [{"relation": "next", "url": link}]})

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        target = client.build_request("GET", link).url
        verifier.snapshot(create_claim())
    off_origin = (target.scheme, target.host, target.port) != ("https", "fhir.test", None)
    assert all(h.startswith("https://fhir.test/") for h in hosts)
    if off_origin:
        assert len(hosts) == 1  # refused before the request was ever made


def test_root_relative_next_link_is_not_appended_to_the_base_path():
    paths = []

    def handle(request):
        paths.append(request.url.path)
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"resourceType": "Bundle", "entry": []})
        return httpx.Response(200, json={"resourceType": "Bundle", "entry": [], "link": [{"relation": "next", "url": "/r4/Appointment?page=2"}]})

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test/r4/") as client:
        assert FhirAppointmentVerifier(client).snapshot(create_claim()) == set()
    assert paths == ["/r4/Appointment", "/r4/Appointment"]


@pytest.mark.parametrize("link", ["/Appointment?page=2#next", "https://fhir.test/Appointment?page=2#frag", "https://[bad"])
def test_odd_next_links_never_crash_the_snapshot(link):
    def handle(request):
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"resourceType": "Bundle", "entry": []})
        return httpx.Response(200, json={"resourceType": "Bundle", "entry": [], "link": [{"relation": "next", "url": link}]})

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://fhir.test") as client:
        result = FhirAppointmentVerifier(client).snapshot(create_claim())
    assert result in (set(), None)  # followed, or refused as unverified; never an exception


MALFORMED_BUNDLES = {
    "bundle is a list": [],
    "entry is a string": {"resourceType": "Bundle", "entry": "x"},
    "entry item is a string": {"resourceType": "Bundle", "entry": ["x"]},
    "resource is a string": {"resourceType": "Bundle", "entry": [{"resource": "x"}]},
    "id is an object": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": {"x": 1}}}]},
    "participant is a string": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": "a1", "participant": "x"}}]},
    "actor reference is a number": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": "a1", "participant": [{"actor": {"reference": 7}}]}}]},
    "link is a string": {"resourceType": "Bundle", "entry": [], "link": "next"},
    "link item is a string": {"resourceType": "Bundle", "entry": [], "link": ["next"]},
    "next url is a number": {"resourceType": "Bundle", "entry": [], "link": [{"relation": "next", "url": 5}]},
    "OperationOutcome with 200": {"resourceType": "OperationOutcome", "issue": [{"severity": "error"}]},
    "bundle without resourceType": {"entry": []},
    "matched entry is not an Appointment": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Patient", "id": "p1"}}]},
    "appointment without an id": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment"}}]},
    "appointment id is empty": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": ""}}]},
    "appointment id is whitespace": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": "   "}}]},
    "actor is a list": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": "a1", "participant": [{"actor": []}]}}]},
    "actor is an empty dict list": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": "a1", "participant": [{"actor": [{}]}]}}]},
    "actor is an empty string": {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "id": "a1", "participant": [{"actor": ""}]}}]},
    "entry search is a string": {"resourceType": "Bundle", "entry": [{"search": "match", "resource": {"resourceType": "Appointment", "id": "a1"}}]},
}


@pytest.mark.parametrize("body", MALFORMED_BUNDLES.values(), ids=MALFORMED_BUNDLES.keys())
def test_malformed_fhir_search_is_unverified_not_a_crash(body):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    with httpx.Client(transport=transport, base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        assert verifier.snapshot(create_claim()) is None
        assert verifier.check(create_claim(), set()).status is Status.UNVERIFIED


def test_malformed_fhir_read_by_id_is_unverified_not_a_crash(server, tools):
    from agent_readback.verifiers.fhir import flatten_appointment

    for bad in ([], "x", {"id": "a1", "participant": [42]}):
        with pytest.raises(ValueError, match="malformed FHIR response"):
            flatten_appointment(bad)


def _bundle_appointment(appointment_id, start=START):
    return {"resource": {"resourceType": "Appointment", "id": appointment_id, "status": "booked", "start": start,
                         "end": END, "participant": [{"actor": {"reference": PATIENT}}, {"actor": {"reference": DOCTOR}}]}}


@pytest.mark.parametrize("next_link", [{"relation": "next", "url": None}, {"relation": "next", "url": ""}, {"relation": "next"}])
def test_next_link_without_a_usable_url_is_an_incomplete_read_not_verified(next_link):
    # The duplicate booking would be on page 2; a next link we cannot follow must not end the search as complete.
    pages = [{"resourceType": "Bundle", "entry": []},
             {"resourceType": "Bundle", "entry": [_bundle_appointment("a1")], "link": [next_link]}]
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=pages.pop(0) if len(pages) > 1 else pages[0]))
    with httpx.Client(transport=transport, base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        before = verifier.snapshot(create_claim())
        assert before == set()
        assert verifier.check(create_claim(), before).status is Status.UNVERIFIED


def test_outcome_and_include_entries_are_not_counted_as_appointments():
    # A server warning added only to the check-time search must not become a false extra_effect.
    warning = {"search": {"mode": "outcome"}, "resource": {"resourceType": "OperationOutcome", "issue": []}}
    included = {"search": {"mode": "include"}, "resource": {"resourceType": "Practitioner", "id": "d1"}}
    booked = {**_bundle_appointment("a1"), "search": {"mode": "match"}}
    pages = [{"resourceType": "Bundle", "entry": []},
             {"resourceType": "Bundle", "entry": [warning, booked, included]}]
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=pages.pop(0) if len(pages) > 1 else pages[0]))
    with httpx.Client(transport=transport, base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        verdict = verifier.check(create_claim(), verifier.snapshot(create_claim()))
    assert verdict.status is Status.VERIFIED and [item["id"] for item in verdict.observed["created"]] == ["a1"]


@pytest.mark.parametrize("claimed, status", [
    ("0001-01-01T00:00:00+01:00", Status.VERIFIED),  # identical text matches
    ("0001-01-01T01:00:00+02:00", Status.FAILED),    # same instant written another way does not
    (START, Status.FAILED),                          # a different instant does not
])
def test_timestamp_without_a_utc_form_is_compared_as_written_not_a_crash(claimed, status):
    stored = "0001-01-01T00:00:00+01:00"  # year 1 at +01:00 has no UTC form
    assert normalize_instant(stored) == stored
    pages = [{"resourceType": "Bundle", "entry": []},
             {"resourceType": "Bundle", "entry": [_bundle_appointment("a1", stored)]}]
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=pages.pop(0) if len(pages) > 1 else pages[0]))
    with httpx.Client(transport=transport, base_url="https://fhir.test") as client:
        verifier = FhirAppointmentVerifier(client)
        claim = create_claim(start=claimed)
        verdict = verifier.check(claim, verifier.snapshot(claim))
    assert verdict.status is status
    assert [f.field for f in verdict.findings] == ([] if status is Status.VERIFIED else ["start"])
