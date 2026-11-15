import pytest

from agent_readback import Claim
from examples.healthcare.mock_fhir import MockFhirServer
from examples.healthcare.tools import make_tools

PATIENT, DOCTOR = "Patient/1", "Practitioner/2"
START, END = "2027-01-04T15:00:00+00:00", "2027-01-04T15:30:00+00:00"
LATER, LATER_END = "2027-01-05T16:00:00+00:00", "2027-01-05T16:30:00+00:00"


@pytest.fixture
def server():
    return MockFhirServer()


@pytest.fixture
def tools(server):
    return make_tools(server.client())


def create_claim(**overrides):
    expected = {"patient": PATIENT, "practitioner": DOCTOR, "start": START, "end": END, "status": "booked"}
    expected.update(overrides)
    return Claim("fhir.appointment.create", "DONE", expected)
