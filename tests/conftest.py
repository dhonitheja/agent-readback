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


_RANDOM_FIELDS = ("checked_at", "issued_at")


def leak_text(receipts, extra: str = "") -> str:
    """Receipts as text for leak checks, with the parts that are random by design blanked.

    Ids, digests and MACs are hex, and timestamps carry microseconds, so a value
    like "2500" can turn up in them by chance; leak checks look at everything else.
    """
    import json
    import re

    items = receipts if isinstance(receipts, list) else [receipts]
    text = json.dumps([{k: ("-" if k in _RANDOM_FIELDS else v) for k, v in item.items()} for item in items]) + extra
    return re.sub(r"[0-9a-f]{32,}", "<hex>", text)


@pytest.fixture(autouse=True)
def _forget_alert_keys():
    """WebhookAlert remembers its keys for the whole process; each test starts clean."""
    from agent_readback import alerts

    alerts._ALERT_KEY_FINGERPRINTS.clear()
    yield
    alerts._ALERT_KEY_FINGERPRINTS.clear()
