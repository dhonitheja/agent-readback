"""Run one synthetic booking for a local agent and report the readback verdict."""

import argparse

from agent_readback import Claim, Status, watch
from agent_readback.verifiers import FhirAppointmentVerifier

from .mock_fhir import FAULTS, MockFhirServer
from .tasks import VISIT, seed_people, slot, utc
from .tools import make_tools


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=(*FAULTS, "unavailable"), default="ok")
    args = parser.parse_args()
    server = MockFhirServer()
    with server.client() as writer, server.client() as reader:
        patients, practitioners = seed_people(writer, patients=1, practitioners=1)
        start = slot(0)
        booking = {
            "patient": patients[0], "practitioner": practitioners[0],
            "start": utc(start), "end": utc(start + VISIT),
        }
        claim = Claim("fhir.appointment.create", "", {**booking, "status": "booked"})
        server.fault = "ok" if args.scenario == "unavailable" else args.scenario
        with watch(FhirAppointmentVerifier(reader), claim) as check:
            make_tools(writer)["book_appointment"](**booking)
            server.down = args.scenario == "unavailable"
        if check.verdict is None:  # not assert: python -O strips it
            raise SystemExit("unverified: no verdict was produced. Review required.")
        messages = {
            Status.VERIFIED: f"Synthetic appointment booked for {booking['start']}.",
            Status.FAILED: "The appointment record differs from the request. Review required.",
            Status.UNVERIFIED: "The appointment could not be verified. Review required.",
        }
        print(f"{check.verdict.status.value}: {messages[check.verdict.status]}")


if __name__ == "__main__":
    main()
