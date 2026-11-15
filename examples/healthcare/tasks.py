"""Generate scheduling requests in plain English together with the ground truth
that Readback will check against the FHIR server."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo

import httpx

from agent_readback import Claim

from .tools import _appointment

CENTRAL = ZoneInfo("America/Chicago")
FIRST_DAY = datetime(2027, 1, 4, 8, 0, tzinfo=CENTRAL)  # a Monday
SLOTS_PER_DAY = 16
VISIT = timedelta(minutes=30)


@dataclass
class Task:
    kind: str                                   # book | reschedule | cancel
    prompt: str                                 # what the agent is asked
    probe: Claim                                # action + expected state
    oracle: Callable[[Callable[[str, dict[str, Any]], dict[str, Any]]], str]  # correct tool calls


def slot(index: int) -> datetime:
    day, position = divmod(index, SLOTS_PER_DAY)
    return FIRST_DAY + timedelta(days=day, minutes=30 * position)


def spoken(moment: datetime) -> str:
    hour = moment.strftime("%I").lstrip("0")
    return f"{moment.strftime('%A, %B')} {moment.day}, {moment.year} at {hour}:{moment.strftime('%M %p')} Central Time"


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def seed_people(setup: httpx.Client, patients: int = 5, practitioners: int = 3) -> tuple[list[str], list[str]]:
    """Create synthetic patients and practitioners and return their references."""
    def create(kind: str, number: int) -> str:
        body = {"resourceType": kind, "name": [{"family": "Readback-Synthetic", "given": [f"{kind}{number}"]}]}
        response = setup.post(kind, json=body)
        response.raise_for_status()
        return f"{kind}/{response.json()['id']}"

    return [create("Patient", n) for n in range(patients)], [create("Practitioner", n) for n in range(practitioners)]


def make_task(rng: random.Random, run: int, setup: httpx.Client, patients: list[str], practitioners: list[str]) -> Task:
    kind = rng.choices(["book", "reschedule", "cancel"], weights=[60, 20, 20])[0]
    patient, practitioner = rng.choice(patients), rng.choice(practitioners)
    # Two distinct slots per run, so reschedules never collide with other runs.
    first, second = slot(2 * run), slot(2 * run + 1)

    if kind == "book":
        expected = {"patient": patient, "practitioner": practitioner, "start": utc(first), "end": utc(first + VISIT), "status": "booked"}
        prompt = f"Book {patient} with {practitioner} for a 30-minute visit on {spoken(first)}."

        def oracle(call: Callable[[str, dict[str, Any]], dict[str, Any]]) -> str:
            result = call("book_appointment", {"patient": patient, "practitioner": practitioner, "start": expected["start"], "end": expected["end"]})
            return "DONE: booked." if result.get("ok") else "FAILED: the booking was rejected."

        return Task(kind, prompt, Claim("fhir.appointment.create", "", expected), oracle)

    created = setup.post("Appointment", json=_appointment(patient, practitioner, utc(first), utc(first + VISIT)))
    created.raise_for_status()
    appointment_id = created.json()["id"]

    if kind == "reschedule":
        expected = {"id": appointment_id, "patient": patient, "start": utc(second), "end": utc(second + VISIT), "status": "booked"}
        prompt = f"{patient} has an appointment on {spoken(first)}. Move it to {spoken(second)}, keeping it 30 minutes long."

        def oracle(call: Callable[[str, dict[str, Any]], dict[str, Any]]) -> str:
            result = call("reschedule_appointment", {"appointment_id": appointment_id, "start": expected["start"], "end": expected["end"]})
            return "DONE: rescheduled." if result.get("ok") else "FAILED: the change was rejected."

        return Task(kind, prompt, Claim("fhir.appointment.update", "", expected), oracle)

    expected = {"id": appointment_id, "patient": patient}
    prompt = f"Cancel the appointment {patient} has on {spoken(first)}."

    def oracle(call: Callable[[str, dict[str, Any]], dict[str, Any]]) -> str:
        result = call("cancel_appointment", {"appointment_id": appointment_id})
        return "DONE: cancelled." if result.get("ok") else "FAILED: the cancellation was rejected."

    return Task(kind, prompt, Claim("fhir.appointment.cancel", "", expected), oracle)
