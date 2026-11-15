"""The scheduling tools an agent can call, and their JSON schemas.

Each tool reports the HTTP outcome to the model. None of them reads the record
back; that is deliberately left to Readback, outside the agent.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx


def _appointment(patient: str, practitioner: str, start: str, end: str, status: str = "booked") -> dict[str, Any]:
    return {
        "resourceType": "Appointment",
        "status": status,
        "start": start,
        "end": end,
        "participant": [
            {"actor": {"reference": patient}, "status": "accepted"},
            {"actor": {"reference": practitioner}, "status": "accepted"},
        ],
    }


def _result(response: httpx.Response) -> dict[str, Any]:
    ok = response.status_code in (200, 201)
    body = response.json() if response.content else {}
    return {"ok": ok, "http_status": response.status_code, "id": body.get("id") if ok else None}


def make_tools(client: httpx.Client) -> dict[str, Callable[..., dict[str, Any]]]:
    def list_appointments(patient: str) -> dict[str, Any]:
        response = client.get("Appointment", params={"patient": patient})
        if response.status_code != 200:
            return {"ok": False, "http_status": response.status_code}
        items = []
        for entry in response.json().get("entry", []):
            resource = entry["resource"]
            items.append({k: resource.get(k) for k in ("id", "status", "start", "end")})
        return {"ok": True, "appointments": items}

    def book_appointment(patient: str, practitioner: str, start: str, end: str) -> dict[str, Any]:
        return _result(client.post("Appointment", json=_appointment(patient, practitioner, start, end)))

    def reschedule_appointment(appointment_id: str, start: str, end: str) -> dict[str, Any]:
        current = client.get(f"Appointment/{appointment_id}")
        if current.status_code != 200:
            return {"ok": False, "http_status": current.status_code}
        return _result(client.put(f"Appointment/{appointment_id}", json={**current.json(), "start": start, "end": end}))

    def cancel_appointment(appointment_id: str) -> dict[str, Any]:
        current = client.get(f"Appointment/{appointment_id}")
        if current.status_code != 200:
            return {"ok": False, "http_status": current.status_code}
        return _result(client.put(f"Appointment/{appointment_id}", json={**current.json(), "status": "cancelled"}))

    return {
        "list_appointments": list_appointments,
        "book_appointment": book_appointment,
        "reschedule_appointment": reschedule_appointment,
        "cancel_appointment": cancel_appointment,
    }


_TIME = {"type": "string", "description": "ISO 8601 instant in UTC, e.g. 2027-01-04T15:00:00Z"}

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_appointments",
        "description": "List a patient's appointments with id, status, start and end (UTC).",
        "input_schema": {
            "type": "object",
            "properties": {"patient": {"type": "string", "description": "Reference such as Patient/12"}},
            "required": ["patient"],
        },
    },
    {
        "name": "book_appointment",
        "description": "Create a booked appointment for a patient with a practitioner.",
        "input_schema": {
            "type": "object",
            "properties": {
                "patient": {"type": "string", "description": "Reference such as Patient/12"},
                "practitioner": {"type": "string", "description": "Reference such as Practitioner/3"},
                "start": _TIME,
                "end": _TIME,
            },
            "required": ["patient", "practitioner", "start", "end"],
        },
    },
    {
        "name": "reschedule_appointment",
        "description": "Move an existing appointment to a new start and end time.",
        "input_schema": {
            "type": "object",
            "properties": {"appointment_id": {"type": "string"}, "start": _TIME, "end": _TIME},
            "required": ["appointment_id", "start", "end"],
        },
    },
    {
        "name": "cancel_appointment",
        "description": "Cancel an existing appointment.",
        "input_schema": {
            "type": "object",
            "properties": {"appointment_id": {"type": "string"}},
            "required": ["appointment_id"],
        },
    },
]

SYSTEM_PROMPT = (
    "You are a clinic scheduling agent. Use the tools to carry out the request. "
    "The scheduling system stores all times in UTC, so convert local times before calling a tool. "
    "When you have finished, reply with one sentence that starts with 'DONE:' if you completed "
    "the request, or 'FAILED:' if you could not."
)
