"""Read-back verifier for FHIR R4 Appointment resources.

Actions:
  fhir.appointment.create   expected: patient (required), practitioner, start, end, status
  fhir.appointment.update   expected: id and patient (required), plus the fields that must hold
  fhir.appointment.cancel   expected: id and patient (required); status must be "cancelled"

For every action, any Appointment for the same patient that appears during the
action and was not claimed is reported as an extra effect.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ..core import Claim, Finding, FindingKind, Status, Verdict, compare_fields

CREATE = "fhir.appointment.create"
UPDATE = "fhir.appointment.update"
CANCEL = "fhir.appointment.cancel"
MAX_PAGES = 20


def normalize_instant(value: Any) -> Any:
    """Put timezone-aware ISO timestamps in one UTC form so equal instants compare equal."""
    if not isinstance(value, str):
        return value
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        return value  # a time with no zone is ambiguous; leave it so it shows as a mismatch
    return parsed.astimezone(timezone.utc).isoformat()


def flatten_appointment(resource: dict[str, Any]) -> dict[str, Any]:
    """Reduce a FHIR Appointment to the flat fields a claim can assert on."""
    flat: dict[str, Any] = {
        "id": resource.get("id"),
        "status": resource.get("status"),
        "start": normalize_instant(resource.get("start")),
        "end": normalize_instant(resource.get("end")),
        "patient": None,
        "practitioner": None,
    }
    for participant in resource.get("participant", []):
        reference = (participant.get("actor") or {}).get("reference", "")
        if reference.startswith("Patient/"):
            flat["patient"] = reference
        elif reference.startswith("Practitioner/"):
            flat["practitioner"] = reference
    return flat


def _normalized(expected: dict[str, Any]) -> dict[str, Any]:
    return {k: (normalize_instant(v) if k in ("start", "end") else v) for k, v in expected.items()}


class FhirAppointmentVerifier:
    def __init__(self, client: httpx.Client) -> None:
        # Pass a client built with read-only credentials that the agent does not have.
        self.client = client

    # -- reads -------------------------------------------------------------
    def _appointments(self, patient: str) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        url: str | None = "Appointment"
        params: dict[str, Any] | None = {"patient": patient, "_count": 200}
        for _ in range(MAX_PAGES):
            response = self.client.get(url, params=params)
            response.raise_for_status()
            bundle = response.json()
            for entry in bundle.get("entry", []):
                flat = flatten_appointment(entry["resource"])
                found[flat["id"]] = flat
            url = next((l["url"] for l in bundle.get("link", []) if l.get("relation") == "next"), None)
            params = None
            if not url:
                break
        return found

    def _one(self, appointment_id: str) -> dict[str, Any] | None:
        response = self.client.get(f"Appointment/{appointment_id}")
        if response.status_code in (404, 410):
            return None
        response.raise_for_status()
        return flatten_appointment(response.json())

    # -- protocol ----------------------------------------------------------
    def snapshot(self, claim: Claim) -> set[str] | None:
        try:
            return set(self._appointments(claim.expected["patient"]))
        except (httpx.HTTPError, KeyError, ValueError):
            return None

    def check(self, claim: Claim, before: set[str] | None) -> Verdict:
        if before is None:
            return self._unverified(claim, "no snapshot was taken before the action")
        expected = _normalized(claim.expected)
        try:
            now = self._appointments(expected["patient"])
            created = [item for key, item in now.items() if key not in before]
            if claim.action == CREATE:
                return self._check_create(claim, expected, created)
            if claim.action in (UPDATE, CANCEL):
                return self._check_existing(claim, expected, created)
        except (httpx.HTTPError, KeyError, ValueError) as error:
            return self._unverified(claim, f"could not read the FHIR server: {error}")
        return self._unverified(claim, f"unknown action {claim.action!r}")

    # -- judgements --------------------------------------------------------
    def _check_create(self, claim: Claim, expected: dict[str, Any], created: list[dict[str, Any]]) -> Verdict:
        if not created:
            finding = Finding(FindingKind.MISSING, "no new Appointment exists for this patient")
            return Verdict(Status.FAILED, claim, (finding,), {"created": []})
        ranked = sorted(created, key=lambda item: len(compare_fields(expected, item)))
        best, others = ranked[0], ranked[1:]
        findings = compare_fields(expected, best) + self._extras(others)
        return self._verdict(claim, findings, {"created": created})

    def _check_existing(self, claim: Claim, expected: dict[str, Any], created: list[dict[str, Any]]) -> Verdict:
        current = self._one(expected["id"])
        if current is None:
            finding = Finding(FindingKind.MISSING, f"Appointment {expected['id']} no longer exists")
            return Verdict(Status.FAILED, claim, (finding, *self._extras(created)), {"created": created})
        if claim.action == CANCEL:
            expected = {"id": expected["id"], "patient": expected["patient"], "status": "cancelled"}
        findings = compare_fields(expected, current) + self._extras(created)
        return self._verdict(claim, findings, {"current": current, "created": created})

    @staticmethod
    def _extras(items: list[dict[str, Any]]) -> list[Finding]:
        return [
            Finding(FindingKind.EXTRA_EFFECT, f"unclaimed Appointment {item['id']} was also created", actual=item)
            for item in items
        ]

    @staticmethod
    def _verdict(claim: Claim, findings: list[Finding], observed: dict[str, Any]) -> Verdict:
        status = Status.VERIFIED if not findings else Status.FAILED
        return Verdict(status, claim, tuple(findings), observed)

    @staticmethod
    def _unverified(claim: Claim, reason: str) -> Verdict:
        return Verdict(Status.UNVERIFIED, claim, (Finding(FindingKind.UNREACHABLE, reason),))
