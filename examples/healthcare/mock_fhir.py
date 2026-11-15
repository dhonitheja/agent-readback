"""An in-memory stand-in for a FHIR R4 server, with switchable faults.

It answers through httpx.MockTransport, so the example and tests need no
network and no real patient data. Every write fault still returns a success
status, which is the point: the tool call looks fine while stored state is wrong.

Faults (set `server.fault`; applies to every write until changed):
  ok                  behave correctly
  drop                acknowledge a create or update but store nothing
  wrong_time          store a create one day later than requested
  wrong_practitioner  store a create with a different practitioner
  duplicate           store a create twice
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import httpx

FAULTS = ("ok", "drop", "wrong_time", "wrong_practitioner", "duplicate")
BASE = "http://fhir.test/baseR4/"


class MockFhirServer:
    def __init__(self) -> None:
        self.store: dict[str, dict[str, dict[str, Any]]] = {"Appointment": {}, "Patient": {}, "Practitioner": {}}
        self.fault = "ok"
        self.down = False
        self._next_id = 1

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handle), base_url=BASE)

    def _save(self, kind: str, resource: dict[str, Any]) -> dict[str, Any]:
        saved = {**resource, "resourceType": kind, "id": str(self._next_id)}
        self._next_id += 1
        self.store[kind][saved["id"]] = saved
        return saved

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(503, json={"issue": "server unavailable"})
        parts = request.url.path.removeprefix("/baseR4/").strip("/").split("/")
        kind = parts[0]
        if kind not in self.store:
            return httpx.Response(404, json={"issue": "unknown resource type"})
        if request.method == "POST" and len(parts) == 1:
            body = json.loads(request.content)
            if kind == "Appointment":
                return self._create_appointment(body)
            return httpx.Response(201, json=self._save(kind, body))
        if request.method == "GET" and len(parts) == 1 and kind == "Appointment":
            patient = request.url.params.get("patient")
            entries = [
                {"resource": resource}
                for resource in self.store["Appointment"].values()
                if any((p.get("actor") or {}).get("reference") == patient for p in resource.get("participant", []))
            ]
            return httpx.Response(200, json={"resourceType": "Bundle", "entry": entries})
        if len(parts) == 2:
            resource = self.store[kind].get(parts[1])
            if resource is None:
                return httpx.Response(404, json={"issue": "not found"})
            if request.method == "GET":
                return httpx.Response(200, json=resource)
            if request.method == "PUT":
                body = {**json.loads(request.content), "resourceType": kind, "id": parts[1]}
                if self.fault != "drop":
                    self.store[kind][parts[1]] = body
                return httpx.Response(200, json=body)
        return httpx.Response(405, json={"issue": "not supported by the mock"})

    def _create_appointment(self, resource: dict[str, Any]) -> httpx.Response:
        fault = self.fault
        if fault == "drop":
            return httpx.Response(201, json={**resource, "id": "pending"})
        if fault == "wrong_time":
            start = datetime.fromisoformat(resource["start"].replace("Z", "+00:00")) + timedelta(days=1)
            resource = {**resource, "start": start.isoformat()}
        if fault == "wrong_practitioner":
            resource = {
                **resource,
                "participant": [
                    {"actor": {"reference": "Practitioner/999"}}
                    if (p.get("actor") or {}).get("reference", "").startswith("Practitioner/")
                    else p
                    for p in resource["participant"]
                ],
            }
        saved = self._save("Appointment", resource)
        if fault == "duplicate":
            self._save("Appointment", resource)
        return httpx.Response(201, json=saved)
