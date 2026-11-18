"""Authenticated API wiring with source-shaped test responses, not real Shuffle."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from responseforge.api import create_app
from tests.rf02.helpers import TOKENS
from tests.rf04.helpers import EXECUTION_SECRET, KEY, RUN, WF, workflow
from tests.rf04.test_client import wire_response
from tests.rf04.test_coordinator import case_world


def test_api_authenticated_launch_reconcile_restart_and_report_excludes_private_vendor_state(
    tmp_path: Path,
) -> None:
    import httpx

    starts, lookups, arguments = [], [], []

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        if request.url.path.endswith("/execute"):
            starts.append(request)
            arguments.append(json.loads(request.content)["execution_argument"])
            return wire_response(
                200, json={"success": True, "execution_id": RUN, "authorization": EXECUTION_SECRET}
            )
        lookups.append(request)
        return wire_response(
            200,
            json={
                "execution_id": RUN,
                "workflow_id": WF,
                "workflow": workflow(),
                "execution_argument": arguments[0],
                "status": "FINISHED",
                "authorization": EXECUTION_SECRET,
            },
        )

    v = case_world(tmp_path, handler)
    app = create_app(
        v.service.settings, clock=v.w.clock, shuffle_transport=httpx.MockTransport(handler)
    )
    client = TestClient(app)
    base = f"/v1/incidents/{v.incident_id}/shuffle"
    body = {"workflow_id": WF, "run_id": RUN}
    auth = {"Authorization": "Bearer " + TOKENS["analyst"]}
    assert client.post(base + "/start", json=body).status_code == 401
    assert (
        client.post(
            base + "/start", json=body, headers={"Authorization": "Bearer " + TOKENS["source"]}
        ).status_code
        == 403
    )
    assert not starts
    accepted = client.post(base + "/start", json=body, headers=auth)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["state"] == "accepted"
    completed = client.post(base + "/reconcile", json={"run_id": RUN}, headers=auth)
    assert completed.status_code == 200 and completed.json()["state"] == "finished"
    reopened = TestClient(
        create_app(
            v.service.settings, clock=v.w.clock, shuffle_transport=httpx.MockTransport(handler)
        )
    )
    duplicate = reopened.post(base + "/start", json=body, headers=auth)
    assert duplicate.status_code == 200 and duplicate.json()["state"] == "finished"
    assert len(starts) == len(lookups) == 1
    report = client.get(f"/v1/incidents/{v.incident_id}/report", headers=auth)
    assert report.status_code == 200
    assert EXECUTION_SECRET not in accepted.text + completed.text + report.text
    assert KEY not in accepted.text + completed.text + report.text
    assert "shuffle.invalid" not in report.text
    assert report.json()["verified_live"] is False
    assert client.get(f"/v1/incidents/{v.incident_id}", headers=auth).json()["status"] == "RECEIVED"
    assert (
        client.post(base + "/start", json=body | {"actor_id": "forged"}, headers=auth).status_code
        == 422
    )
