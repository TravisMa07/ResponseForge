"""I06/E03: new collection/report routes retain authentication and source scope."""

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from responseforge.api import create_app
from responseforge.contracts import ActionType, CollectionResult
from responseforge.investigation import ReplayEvidenceProvider
from responseforge.replay import load_replay, make_alerts
from responseforge.runtime import Principal, Settings
from tests.rf03.helpers import ENDPOINT, NOW, event, fixture


def app_world(tmp_path: Path, provider_type=ReplayEvidenceProvider):
    batch = load_replay(fixture(tmp_path / "api.jsonl", [event()]), source_id="api-original")
    credentials = {}
    tokens = {}
    for role in ("source", "analyst", "approver", "executor"):
        tokens[role] = ("original-api-" + role + "-").ljust(48, "x")
        credentials[tokens[role]] = Principal(
            actor_id=role,
            roles=frozenset({role}),
            endpoint_ids=frozenset({ENDPOINT.endpoint_id}),
            actions=frozenset({ActionType.TERMINATE_PROCESS}),
            resources=frozenset({"process:42"}),
            sources=frozenset({"replay-fixture"}),
            human=role == "approver",
        )
    settings = Settings(
        database_path=tmp_path / "api.sqlite",
        endpoints=(ENDPOINT,),
        credentials=credentials,
        resource_allowlist={ENDPOINT.endpoint_id: frozenset({"process:42"})},
        evidence_provider=provider_type(batch, clock=lambda: NOW),
        replay_batch=batch,
    )
    app = create_app(settings, clock=lambda: NOW)
    client = TestClient(app)
    headers = {role: {"Authorization": "Bearer " + token} for role, token in tokens.items()}
    result = client.post(
        "/v1/alerts",
        json=make_alerts(batch, ingested_at=NOW)[0].model_dump(mode="json"),
        headers=headers["source"],
    )
    assert result.status_code == 201
    return batch, client, headers, result.json()["incident_id"], settings


def collect_body(incident_id: str):
    return {
        "incident_id": incident_id,
        "mode": "replay",
        "scenario_id": "original-scenario",
        "endpoint": ENDPOINT.model_dump(mode="json"),
        "start": "2026-01-01T11:59:00Z",
        "end": "2026-01-01T12:01:00Z",
        "artifact": "process",
    }


def test_report_and_collection_are_authenticated_and_case_scoped(tmp_path: Path) -> None:
    batch, client, headers, case, settings = app_world(tmp_path)
    path = f"/v1/incidents/{case}/collect"
    assert client.post(path, json=collect_body(case)).status_code == 401
    assert client.get(f"/v1/incidents/{case}/report").status_code == 401
    assert client.post(path, json=collect_body(case), headers=headers["source"]).status_code == 403
    valid = client.post(path, json=collect_body(case), headers=headers["analyst"])
    assert valid.status_code == 200, valid.text
    assert valid.json()["evidence"][0]["provenance"]["sha256"] == batch.sha256
    for changes in (
        {"incident_id": "another-case"},
        {"scenario_id": "another-scenario"},
        {"mode": "live"},
    ):
        assert client.post(
            path, json=collect_body(case) | changes, headers=headers["analyst"]
        ).status_code in (403, 409, 422)
    report = client.get(f"/v1/incidents/{case}/report?format=json", headers=headers["analyst"])
    assert report.status_code == 200 and report.json()["simulated"] is True
    assert (
        client.get(
            f"/v1/incidents/{case}/report?format=html", headers=headers["analyst"]
        ).status_code
        == 200
    )
    assert client.get(
        f"/v1/incidents/{case}/report?format=xml", headers=headers["analyst"]
    ).status_code in (400, 422)
    outsider = replace(
        settings.credentials[next(iter(headers["analyst"].values())).split(" ", 1)[1]],
        endpoint_ids=frozenset(),
    )
    outsider_token = "outsider-credential-".ljust(48, "x")
    cfg = replace(settings, credentials={outsider_token: outsider})
    outsider_client = TestClient(create_app(cfg, clock=lambda: NOW))
    assert (
        outsider_client.get(
            f"/v1/incidents/{case}/report", headers={"Authorization": "Bearer " + outsider_token}
        ).status_code
        == 403
    )


@pytest.mark.parametrize("kind", ["hash", "time", "event", "case"])
def test_forged_provider_evidence_is_rejected_before_persistence(tmp_path: Path, kind: str) -> None:
    class Forged(ReplayEvidenceProvider):
        async def collect(self, request):
            result = await super().collect(request)
            value = result.evidence[0]
            if kind == "hash":
                value = value.model_copy(
                    update={"provenance": value.provenance.model_copy(update={"sha256": "b" * 64})}
                )
            elif kind == "event":
                value = value.model_copy(
                    update={
                        "provenance": value.provenance.model_copy(
                            update={"original_event_ids": ("fabricated",)}
                        )
                    }
                )
            elif kind == "time":
                value = value.model_copy(update={"observed_at": NOW})
            else:
                value = value.model_copy(update={"incident_id": "another-case"})
            return CollectionResult(evidence=(value,), gaps=())

    _, client, headers, case, _ = app_world(tmp_path, Forged)
    response = client.post(
        f"/v1/incidents/{case}/collect", json=collect_body(case), headers=headers["analyst"]
    )
    assert response.status_code in (403, 409, 422, 503)
    listed = client.get(f"/v1/incidents/{case}/evidence", headers=headers["analyst"])
    assert listed.status_code == 200 and listed.json() == []


@pytest.mark.parametrize("kind", ["identity", "hash", "reference", "rule", "event_time"])
def test_case_alert_must_bind_registered_replay_source_before_collection(
    tmp_path: Path, kind: str
) -> None:
    class Counting(ReplayEvidenceProvider):
        calls = 0

        async def collect(self, request):
            self.calls += 1
            return await super().collect(request)

    batch, client, headers, _, settings = app_world(tmp_path, Counting)
    other_alert = make_alerts(batch, ingested_at=NOW)[0].model_dump(mode="json")
    other_alert["alert_id"] = "unrelated-case-source-" + kind
    if kind == "hash":
        other_alert["provenance"]["sha256"] = "b" * 64
    elif kind == "reference":
        other_alert["provenance"]["source_ref"] = "fixture:another-source"
    elif kind == "rule":
        other_alert["rule_id"] = "ANOTHER-RULE"
    elif kind == "event_time":
        other_alert["event_time"] = "2025-01-01T00:00:00Z"
    intake = client.post("/v1/alerts", json=other_alert, headers=headers["source"])
    assert intake.status_code == 201
    unrelated_case = intake.json()["incident_id"]
    response = client.post(
        f"/v1/incidents/{unrelated_case}/collect",
        json=collect_body(unrelated_case),
        headers=headers["analyst"],
    )
    assert response.status_code in (403, 409, 422)
    assert settings.evidence_provider.calls == 0
    listed = client.get(f"/v1/incidents/{unrelated_case}/evidence", headers=headers["analyst"])
    assert listed.json() == []


def test_registered_source_binding_allows_explicit_logical_receipt_variant(tmp_path: Path) -> None:
    from datetime import timedelta

    batch, _, headers, _, settings = app_world(tmp_path)
    alternate = replace(settings, database_path=tmp_path / "alternate-receipt.sqlite")
    client = TestClient(create_app(alternate, clock=lambda: NOW))
    original = make_alerts(batch, ingested_at=NOW + timedelta(hours=1))[0]
    intake = client.post(
        "/v1/alerts", json=original.model_dump(mode="json"), headers=headers["source"]
    )
    assert intake.status_code == 201
    case = intake.json()["incident_id"]
    assert (
        client.post(
            f"/v1/incidents/{case}/collect", json=collect_body(case), headers=headers["analyst"]
        ).status_code
        == 200
    )
