"""HTTP authentication, server identity, rate and callback envelope expectations."""

import json
import stat
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from responseforge.__main__ import load_settings, write_initial_config
from responseforge.api import create_app
from responseforge.runtime import Settings
from tests.rf02.helpers import ENDPOINT, TOKENS, alert, prepared, world


def auth(role: str, **extra: str) -> dict[str, str]:
    return {"Authorization": "Bearer " + TOKENS[role]} | extra


def test_missing_wrong_and_wrong_role_credentials_are_rejected(tmp_path: Path) -> None:
    w = world(tmp_path / "auth.sqlite")
    client = TestClient(create_app(w.settings, clock=w.clock))
    payload = alert().model_dump(mode="json")
    for headers in (
        {},
        {"Authorization": "Bearer secret-wrong-token"},
        {"Authorization": "Basic " + TOKENS["source"]},
    ):
        result = client.post("/v1/alerts", json=payload, headers=headers)
        assert result.status_code == 401
        assert "secret-wrong-token" not in result.text
    assert client.post("/v1/alerts", json=payload, headers=auth("analyst")).status_code == 403
    assert client.get("/v1/incidents", headers=auth("source")).status_code == 403
    assert client.get("/v1/incidents", headers=auth("analyst")).json() == []
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_authenticated_intake_duplicate_and_restart_remain_stable(tmp_path: Path) -> None:
    w = world(tmp_path / "api-intake.sqlite")
    client = TestClient(create_app(w.settings, clock=w.clock))
    payload = alert().model_dump(mode="json")
    first = client.post("/v1/alerts", json=payload, headers=auth("source"))
    assert first.status_code == 201
    assert first.json()["duplicate"] is False
    restarted = TestClient(create_app(w.settings, clock=w.clock))
    repeated = restarted.post("/v1/alerts", json=payload, headers=auth("source"))
    assert repeated.status_code == 200
    assert repeated.json()["duplicate"] is True
    assert repeated.json()["incident_id"] == first.json()["incident_id"]
    assert repeated.json()["correlation_id"] == first.json()["correlation_id"]
    case_id = first.json()["incident_id"]
    metrics = restarted.get(f"/v1/incidents/{case_id}/metrics", headers=auth("analyst")).json()
    assert len(metrics) == 1 and metrics[0]["kind"] == "alert_accepted"
    assert metrics[0]["occurred_at"] != payload["ingested_at"]


def test_invalid_schema_and_client_approver_identity_are_not_echoed(tmp_path: Path) -> None:
    w = world(tmp_path / "schema.sqlite")
    proposal = prepared(w)
    client = TestClient(create_app(w.settings, clock=w.clock))
    result = client.post(
        "/v1/alerts",
        json=alert().model_dump(mode="json")
        | {
            "command": "SECRET-UNTRUSTED-COMMAND",
            "approved": True,
        },
        headers=auth("source"),
    )
    assert result.status_code == 422
    assert "SECRET" not in result.text and "command" not in result.text
    approval = client.post(
        f"/v1/actions/{proposal.proposal_id}/approve",
        json={
            "expires_at": (w.clock() + timedelta(minutes=10)).isoformat(),
            "approver_id": "forged-human",
            "approved": True,
        },
        headers=auth("approver"),
    )
    assert approval.status_code == 422
    assert "forged-human" not in approval.text
    assert w.service.action(proposal.proposal_id, w.actors["analyst"]).approval is None
    accepted = client.post(
        f"/v1/actions/{proposal.proposal_id}/approve",
        json={
            "expires_at": (w.clock() + timedelta(minutes=10)).isoformat(),
        },
        headers=auth("approver"),
    )
    assert accepted.status_code == 200
    assert accepted.json()["approver_id"] == w.actors["approver"].actor_id
    assert accepted.json()["proposal"] == proposal.model_dump(mode="json")


def test_rate_limit_counts_persist_on_restart_and_allow_next_minute(tmp_path: Path) -> None:
    w = world(tmp_path / "api-rate.sqlite")
    client = TestClient(create_app(w.settings, clock=w.clock))
    for _ in range(60):
        assert client.get("/v1/incidents", headers=auth("analyst")).status_code == 200
    restarted = TestClient(create_app(w.settings, clock=w.clock))
    assert restarted.get("/v1/incidents", headers=auth("analyst")).status_code == 429
    assert restarted.get("/v1/incidents", headers=auth("source")).status_code == 403
    w.clock.advance(minutes=1)
    assert restarted.get("/v1/incidents", headers=auth("analyst")).status_code == 200


def test_callback_requires_auth_valid_time_nonce_and_exact_correlation(tmp_path: Path) -> None:
    w = world(tmp_path / "api-callback.sqlite")
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(
        intake.incident_id, "run-1", "workflow-1", "v1", w.actors["analyst"]
    )
    body = {
        "run_id": "run-1",
        "incident_id": intake.incident_id,
        "workflow_id": "workflow-1",
        "correlation_id": intake.correlation_id,
        "status": "succeeded",
    }
    client = TestClient(create_app(w.settings, clock=w.clock))
    url = "/v1/integrations/shuffle/callback"
    assert client.post(url, json=body).status_code == 401
    assert client.post(url, json=body, headers=auth("workflow")).status_code == 422
    for header in (
        {"X-Request-Timestamp": "SECRET-invalid-time", "X-Request-Nonce": "fresh"},
        {
            "X-Request-Timestamp": w.clock().replace(tzinfo=None).isoformat(),
            "X-Request-Nonce": "fresh",
        },
    ):
        result = client.post(url, json=body, headers=auth("workflow", **header))
        assert result.status_code == 422 and "SECRET" not in result.text
    headers = auth(
        "workflow",
        **{"X-Request-Timestamp": w.clock().isoformat(), "X-Request-Nonce": "api-unique-nonce"},
    )
    forged = client.post(url, json=body | {"correlation_id": "forged"}, headers=headers)
    assert forged.status_code in {403, 409}
    accepted = client.post(url, json=body, headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "succeeded"
    restarted = TestClient(create_app(w.settings, clock=w.clock))
    assert restarted.post(url, json=body, headers=headers).status_code == 409
    assert w.service.get_incident(intake.incident_id, w.actors["analyst"]).status == "RECEIVED"


def test_openapi_documents_bearer_without_exposing_config(tmp_path: Path) -> None:
    w = world(tmp_path / "api-schema.sqlite")
    schema = create_app(w.settings, clock=w.clock).openapi()
    assert "securitySchemes" in schema["components"]
    for path, methods in schema["paths"].items():
        if path.startswith("/v1/"):
            assert all(operation.get("security") for operation in methods.values())
    encoded = json.dumps(schema)
    assert all(token not in encoded for token in TOKENS.values())
    assert "SECRET" not in encoded


def test_config_generator_is_private_exclusive_and_has_separate_identities(tmp_path: Path) -> None:
    path = tmp_path / "private-config.json"
    write_initial_config(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        write_initial_config(path)
    assert path.read_bytes() == original
    settings = load_settings(path)
    assert (
        len(settings.credentials) == len({p.actor_id for p in settings.credentials.values()}) == 5
    )
    assert all(len(token) >= 32 for token in settings.credentials)
    assert all(token not in repr(settings) for token in settings.credentials)
    assert settings.providers == {} and not settings.live_dispatch_enabled


def test_settings_reject_short_tokens_duplicate_actors_and_conflicting_endpoints(
    tmp_path: Path,
) -> None:
    w = world(tmp_path / "settings.sqlite")
    with pytest.raises(ValueError):
        replace(w.settings, credentials={"short": w.actors["analyst"]})
    with pytest.raises(ValueError):
        replace(
            w.settings, credentials={"a" * 40: w.actors["analyst"], "b" * 40: w.actors["analyst"]}
        )
    with pytest.raises(ValueError):
        replace(
            w.settings, endpoints=(ENDPOINT, ENDPOINT.model_copy(update={"hostname": "changed"}))
        )
    with pytest.raises(ValueError):
        Settings(database_path=tmp_path / "bad.sqlite", provider_timeout=float("nan"))


def test_authenticated_http_case_approval_dispatch_and_restart_duplicate_are_one_effect(
    tmp_path: Path,
) -> None:
    """Wire the full internal HTTP path; effects remain controlled synthetic state."""
    w = world(tmp_path / "http-complete.sqlite")
    client = TestClient(create_app(w.settings, clock=w.clock))
    intake = client.post("/v1/alerts", json=alert().model_dump(mode="json"), headers=auth("source"))
    assert intake.status_code == 201
    case_id = intake.json()["incident_id"]
    for state in ("TRIAGING", "INVESTIGATING"):
        transition = client.post(
            f"/v1/incidents/{case_id}/transition", json={"status": state}, headers=auth("analyst")
        )
        assert transition.status_code == 200
        assert transition.json()["status"] == state
    proposal_id = "http-proposal-1"
    proposal = {
        "proposal_id": proposal_id,
        "incident_id": case_id,
        "mode": "replay",
        "target": {"endpoint": ENDPOINT.model_dump(mode="json"), "resource": "process:42"},
        "action": "terminate_process",
        "rationale": "Synthetic HTTP route integration",
        "risk": "disruptive",
        "created_at": w.clock().isoformat(),
        "expires_at": (w.clock() + timedelta(minutes=30)).isoformat(),
        "idempotency_key": "http-effect-1",
    }
    proposed = client.post(
        f"/v1/incidents/{case_id}/actions/propose", json=proposal, headers=auth("analyst")
    )
    assert proposed.status_code == 200
    expiry = {"expires_at": (w.clock() + timedelta(minutes=20)).isoformat()}
    denied = client.post(
        f"/v1/actions/{proposal_id}/approve", json=expiry, headers=auth("executor")
    )
    assert denied.status_code == 403
    assert w.provider.execute_calls == w.provider.effect_count == 0
    approved = client.post(
        f"/v1/actions/{proposal_id}/approve", json=expiry, headers=auth("approver")
    )
    assert approved.status_code == 200
    assert approved.json()["approver_id"] == w.actors["approver"].actor_id
    assert approved.json()["approver_id"] != w.actors["executor"].actor_id
    executed = client.post(
        f"/v1/actions/{proposal_id}/execute",
        json={"provider": "controlled"},
        headers=auth("executor"),
    )
    assert executed.status_code == 200
    assert executed.json()["verification"]["status"] == "verified"
    assert executed.json()["verification"]["simulated"] is True
    assert executed.json()["verification"]["verified_live"] is False
    assert w.provider.execute_calls == w.provider.effect_count == w.provider.verify_calls == 1
    case = client.get(f"/v1/incidents/{case_id}", headers=auth("analyst"))
    assert case.status_code == 200 and case.json()["status"] == "RESOLVED"
    audit = client.get(f"/v1/incidents/{case_id}/audit", headers=auth("analyst")).json()
    assert any(
        event["operation"] == "dispatch_reserved"
        and event["actor"] == w.actors["executor"].actor_id
        for event in audit
    )
    w.clock.advance(hours=2)
    restarted = TestClient(create_app(w.settings, clock=w.clock))
    repeated = restarted.post(
        f"/v1/actions/{proposal_id}/execute",
        json={"provider": "controlled"},
        headers=auth("executor"),
    )
    assert repeated.status_code == 200
    assert repeated.json() == executed.json()
    assert w.provider.execute_calls == w.provider.effect_count == w.provider.verify_calls == 1
