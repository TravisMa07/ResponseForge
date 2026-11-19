"""Workflow step authority is trusted server configuration, never JSON input."""

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from responseforge.api import create_app
from responseforge.runtime import Settings
from tests.rf02.helpers import TOKENS
from tests.rf04.helpers import OTHER_WF, WF
from tests.rf05.helpers import effects, world


def test_old_settings_defaults_keep_playbooks_disabled(tmp_path):
    settings = Settings(database_path=tmp_path / "core.sqlite")
    assert settings.playbook_bindings == {} and settings.playbook_actors == {}
    assert settings.playbook_provider is None


@pytest.mark.parametrize(
    "changes",
    [
        {"playbook_bindings": {}},
        {"playbook_bindings": {OTHER_WF: "process"}},
        {"playbook_bindings": {WF: "unknown"}},
        {"playbook_actors": {}},
        {"playbook_actors": {"analyst": "rf05-analyst"}},
        {"playbook_actors": {"analyst": "rf05-analyst", "executor": "unknown"}},
        {"playbook_actors": {"analyst": "rf05-approver", "executor": "rf05-executor"}},
        {"playbook_provider": "unknown-provider"},
        {"playbook_provider": None},
    ],
)
def test_partial_or_unreviewed_trust_configuration_rejects(tmp_path, changes):
    w = world(tmp_path)
    with pytest.raises(ValueError):
        replace(w.settings, **changes)


@pytest.mark.parametrize("role", ["analyst", "executor"])
@pytest.mark.parametrize(
    "changes",
    [
        {"human": True},
        {"roles": frozenset({"approver"})},
        {"roles": frozenset({"analyst", "executor"})},
        {"roles": frozenset({"workflow", "approver"})},
    ],
)
def test_technical_actor_cannot_be_human_approver_or_multi_role(tmp_path, role, changes):
    w = world(tmp_path)
    principal = w.actors[role]
    changed = replace(principal, **changes)
    credentials = {
        token: changed if actor.actor_id == principal.actor_id else actor
        for token, actor in w.settings.credentials.items()
    }
    with pytest.raises(ValueError):
        replace(w.settings, credentials=credentials)


def test_external_trust_mappings_are_copied_on_settings_construction(tmp_path):
    w = world(tmp_path)
    bindings, actors = dict(w.settings.playbook_bindings), dict(w.settings.playbook_actors)
    settings = replace(w.settings, playbook_bindings=bindings, playbook_actors=actors)
    bindings[WF] = "unreviewed"
    actors["executor"] = "rf05-approver"
    assert settings.playbook_bindings[WF] == "process"
    assert settings.playbook_actors["executor"] == "rf05-executor"


@pytest.mark.parametrize("step", ["prepare", "gate", "dispatch"])
@pytest.mark.parametrize(
    "injected",
    [
        {"action": "isolate_host"},
        {"provider": "mock-edr"},
        {"approved": True},
        {"target": {"endpoint": "foreign"}},
        {"command": "DO_NOT_RUN_PRIVATE_COMMAND"},
    ],
)
def test_unknown_authority_fields_are_schema_rejected_before_mutation(tmp_path, step, injected):
    w = world(tmp_path)
    client = TestClient(create_app(w.settings, clock=w.clock))
    response = client.post(
        "/v1/incidents/" + w.incident_id + "/playbooks/" + step,
        headers={"Authorization": "Bearer " + TOKENS["workflow"]},
        json=w.request.model_dump(mode="json") | injected,
    )
    assert response.status_code == 422
    assert "DO_NOT_RUN_PRIVATE_COMMAND" not in response.text
    with w.core.store.transaction() as tx:
        assert not tx.list("proposals") and not tx.list("evidence")
    assert effects(w) == 0


@pytest.mark.parametrize("step", ["prepare", "gate", "dispatch"])
@pytest.mark.parametrize("role", ["analyst", "approver", "source", "executor"])
def test_valid_non_workflow_credentials_cannot_invoke_steps(tmp_path, step, role):
    w = world(tmp_path)
    client = TestClient(create_app(w.settings, clock=w.clock))
    response = client.post(
        "/v1/incidents/" + w.incident_id + "/playbooks/" + step,
        headers={"Authorization": "Bearer " + TOKENS[role]},
        json=w.request.model_dump(mode="json"),
    )
    assert response.status_code == 403 and effects(w) == 0


def test_workflow_http_prepare_and_gate_do_not_grant_human_approval(tmp_path):
    w = world(tmp_path)
    client = TestClient(create_app(w.settings, clock=w.clock))
    headers = {"Authorization": "Bearer " + TOKENS["workflow"]}
    path = "/v1/incidents/" + w.incident_id + "/playbooks/"
    response = client.post(
        path + "prepare", headers=headers, json=w.request.model_dump(mode="json")
    )
    assert response.status_code == 200
    plan = response.json()
    response = client.post(path + "gate", headers=headers, json=w.request.model_dump(mode="json"))
    assert response.status_code == 200 and response.json()["status"] == "awaiting_approval"
    proposal = w.core.action(plan["proposal_id"], w.actors["analyst"]).proposal
    response = client.post(
        "/v1/actions/" + plan["proposal_id"] + "/approve",
        headers=headers,
        json={"expires_at": proposal.expires_at.isoformat()},
    )
    assert response.status_code == 403 and effects(w) == 0


def test_wrong_credential_and_wrong_case_path_do_not_reach_domain_work(tmp_path):
    w = world(tmp_path)
    client = TestClient(create_app(w.settings, clock=w.clock))
    response = client.post(
        "/v1/incidents/" + w.incident_id + "/playbooks/prepare",
        headers={"Authorization": "Bearer invalid"},
        json=w.request.model_dump(mode="json"),
    )
    assert response.status_code == 401
    response = client.post(
        "/v1/incidents/foreign-case/playbooks/prepare",
        headers={"Authorization": "Bearer " + TOKENS["workflow"]},
        json=w.request.model_dump(mode="json"),
    )
    assert response.status_code == 409 and effects(w) == 0
