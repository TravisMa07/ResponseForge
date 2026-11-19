"""Read-only host inspection cannot create missing native preparation proof."""

import asyncio
import sqlite3

import pytest
from fastapi.testclient import TestClient

from responseforge.api import create_app
from tests.rf02.helpers import TOKENS
from tests.rf05.helpers import effects, world


def test_workflow_inspection_reads_original_plan_without_repreparing(tmp_path):
    w = world(tmp_path)
    original = asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    client = TestClient(create_app(w.settings, clock=w.clock))
    response = client.post(
        "/v1/incidents/" + w.incident_id + "/playbooks/inspect",
        headers={"Authorization": "Bearer " + TOKENS["workflow"]},
        json=w.request.model_dump(mode="json"),
    )
    assert response.status_code == 200
    assert response.json() == original.model_dump(mode="json")
    assert (
        len(
            [
                event
                for event in w.core.metrics(w.incident_id, w.actors["analyst"])
                if event.kind == "case_ready"
            ]
        )
        == 1
    )
    assert effects(w) == 0


def test_missing_original_plan_stays_missing_despite_prior_native_audit(tmp_path):
    w = world(tmp_path)
    original = asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    key = "playbook-plan:" + w.request.run_id
    with sqlite3.connect(w.settings.database_path) as connection:
        connection.execute("DELETE FROM documents WHERE collection=? AND key=?", ("callbacks", key))
    client = TestClient(create_app(w.settings, clock=w.clock))
    response = client.post(
        "/v1/incidents/" + w.incident_id + "/playbooks/inspect",
        headers={"Authorization": "Bearer " + TOKENS["workflow"]},
        json=w.request.model_dump(mode="json"),
    )
    assert response.status_code == 409
    with w.core.store.transaction() as tx:
        assert tx.get("callbacks", key) is None
        assert len(tx.list("proposals")) == 1
    assert (
        w.core.action(original.proposal_id, w.actors["analyst"]).proposal.proposal_id
        == original.proposal_id
    )
    assert (
        len(
            [
                event
                for event in w.core.metrics(w.incident_id, w.actors["analyst"])
                if event.kind == "case_ready"
            ]
        )
        == 1
    )
    assert effects(w) == 0


@pytest.mark.parametrize("role", ["source", "analyst", "executor", "approver"])
def test_other_roles_cannot_inspect_workflow_plan(tmp_path, role):
    w = world(tmp_path)
    client = TestClient(create_app(w.settings, clock=w.clock))
    response = client.post(
        "/v1/incidents/" + w.incident_id + "/playbooks/inspect",
        headers={"Authorization": "Bearer " + TOKENS[role]},
        json=w.request.model_dump(mode="json"),
    )
    assert response.status_code == 403
    with w.core.store.transaction() as tx:
        assert not tx.list("proposals") and not tx.list("evidence")
    assert effects(w) == 0
