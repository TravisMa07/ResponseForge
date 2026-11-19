"""Host qualification may inspect only the exact original native-created plan/proof."""

import asyncio
import json
import sqlite3
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

import responseforge.integrations.shuffle.recorded_qualification as module
from responseforge.playbooks.service import PlaybookService
from responseforge.recorded_contracts import RecordedConfig
from tests.rf06b2.test_file_config import register_case
from tests.rf06b2.test_source_authority import setup_world, source


@pytest.fixture
def proof_world(tmp_path):
    core, settings, _ = setup_world(tmp_path)
    batch = source(settings, "powershell")
    incident_id, request, actors = register_case(core, settings, batch)
    # Original synthetic core setup stands in for an already-created native plan.
    # These tests establish host proof checks only, never genuine Shuffle execution.
    plan = asyncio.run(PlaybookService(core).prepare(incident_id, request, actors["workflow"]))
    evidence = [
        value.model_dump(mode="json") for value in core.evidence(incident_id, actors["analyst"])
    ]
    config_value = json.loads((tmp_path / "private-config.json").read_text())["recorded"]
    lab = module.RecordedLab.__new__(module.RecordedLab)
    lab.core = object()
    lab.roles = {"workflow": "original-workflow-token", "analyst": "original-analyst-token"}
    lab.config = RecordedConfig.model_validate(config_value)
    lab.batches = {"powershell": batch}
    lab.alerts = {"powershell": core.snapshot(incident_id, actors["analyst"]).alert}
    item = {
        "kind": "process",
        "incident_id": incident_id,
        "run_id": request.run_id,
        "correlation_id": request.correlation_id,
        "workflow_id": request.workflow_id,
    }
    return SimpleNamespace(
        lab=lab,
        item=item,
        plan=plan,
        evidence=evidence,
        calls=[],
        core=core,
        actors=actors,
        request=request,
        settings=settings,
    )


def responses(monkeypatch, world, *, plan=None, evidence=None, inspect_failure=False):
    plan = world.plan.model_dump(mode="json") if plan is None else plan
    evidence = world.evidence if evidence is None else evidence

    async def controlled_request(client, method, path, **arguments):
        world.calls.append((method, path))
        if method == "POST":
            assert path.endswith("/playbooks/inspect"), "Host attempted mutating preparation"
            assert arguments["body"] == world.request.model_dump(mode="json")
            if inspect_failure:
                raise ValueError("Recorded core read failed")
            return deepcopy(plan)
        assert method == "GET" and path.endswith("/evidence")
        return deepcopy(evidence)

    monkeypatch.setattr(module, "_request", controlled_request)


def test_source_plan_accepts_exact_original_typed_plan_and_evidence_with_inspect_only(
    proof_world, monkeypatch
):
    world = proof_world
    responses(monkeypatch, world)
    result = asyncio.run(world.lab.source_plan("powershell", world.item))
    assert result == world.plan
    assert world.calls == [
        ("POST", "/v1/incidents/" + world.item["incident_id"] + "/playbooks/inspect"),
        ("GET", "/v1/incidents/" + world.item["incident_id"] + "/evidence"),
    ]


@pytest.mark.parametrize(
    "field", ["incident_id", "run_id", "correlation_id", "workflow_id", "mode"]
)
def test_source_plan_rejects_wrong_original_request_despite_same_source_proof(
    proof_world, monkeypatch, field
):
    world = proof_world
    plan = world.plan.model_dump(mode="json")
    plan["request"][field] = (
        "live"
        if field == "mode"
        else (
            "77777777-7777-4777-8777-777777777777"
            if field in {"run_id", "workflow_id"}
            else "unrelated-case-or-correlation"
        )
    )
    responses(monkeypatch, world, plan=plan)
    with pytest.raises(ValueError):
        asyncio.run(world.lab.source_plan("powershell", world.item))
    assert not any("prepare" in path for _, path in world.calls)


@pytest.mark.parametrize(
    "field,incorrect",
    [
        ("provider", "mock-edr"),
        ("provider_version", "99.0"),
        ("source_sha256", "f" * 64),
    ],
)
def test_source_plan_rejects_changed_provider_version_or_raw_hash(
    proof_world, monkeypatch, field, incorrect
):
    world = proof_world
    plan = world.plan.model_dump(mode="json")
    plan[field] = incorrect
    responses(monkeypatch, world, plan=plan)
    with pytest.raises(ValueError):
        asyncio.run(world.lab.source_plan("powershell", world.item))


def test_matching_forged_plan_and_evidence_reference_still_needs_derived_source_identity(
    proof_world, monkeypatch
):
    world = proof_world
    plan = world.plan.model_dump(mode="json")
    evidence = deepcopy(world.evidence)
    plan["evidence_refs"] = ["evidence-forged"]
    for value in evidence:
        if value["availability"] == "available":
            value["evidence_id"] = "evidence-forged"
    responses(monkeypatch, world, plan=plan, evidence=evidence)
    with pytest.raises(ValueError):
        asyncio.run(world.lab.source_plan("powershell", world.item))


@pytest.mark.parametrize(
    "change",
    ["incident", "endpoint", "agent", "mode", "classification", "chronology", "observed-time"],
)
def test_source_plan_rejects_evidence_scope_even_when_ref_proof_and_original_hash_match(
    proof_world, monkeypatch, change
):
    world = proof_world
    evidence = deepcopy(world.evidence)
    value = next(value for value in evidence if value["availability"] == "available")
    if change == "incident":
        value["incident_id"] = "unrelated-case"
    elif change == "endpoint":
        value["endpoint"]["hostname"] = "different-recorded-computer"
    elif change == "agent":
        value["endpoint"]["agent_id"] = "unrelated-agent"
    elif change == "mode":
        value["mode"] = "live"
    elif change == "classification":
        value["classification"] = "public"
    elif change == "chronology":
        value["collected_at"] = (world.plan.created_at + timedelta(seconds=1)).isoformat()
    else:
        value["observed_at"] = (
            world.lab.batches["powershell"].events[0].observed_at + timedelta(seconds=1)
        ).isoformat()
    responses(monkeypatch, world, evidence=evidence)
    with pytest.raises(ValueError):
        asyncio.run(world.lab.source_plan("powershell", world.item))


def test_missing_original_server_plan_cannot_trigger_host_prepare_recreation(
    proof_world, monkeypatch
):
    world = proof_world
    key = "playbook-plan:" + world.request.run_id
    with sqlite3.connect(world.settings.database_path) as connection:
        connection.execute("DELETE FROM documents WHERE collection=? AND key=?", ("callbacks", key))
    responses(monkeypatch, world, inspect_failure=True)
    with pytest.raises(ValueError):
        asyncio.run(world.lab.source_plan("powershell", world.item))
    assert world.calls == [
        ("POST", "/v1/incidents/" + world.item["incident_id"] + "/playbooks/inspect")
    ]
    with world.core.store.transaction() as transaction:
        assert transaction.get("callbacks", key) is None
        assert len(transaction.list("proposals")) == 1
