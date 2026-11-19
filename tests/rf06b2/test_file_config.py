"""Recorded configuration retains legacy receipt authority and seeds only source facts."""

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta

import pytest

from responseforge.__main__ import load_settings
from responseforge.contracts import ActionType
from responseforge.core import CaseService, ServiceError
from responseforge.integrations.shuffle.models import DeliveryRecord, ShuffleArgument
from responseforge.playbooks.models import PlaybookStepRequest
from responseforge.playbooks.service import PlaybookService
from responseforge.replay import make_alerts
from responseforge.storage import Store
from tests.rf04.helpers import WF
from tests.rf05b.test_runtime import write_config
from tests.rf06b2.helpers import recorded_file_value


def test_recorded_provider_namespace_changes_with_qualification_and_database(tmp_path):
    value, _, _, _ = recorded_file_value(tmp_path)
    first = load_settings(write_config(tmp_path, value))
    changed = json.loads(json.dumps(value))
    changed["recorded"]["qualification_id"] = "44444444-4444-4444-8444-444444444444"
    changed["recorded"]["mock_path"] = str(tmp_path / "another-recorded.sqlite3")
    second = load_settings(write_config(tmp_path, changed))
    assert first.recorded_playbook_provider != second.recorded_playbook_provider
    assert first.recorded_playbook_provider not in second.providers
    assert second.recorded_playbook_provider not in first.providers
    assert first.playbook_provider == second.playbook_provider == "mock-edr"


def register_case(core, settings, batch, run_id="66666666-6666-4666-8666-666666666666"):
    actors = {
        next(iter(actor.roles)): actor
        for actor in settings.credentials.values()
        if len(actor.roles) == 1
    }
    alert = make_alerts(batch, ingested_at=datetime.now(UTC))[0]
    intake = core.intake(alert, actors["source"])
    binding = settings.shuffle_bindings[WF]
    core.register_workflow(intake.incident_id, run_id, WF, binding.version, actors["analyst"])
    argument = ShuffleArgument(
        incident_id=intake.incident_id,
        run_id=run_id,
        correlation_id=intake.correlation_id,
        mode="replay",
    )
    now = datetime.now(UTC)
    delivery = DeliveryRecord(
        argument=argument,
        workflow_id=WF,
        workflow_version=binding.version,
        workflow_sha256=binding.sha256,
        origin=settings.shuffle_config.base_url,
        state="accepted",
        created_at=now,
        updated_at=now,
    )
    with core.store.transaction() as tx:
        tx.insert("callbacks", "shuffle:" + run_id, delivery.model_dump(mode="json"))
    request = PlaybookStepRequest(**argument.model_dump(mode="json"), workflow_id=WF)
    return intake.incident_id, request, actors


def test_file_loading_seeds_union_of_actual_process_creation_only(tmp_path):
    value, config, sources, legacy = recorded_file_value(tmp_path)
    settings = load_settings(write_config(tmp_path, value))
    name = settings.recorded_playbook_provider
    assert re.fullmatch(r"recorded-mock-edr-[0-9a-f]{24}", name)
    assert config.qualification_id not in name and config.mock_path not in name
    provider = settings.providers[name]
    assert settings.provider_versions[name] == "1.0"
    endpoints = {
        source.events[0].endpoint.hostname: source.events[0].endpoint for source in sources
    }
    expected = {"powershell": ["42", "43"], "lsass": [], "task": [], "note": ["43"], "dns": []}
    for family, processes in expected.items():
        endpoint = endpoints["recorded-" + family + ".example"]
        assert provider.snapshot(endpoint)["running_processes"] == processes
        capabilities = asyncio.run(provider.capabilities(endpoint))
        assert capabilities and all(
            item.provider == name and item.provider_version == "1.0" for item in capabilities
        )
        assert ActionType.DISABLE_PERSISTENCE not in {item.action for item in capabilities}
    assert settings.providers["mock-edr"].snapshot(legacy.settings.endpoints[0])[
        "running_processes"
    ] == ["42"]
    reloaded = load_settings(write_config(tmp_path, value))
    assert reloaded.recorded_playbook_provider == name
    assert len(reloaded.replay_sources) == 14


@pytest.mark.parametrize(
    "change",
    ["live", "missing-legacy", "case-db", "legacy-db", "inside-bundle", "unknown-endpoint"],
)
def test_invalid_recorded_file_config_cannot_silently_fall_back(tmp_path, change):
    value, _, _, _ = recorded_file_value(tmp_path)
    if change == "live":
        value["mode"] = "live"
    elif change == "missing-legacy":
        value.pop("playbooks")
    elif change == "case-db":
        value["recorded"]["mock_path"] = value["database_path"]
    elif change == "legacy-db":
        value["recorded"]["mock_path"] = value["playbooks"]["mock_path"]
    elif change == "inside-bundle":
        value["recorded"]["mock_path"] = value["recorded"]["bundle_root"] + "/state.sqlite3"
    else:
        value["endpoints"] = [
            item for item in value["endpoints"] if item["endpoint_id"] == "rf05-host"
        ]
    with pytest.raises(ValueError):
        load_settings(write_config(tmp_path, value))


def test_changed_seed_same_namespace_refuses_instead_of_resetting(tmp_path):
    value, _, sources, _ = recorded_file_value(tmp_path)
    first = load_settings(write_config(tmp_path, value))
    provider = first.providers[first.recorded_playbook_provider]
    endpoint = next(
        source.events[0].endpoint
        for source in sources
        if source.events[0].endpoint.hostname == "recorded-powershell.example"
    )
    assert provider.snapshot(endpoint)["running_processes"] == ["42", "43"]
    changed = json.loads(json.dumps(value))
    changed["recorded"]["cases"] = [
        case for case in changed["recorded"]["cases"] if case["profile"] != "powershell-negative"
    ]
    with pytest.raises(ValueError):
        load_settings(write_config(tmp_path, changed))
    assert provider.snapshot(endpoint)["running_processes"] == ["42", "43"]
    load_settings(write_config(tmp_path, value))


def test_old_uncertain_execution_cannot_query_new_qualification_database(tmp_path, monkeypatch):
    value, _, _, _ = recorded_file_value(tmp_path)
    first = load_settings(write_config(tmp_path, value))
    original_provider_name = first.recorded_playbook_provider
    original_provider = first.providers[original_provider_name]
    original_provider.fault = "error_after_effect"
    source = next(
        batch
        for batch in first.replay_sources
        if batch.events[0].scenario_id.startswith("rf06-powershell-")
    )
    core = CaseService(Store(first.database_path), first)
    incident_id, request, actors = register_case(core, first, source)
    service = PlaybookService(core)
    plan = asyncio.run(service.prepare(incident_id, request, actors["workflow"]))
    assert plan.provider == original_provider_name and plan.proposal_id
    core.decide(
        plan.proposal_id, "approved", datetime.now(UTC) + timedelta(seconds=120), actors["approver"]
    )
    uncertain = asyncio.run(service.dispatch(incident_id, request, actors["workflow"]))
    assert uncertain.execution.dispatch_state == "uncertain"
    assert original_provider.snapshot(source.events[0].endpoint)["effect_count"] == 1
    changed = json.loads(json.dumps(value))
    changed["recorded"]["qualification_id"] = "44444444-4444-4444-8444-444444444444"
    changed["recorded"]["mock_path"] = str(tmp_path / "new-recorded.sqlite3")
    second = load_settings(write_config(tmp_path, changed))
    new_provider = second.providers[second.recorded_playbook_provider]
    calls = []

    async def forbidden(*args, **kwargs):
        calls.append("new database queried")
        pytest.fail("Old receipt was routed to new recorded DB")

    monkeypatch.setattr(new_provider, "verify", forbidden)
    monkeypatch.setattr(new_provider, "execute", forbidden)
    restored = CaseService(Store(second.database_path), second)
    current_actor = next(
        actor for actor in second.credentials.values() if actor.roles == {"executor"}
    )
    with pytest.raises(ServiceError) as captured:
        asyncio.run(restored.reconcile(plan.proposal_id, original_provider_name, current_actor))
    assert captured.value.status_code in {409, 503}
    assert not calls and new_provider.snapshot(source.events[0].endpoint)["effect_count"] == 0
    assert original_provider.snapshot(source.events[0].endpoint)["effect_count"] == 1
