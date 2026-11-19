"""Multi-source case lookup and atomic dispatch guards never choose a default."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from responseforge.__main__ import load_settings
from responseforge.contracts import CollectionRequest
from responseforge.core import CaseService, ServiceError
from responseforge.playbooks.service import PlaybookService
from responseforge.reports import build_report
from responseforge.storage import Store
from tests.rf05b.test_runtime import write_config
from tests.rf06b2.helpers import recorded_file_value
from tests.rf06b2.test_file_config import register_case


def setup_world(tmp_path):
    value, _, _, legacy = recorded_file_value(tmp_path)
    settings = load_settings(write_config(tmp_path, value))
    core = CaseService(Store(settings.database_path), settings)
    return core, settings, legacy


def source(settings, profile):
    return next(
        batch
        for batch in settings.replay_sources
        if batch.events[0].scenario_id
        == "rf06-" + profile + "-33333333-3333-4333-8333-333333333333"
    )


def test_each_case_keeps_its_recorded_or_legacy_source_provider_and_report(tmp_path):
    core, settings, legacy = setup_world(tmp_path)
    service = PlaybookService(core)
    cases = [
        (
            source(settings, "powershell"),
            "66666666-6666-4666-8666-666666666666",
            "propose",
            settings.recorded_playbook_provider,
            "explicit_subset",
        ),
        (
            source(settings, "powershell-negative"),
            "77777777-7777-4777-8777-777777777777",
            "no_action",
            settings.recorded_playbook_provider,
            "explicit_subset",
        ),
        (
            legacy.batch,
            "88888888-8888-4888-8888-888888888888",
            "propose",
            "mock-edr",
            "full_registered_source",
        ),
    ]
    references = []
    for batch, run_id, disposition, provider, selection in cases:
        incident_id, request, actors = register_case(core, settings, batch, run_id)
        plan = asyncio.run(service.prepare(incident_id, request, actors["workflow"]))
        assert plan.source_sha256 == batch.sha256
        assert plan.provider == provider and plan.assessment.disposition == disposition
        references.append(plan.evidence_refs)
        again = asyncio.run(
            PlaybookService(CaseService(Store(settings.database_path), settings)).prepare(
                incident_id, request, actors["workflow"]
            )
        )
        assert again == plan
        report = build_report(core, incident_id, actors["analyst"])
        assert report["source_selection"] == selection
        assert report["alert"]["provenance"]["sha256"] == batch.sha256
    assert len(set(references)) == 3


def test_historical_missing_source_is_unavailable_not_current_other_source(tmp_path, monkeypatch):
    core, settings, _ = setup_world(tmp_path)
    original = source(settings, "powershell")
    incident_id, request, actors = register_case(core, settings, original)
    plan = asyncio.run(PlaybookService(core).prepare(incident_id, request, actors["workflow"]))
    remaining = tuple(batch for batch in settings.replay_sources if batch != original)
    core.settings = replace(settings, replay_sources=remaining)
    calls = []

    async def forbidden(*args, **kwargs):
        calls.append("provider queried")
        pytest.fail("Missing historical source fell back to provider registry")

    monkeypatch.setattr(settings.evidence_provider, "collect", forbidden)
    event = original.events[0]
    collection = CollectionRequest(
        incident_id=incident_id,
        mode="replay",
        scenario_id=event.scenario_id,
        endpoint=event.endpoint,
        artifact="process",
        start=event.observed_at,
        end=event.observed_at + timedelta(seconds=1),
    )
    with pytest.raises(ServiceError):
        asyncio.run(core.collect(incident_id, collection, actors["analyst"]))
    assert not calls
    report = build_report(core, incident_id, actors["analyst"])
    assert report["source_selection"] == report["source_transformation"] == "unavailable"
    assert core.action(plan.proposal_id, actors["analyst"]).execution is None


@pytest.mark.parametrize("drift", ["source", "provider"])
def test_atomic_guard_rechecks_source_and_provider_after_capability_io(
    tmp_path, monkeypatch, drift
):
    core, settings, _ = setup_world(tmp_path)
    original = source(settings, "powershell")
    incident_id, request, actors = register_case(core, settings, original)
    service = PlaybookService(core)
    plan = asyncio.run(service.prepare(incident_id, request, actors["workflow"]))
    core.decide(
        plan.proposal_id, "approved", datetime.now(UTC) + timedelta(seconds=120), actors["approver"]
    )
    provider = settings.providers[settings.recorded_playbook_provider]
    original_capabilities = provider.capabilities
    calls = []

    async def changed(endpoint):
        capabilities = await original_capabilities(endpoint)
        calls.append("capabilities returned")
        if drift == "source":
            core.settings = replace(
                settings,
                replay_sources=tuple(
                    batch for batch in settings.replay_sources if batch != original
                ),
            )
        else:
            core.settings = replace(settings, recorded_playbook_provider="mock-edr")
        return capabilities

    monkeypatch.setattr(provider, "capabilities", changed)
    with pytest.raises(ServiceError) as captured:
        asyncio.run(service.dispatch(incident_id, request, actors["workflow"]))
    assert captured.value.status_code == 409 and calls
    assert provider.snapshot(original.events[0].endpoint)["effect_count"] == 0
    with core.store.transaction() as tx:
        assert not tx.list("executions")
