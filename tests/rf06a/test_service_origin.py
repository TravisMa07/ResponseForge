"""Recorded-origin cached plans retain source proof without synthetic labels."""

import asyncio

import pytest

from responseforge.core import ServiceError
from responseforge.replay import make_alerts
from responseforge.replay_contracts import ReplayOrigin
from tests.rf05 import helpers
from tests.rf06a.helpers import artifact, event


def recorded_world(tmp_path, monkeypatch):
    original_source = helpers.source
    original_principal = helpers.Principal
    source_ref = artifact(event().encode()).source_url

    def recorded_source(path, records=None):
        batch, _ = original_source(path, records)
        batch = batch.model_copy(update={"origin": ReplayOrigin(source_ref=source_ref)})
        alert = make_alerts(batch, ingested_at=helpers.NOW)[0]
        return batch, alert

    def principal(**values):
        if "source" in values["roles"]:
            values["sources"] = frozenset({"splunk-attack-data"})
        return original_principal(**values)

    monkeypatch.setattr(helpers, "source", recorded_source)
    monkeypatch.setattr(helpers, "Principal", principal)
    return helpers.world(tmp_path), source_ref


def test_recorded_origin_preparation_reuses_cached_plan_and_evidence(tmp_path, monkeypatch):
    w, source_ref = recorded_world(tmp_path, monkeypatch)
    first = asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert first.proposal_id and first.evidence_refs
    second = asyncio.run(
        helpers.reopened(w).prepare(w.incident_id, w.request, w.actors["workflow"])
    )
    assert second == first
    evidence = w.core.evidence(w.incident_id, w.actors["analyst"])
    assert evidence
    unavailable = [value for value in evidence if value.availability == "unavailable"]
    assert unavailable and all(value.provenance is None for value in unavailable)
    evidence = [value for value in evidence if value.availability == "available"]
    assert evidence
    assert all(value.provenance.source == "splunk-attack-data" for value in evidence)
    assert all(value.provenance.source_ref == source_ref for value in evidence)
    assert all(value.provenance.sha256 == w.batch.sha256 for value in evidence)
    assert helpers.effects(w) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "synthetic-fixture"),
        ("source_ref", "fixture:forged"),
        ("sha256", "f" * 64),
    ],
)
def test_recorded_origin_corrupted_evidence_still_rejects(tmp_path, monkeypatch, field, value):
    w, _ = recorded_world(tmp_path, monkeypatch)
    provider = w.settings.evidence_provider
    original = provider.collect

    async def corrupted(request):
        result = await original(request)
        evidence = tuple(
            item.model_copy(
                update={"provenance": item.provenance.model_copy(update={field: value})}
            )
            if item.availability == "available"
            else item
            for item in result.evidence
        )
        return result.model_copy(update={"evidence": evidence})

    monkeypatch.setattr(provider, "collect", corrupted)
    with pytest.raises(ServiceError) as captured:
        asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert captured.value.status_code == 409
    assert helpers.effects(w) == 0
