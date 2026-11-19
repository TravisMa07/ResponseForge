"""Registry source authority is exact and independent of source ordering."""

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest

from responseforge.contracts import CollectionRequest, Incident
from responseforge.replay import ReplayError, load_replay, make_alerts
from responseforge.replay.registry import ReplayRegistry
from tests.rf06b.helpers import NOW
from tests.rf06b2.helpers import memory_source


def request(source, **changes):
    event = source.events[0]
    return CollectionRequest.model_validate(
        {
            "incident_id": "original-case",
            "mode": "replay",
            "scenario_id": event.scenario_id,
            "endpoint": event.endpoint,
            "start": event.observed_at,
            "end": event.observed_at + timedelta(seconds=1),
            "artifact": "process",
        }
        | changes
    )


def incident(source, **changes):
    alert = make_alerts(source, ingested_at=NOW + timedelta(days=1))[0]
    return Incident.model_validate(
        {
            "incident_id": "original-case",
            "alert_id": alert.alert_id,
            "mode": "replay",
            "scenario_id": alert.scenario_id,
            "endpoint": alert.endpoint,
            "priority": alert.severity,
            "assessment": "original test case",
            "created_at": alert.ingested_at,
        }
        | changes
    )


def test_two_sources_route_original_proof_without_order_dependency():
    a = memory_source()
    b = memory_source(scenario="source-b", artifact_id="source-b", computer="other.example")
    for sources in ((a, b), (b, a)):
        registry = ReplayRegistry(sources, clock=lambda: NOW + timedelta(days=1))
        for source in sources:
            alert = make_alerts(source, ingested_at=NOW + timedelta(days=1))[0]
            assert registry.resolve(alert) == source
            result = asyncio.run(registry.collect(request(source)))
            assert len(result.evidence) == 1
            assert result.evidence[0].provenance.sha256 == source.sha256
            assert result.evidence[0].provenance.original_event_ids == ("31",)
            assert result.evidence[0].endpoint == source.events[0].endpoint
            assert result.evidence[0].collected_at == NOW + timedelta(days=1)
            listed = asyncio.run(registry.list_evidence(incident(source)))
            assert len(listed) == 1 and listed[0].provenance == result.evidence[0].provenance


def test_same_source_selection_can_repeat_under_distinct_operator_scenarios():
    a = memory_source()
    b = memory_source(scenario="case-variant")
    assert a.source_id == b.source_id and a.sha256 == b.sha256
    registry = ReplayRegistry((a, b))
    assert registry.resolve(make_alerts(a, ingested_at=NOW)[0]) == a
    assert registry.resolve(make_alerts(b, ingested_at=NOW)[0]) == b


@pytest.mark.parametrize("change", ["hash", "origin", "content"])
def test_conflicting_source_identity_never_selects_first(change):
    a = memory_source()
    b = memory_source(scenario="variant")
    if change == "hash":
        b = b.model_copy(update={"sha256": "b" * 64})
    elif change == "origin":
        b = b.model_copy(
            update={
                "origin": b.origin.model_copy(
                    update={
                        "source_ref": b.origin.source_ref.replace(
                            "datasets/original/", "datasets/changed/"
                        )
                    }
                )
            }
        )
    else:
        changed = b.events[0].model_copy(
            update={"fields": b.events[0].fields | {"image": "different.exe"}}
        )
        b = b.model_copy(update={"events": (changed,)})
    with pytest.raises(ReplayError):
        ReplayRegistry((a, b))


def test_ambiguous_same_full_scenario_endpoint_rejects_before_collection():
    a = memory_source()
    b = memory_source(artifact_id="different-source", fields={"Image": "cmd.exe"})
    with pytest.raises(ReplayError):
        ReplayRegistry((a, b))
    with pytest.raises(ReplayError):
        ReplayRegistry((a, a))


@pytest.mark.parametrize(
    "changes",
    [
        {"alert_id": "forged"},
        {"source": "forged"},
        {"rule_id": "forged"},
        {"severity": "low"},
        {"scenario_id": "other"},
        {"mode": "live"},
        {"event_time": "2030-01-01T00:00:00Z"},
    ],
)
def test_resolve_requires_exact_original_alert(changes):
    source = memory_source()
    alert = make_alerts(source, ingested_at=NOW)[0].model_copy(update=changes)
    with pytest.raises(ReplayError):
        ReplayRegistry((source,)).resolve(alert)


def test_raw_provenance_and_full_endpoint_are_bound():
    source = memory_source()
    original = make_alerts(source, ingested_at=NOW)[0]
    for change in (
        {"endpoint": original.endpoint.model_copy(update={"hostname": "forged"})},
        {"endpoint": original.endpoint.model_copy(update={"agent_id": "forged"})},
        {"provenance": original.provenance.model_copy(update={"sha256": "f" * 64})},
        {"provenance": original.provenance.model_copy(update={"original_event_ids": ("999",)})},
    ):
        with pytest.raises(ReplayError):
            ReplayRegistry((source,)).resolve(original.model_copy(update=change))


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "live"},
        {"scenario_id": "missing"},
        {"endpoint": {"endpoint_id": "missing", "hostname": "missing"}},
    ],
)
def test_collection_unknown_or_live_scope_never_falls_back(changes):
    source = memory_source()
    with pytest.raises(ReplayError):
        asyncio.run(ReplayRegistry((source,)).collect(request(source, **changes)))


def test_known_scope_missing_artifact_is_explicit_gap():
    source = memory_source()
    result = asyncio.run(ReplayRegistry((source,)).collect(request(source, artifact="network")))
    assert result.gaps and len(result.evidence) == 1
    assert result.evidence[0].availability == "unavailable"
    assert result.evidence[0].provenance is None


def test_list_evidence_binds_original_alert_and_full_scope():
    source = memory_source()
    registry = ReplayRegistry((source,))
    for change in ({"alert_id": "forged"}, {"scenario_id": "other"}, {"mode": "live"}):
        with pytest.raises(ReplayError):
            asyncio.run(registry.list_evidence(incident(source, **change)))


def test_source_and_returned_snapshot_mutations_cannot_change_registry():
    source = memory_source()
    original = make_alerts(source, ingested_at=NOW)[0]
    registry = ReplayRegistry((source,))
    source.events[0].fields["image"] = "mutated.exe"
    resolved = registry.resolve(original)
    assert resolved.events[0].fields["image"] == "powershell.exe"
    resolved.events[0].fields["image"] = "second-mutation.exe"
    assert registry.resolve(original).events[0].fields["image"] == "powershell.exe"


def test_legacy_original_fixture_can_coexist_without_source_relabeling():
    legacy = load_replay(Path("datasets/fixtures/benign.jsonl"), source_id="legacy-original")
    recorded = memory_source()
    registry = ReplayRegistry((legacy, recorded))
    alert = make_alerts(legacy, ingested_at=NOW)[0]
    assert registry.resolve(alert) == legacy
    assert alert.provenance.source == "synthetic-fixture"


def test_registry_bounds_are_not_silent_truncation():
    with pytest.raises(ReplayError):
        ReplayRegistry(())
    sources = tuple(
        memory_source(scenario=f"case-{index}", artifact_id=f"source-{index}")
        for index in range(34)
    )
    with pytest.raises(ReplayError):
        ReplayRegistry(sources)
    registry = ReplayRegistry(sources[:33])
    assert registry.resolve(make_alerts(sources[32], ingested_at=NOW)[0]) == sources[32]
