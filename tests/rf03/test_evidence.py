"""E01-E03: scoped source facts, explicit absence, detached provider snapshot."""

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest

from responseforge.contracts import CollectionRequest, Incident
from responseforge.investigation import ReplayEvidenceProvider
from responseforge.replay import load_replay, make_alerts
from tests.rf03.helpers import ENDPOINT, NOW, event, fixture


def request(**changes):
    return CollectionRequest.model_validate(
        {
            "incident_id": "case-1",
            "mode": "replay",
            "scenario_id": "original-scenario",
            "endpoint": ENDPOINT,
            "start": "2026-01-01T12:00:00Z",
            "end": "2026-01-01T12:00:10Z",
            "artifact": "process",
        }
        | changes
    )


def test_collection_boundaries_provenance_and_artifact_scope(tmp_path: Path) -> None:
    batch = load_replay(
        fixture(
            tmp_path / "scoped.jsonl",
            [
                event("at-start"),
                event("at-end", observed_at="2026-01-01T12:00:10Z"),
                event("too-late", observed_at="2026-01-01T12:00:11Z"),
                event("other-scenario", scenario_id="other"),
                event("network", artifact="network"),
            ],
        ),
        source_id="original",
    )
    provider = ReplayEvidenceProvider(batch, clock=lambda: NOW)
    result = asyncio.run(provider.collect(request()))
    assert [item.provenance.original_event_ids for item in result.evidence] == [
        ("at-start",),
        ("at-end",),
    ]
    assert all(item.provenance.sha256 == batch.sha256 for item in result.evidence)
    assert all(item.collected_at == NOW and item.mode == "replay" for item in result.evidence)
    assert all(item.availability == "available" for item in result.evidence)
    assert result.gaps == ()
    again = asyncio.run(provider.collect(request()))
    assert again == result


def test_known_scope_missing_artifact_is_unavailable_not_invented(tmp_path: Path) -> None:
    batch = load_replay(fixture(tmp_path / "missing.jsonl", [event()]), source_id="original")
    provider = ReplayEvidenceProvider(batch, clock=lambda: NOW)
    result = asyncio.run(provider.collect(request(artifact="network")))
    assert len(result.evidence) == 1 and result.gaps
    item = result.evidence[0]
    assert item.availability == "unavailable"
    assert item.unavailable_reason
    assert item.provenance is None and item.observed_at is None


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "live"},
        {"scenario_id": "unrecorded"},
        {"endpoint": ENDPOINT.model_copy(update={"hostname": "forged-host"})},
        {"endpoint": ENDPOINT.model_copy(update={"agent_id": "forged-agent"})},
    ],
)
def test_unknown_or_live_evidence_scope_is_rejected(tmp_path: Path, changes: dict) -> None:
    batch = load_replay(fixture(tmp_path / "known.jsonl", [event()]), source_id="original")
    provider = ReplayEvidenceProvider(batch, clock=lambda: NOW)
    with pytest.raises(ValueError):
        asyncio.run(provider.collect(request(**changes)))


def test_list_evidence_checks_generated_alert_and_anchor_window(tmp_path: Path) -> None:
    batch = load_replay(
        fixture(
            tmp_path / "window.jsonl",
            [
                event("anchor"),
                event("boundary", observed_at="2026-01-01T12:05:00Z"),
                event("outside", observed_at="2026-01-01T12:05:01Z"),
            ],
        ),
        source_id="original",
    )
    alert = make_alerts(batch, ingested_at=NOW)[0]
    incident = Incident(
        incident_id="case-1",
        alert_id=alert.alert_id,
        mode="replay",
        scenario_id=alert.scenario_id,
        endpoint=alert.endpoint,
        priority="high",
        assessment="Synthetic case",
        created_at=NOW,
    )
    provider = ReplayEvidenceProvider(batch, clock=lambda: NOW)
    values = asyncio.run(provider.list_evidence(incident))
    assert [item.provenance.original_event_ids for item in values] == [("anchor",), ("boundary",)]
    with pytest.raises(ValueError):
        asyncio.run(
            provider.list_evidence(incident.model_copy(update={"alert_id": "forged-alert"}))
        )


def test_provider_detaches_source_and_revalidates_model_copy(tmp_path: Path) -> None:
    batch = load_replay(fixture(tmp_path / "immutable.jsonl", [event()]), source_id="original")
    provider = ReplayEvidenceProvider(batch, clock=lambda: NOW)
    batch.events[0].fields["process_id"] = "untrusted-mutation"
    result = asyncio.run(provider.collect(request()))
    assert result.evidence[0].provenance.original_event_ids == ("event-1",)
    malformed = request().model_copy(update={"end": NOW - timedelta(days=20)})
    with pytest.raises(ValueError):
        asyncio.run(provider.collect(malformed))
