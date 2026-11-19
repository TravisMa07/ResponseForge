"""Channel-scoped normalized evidence preserves original raw record provenance."""

import asyncio

from responseforge.replay import make_alerts
from tests.rf05 import helpers as old
from tests.rf06b.helpers import NOW, batch, recorded


def test_raw_ids_from_distinct_channels_are_preserved_without_collapse():
    source = batch([recorded(), recorded("task_create")])
    value = make_alerts(source, ingested_at=NOW)[0]
    assert value.provenance.original_event_ids == ("31", "31")


def test_core_and_cached_plan_accept_distinct_channel_same_raw_id(tmp_path, monkeypatch):
    original_principal = old.Principal
    source = batch([recorded(), recorded("task_create")])

    def source_fixture(path, records=None):
        return source, make_alerts(source, ingested_at=NOW)[0]

    def principal(**values):
        if "source" in values["roles"]:
            values["sources"] = frozenset({"splunk-attack-data"})
        return original_principal(**values)

    monkeypatch.setattr(old, "source", source_fixture)
    monkeypatch.setattr(old, "Principal", principal)
    w = old.world(tmp_path)
    first = asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert first.evidence_refs and first.proposal_id
    assert len(first.evidence_refs) == 2
    available = [
        e
        for e in w.core.evidence(w.incident_id, w.actors["analyst"])
        if e.availability == "available"
    ]
    assert len(available) == 2 and len({e.evidence_id for e in available}) == 2
    assert [e.provenance.original_event_ids for e in available] == [("31",), ("31",)]
    assert all(e.provenance.sha256 == source.sha256 for e in available)
    again = asyncio.run(old.reopened(w).prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert again == first
    assert old.effects(w) == 0


def test_full_source_same_channel_and_raw_id_on_different_computers_stays_scoped():
    from responseforge.contracts import EndpointRef

    one = recorded()
    other = recorded(endpoint=EndpointRef(endpoint_id="other-host", hostname="other-host"))
    source = batch([one, other])
    alerts = make_alerts(source, ingested_at=NOW)
    assert len(alerts) == 2
    assert {value.endpoint.endpoint_id for value in alerts} == {"rf05-host", "other-host"}
    assert all(value.provenance.original_event_ids == ("31",) for value in alerts)
