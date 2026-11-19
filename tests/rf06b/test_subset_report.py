"""A default-redacted report must disclose intentionally selected source scope."""

import asyncio
import json
from dataclasses import replace

from responseforge.playbooks.assessment import assess
from responseforge.replay import make_alerts
from responseforge.replay.selection import select_recorded
from responseforge.reports import build_report, render_html
from tests.rf05 import helpers as old
from tests.rf06b.helpers import NOW, batch, recorded


def test_selected_source_has_explicit_gap():
    source = batch([recorded()])
    selected = select_recorded(source, event_ids=(source.events[0].event_id,))
    alert = make_alerts(selected, ingested_at=NOW)[0]
    result = assess("process", selected, alert)
    assert "Explicit recorded source subset; omitted source events were not assessed" in result.known_gaps


def test_default_report_discloses_selected_scope_and_does_not_infer_changed_source(tmp_path, monkeypatch):
    source = batch([recorded()])
    selected = select_recorded(source, event_ids=(source.events[0].event_id,))
    principal_class = old.Principal

    def principal(**values):
        if "source" in values["roles"]:
            values["sources"] = frozenset({"splunk-attack-data"})
        return principal_class(**values)

    monkeypatch.setattr(old, "source", lambda path, records=None: (
        selected, make_alerts(selected, ingested_at=NOW)[0]
    ))
    monkeypatch.setattr(old, "Principal", principal)
    world = old.world(tmp_path)
    asyncio.run(world.service.prepare(world.incident_id, world.request, world.actors["workflow"]))
    report = build_report(world.core, world.incident_id, world.actors["analyst"])
    assert report["source_selection"] == "explicit_subset"
    assert report["source_transformation"] == "windows-events-v1"
    assert "explicit_subset" in render_html(report)
    assert "INERT" not in json.dumps(report)
    # The historical case cannot acquire a 'full source' claim from reconfiguration.
    world.core.settings = replace(world.core.settings, replay_batch=source)
    changed = build_report(world.core, world.incident_id, world.actors["analyst"])
    assert changed["source_selection"] == "unavailable"
