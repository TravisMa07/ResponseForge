"""Intended behavioral reds against importable pre-implementation scaffolds."""

import re

from responseforge.integrations.shuffle.recorded_bootstrap import recorded_bundle_fingerprint
from responseforge.replay import make_alerts
from responseforge.replay.registry import ReplayRegistry, load_recorded_sources
from tests.rf06b.helpers import NOW, batch, recorded
from tests.rf06b2.helpers import config_for, write_bundle, write_prepared_config


def test_registry_resolves_exact_registered_original_alert():
    source = batch([recorded()])
    original = make_alerts(source, ingested_at=NOW)[0]
    assert ReplayRegistry((source,)).resolve(original) == source


def test_valid_local_recorded_bundle_loads_original_selected_source(tmp_path):
    root = tmp_path / "bundles"
    entry = write_bundle(root)
    config = config_for(root, entry)
    sources = load_recorded_sources(config, mode="replay")
    assert len(sources) == 1
    assert sources[0].sha256 == entry.sha256
    assert sources[0].events[0].fields["original_record_id"] == "31"
    assert sources[0].origin.selected_event_ids == config.cases[0].event_ids


def test_valid_prepared_bundle_has_stable_integrity_fingerprint(tmp_path):
    root = tmp_path / "recorded"
    entry = write_bundle(root)
    write_prepared_config(root, config_for(root, entry))
    first = recorded_bundle_fingerprint(root)
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert recorded_bundle_fingerprint(root) == first
