"""Explicit file bootstrap and source binding; no daemon or network."""

import json

import pytest

from responseforge.__main__ import load_settings
from tests.rf04.helpers import KEY, WF
from tests.rf05.helpers import world


def file_config(tmp_path):
    w = world(tmp_path)
    value = {
        "database_path": str(tmp_path / "loaded-core.sqlite"),
        "mode": "replay",
        "endpoints": [x.model_dump(mode="json") for x in w.settings.endpoints],
        "credentials": {
            token: {
                "actor_id": actor.actor_id,
                "roles": sorted(actor.roles),
                "endpoint_ids": sorted(actor.endpoint_ids),
                "actions": sorted(actor.actions),
                "resources": sorted(actor.resources),
                "sources": sorted(actor.sources),
                "human": actor.human,
            }
            for token, actor in w.settings.credentials.items()
        },
        "resource_allowlist": {k: sorted(v) for k, v in w.settings.resource_allowlist.items()},
        "shuffle": {
            "base_url": "https://shuffle.invalid",
            "api_key": KEY,
            "workflow_bindings": {WF: {"version": "rf05-test-v1", "sha256": "b" * 64}},
        },
        "playbooks": {
            "source_path": str(tmp_path / "original.jsonl"),
            "source_id": w.batch.source_id,
            "source_sha256": w.batch.sha256,
            "mock_path": str(tmp_path / "loaded-mock.sqlite"),
            "bindings": {WF: "process"},
            "actors": w.settings.playbook_actors,
        },
    }
    return value, w


def write_config(tmp_path, value):
    path = tmp_path / "private-config.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def test_explicit_replay_file_config_registers_only_fixed_mock_and_evidence(tmp_path):
    value, w = file_config(tmp_path)
    settings = load_settings(write_config(tmp_path, value))
    assert settings.replay_batch == w.batch
    assert settings.playbook_provider == "mock-edr"
    assert settings.provider_versions == {"mock-edr": "1.0"}
    assert settings.evidence_provider is not None
    assert settings.providers["mock-edr"].snapshot(w.settings.endpoints[0])["effect_count"] == 0


@pytest.mark.parametrize("change", ["live", "hash", "same-db"])
def test_unqualified_domain_file_config_rejects(tmp_path, change):
    value, _ = file_config(tmp_path)
    if change == "live":
        value["mode"] = "live"
    elif change == "hash":
        value["playbooks"]["source_sha256"] = "a" * 64
    else:
        value["playbooks"]["mock_path"] = value["database_path"]
    with pytest.raises(ValueError):
        load_settings(write_config(tmp_path, value))


def test_no_opt_in_preserves_provider_free_default(tmp_path):
    value, _ = file_config(tmp_path)
    value.pop("playbooks")
    settings = load_settings(write_config(tmp_path, value))
    assert not settings.providers and settings.replay_batch is None


def test_domain_source_mount_is_opt_in_and_read_only(tmp_path):
    from responseforge.integrations.shuffle.runtime_deployment import render_runtime

    images = {key: "sha256:" + "a" * 64 for key in
              ("backend", "worker", "orborus", "frontend", "opensearch", "core", "app")}
    target = "/run/responseforge/replay.jsonl"
    default = render_runtime(images, tmp_path)["compose"]["services"]["core"]["volumes"]
    assert not any(isinstance(item, dict) and item["target"] == target for item in default)
    enabled = render_runtime(images, tmp_path, playbooks_enabled=True)["compose"]["services"]["core"]["volumes"]
    mount = next((item for item in enabled if isinstance(item, dict) and item["target"] == target), None)
    assert mount is not None and mount["read_only"] is True
    assert mount["source"] == str(tmp_path / "replay.jsonl")
