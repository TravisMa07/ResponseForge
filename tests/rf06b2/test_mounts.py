"""The recorded-source bind is explicit, read-only and core-only."""

import hashlib
import json

import pytest

from responseforge.integrations.shuffle.operations import DockerRuntime
from responseforge.integrations.shuffle.recorded_bootstrap import recorded_bundle_fingerprint
from responseforge.integrations.shuffle.runtime_deployment import render_runtime
from tests.rf04_runtime.test_deployment import images
from tests.rf04_runtime.test_operations import runner, runtime_state
from tests.rf06b2.helpers import config_for, write_bundle, write_prepared_config

TARGET = "/run/responseforge/recorded"


def test_recorded_mount_is_absent_by_default_and_core_only_when_enabled(tmp_path):
    default = render_runtime(images(), tmp_path, playbooks_enabled=True)["compose"]
    assert not any(
        isinstance(mount, dict) and mount.get("target") == TARGET
        for service in default["services"].values()
        for mount in service.get("volumes", [])
    )
    enabled = render_runtime(images(), tmp_path, playbooks_enabled=True, recorded_enabled=True)[
        "compose"
    ]
    matching = [
        (name, mount)
        for name, service in enabled["services"].items()
        for mount in service.get("volumes", [])
        if isinstance(mount, dict) and mount.get("target") == TARGET
    ]
    assert matching == [
        (
            "core",
            {
                "type": "bind",
                "source": str(tmp_path / "recorded"),
                "target": TARGET,
                "read_only": True,
            },
        )
    ]
    assert not any(
        "ports" in enabled["services"][name] for name in ("backend", "orborus", "opensearch")
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"recorded_enabled": True},
        {"playbooks_enabled": True, "recorded_enabled": "true"},
        {"playbooks_enabled": True, "recorded_enabled": 1},
    ],
)
def test_invalid_source_mount_enablement_is_not_truthy_coercion(tmp_path, changes):
    with pytest.raises(ValueError):
        render_runtime(images(), tmp_path, **changes)


def source_state(tmp_path):
    root = tmp_path / "recorded"
    entry = write_bundle(root)
    write_prepared_config(root, config_for(root, entry))
    raw = b'{"original":"synthetic-state-source"}\n'
    (tmp_path / "replay.jsonl").write_bytes(raw)
    state = runtime_state(
        tmp_path,
        playbooks_enabled=True,
        recorded_enabled=True,
        playbook_source_sha256=hashlib.sha256(raw).hexdigest(),
        recorded_source_sha256=recorded_bundle_fingerprint(root),
    )
    (tmp_path / "compose.json").write_text(
        json.dumps(
            render_runtime(
                images(),
                tmp_path,
                engine_authorized=True,
                playbooks_enabled=True,
                recorded_enabled=True,
            )["compose"]
        )
    )
    return state, root, entry


@pytest.mark.parametrize("change", ["runtime-hash", "source-bytes", "extra-scope"])
def test_changed_recorded_scope_refuses_before_any_engine_operation(tmp_path, change):
    state, root, entry = source_state(tmp_path)
    if change == "runtime-hash":
        value = json.loads((state / "runtime.json").read_text())
        value["recorded_source_sha256"] = "f" * 64
        (state / "runtime.json").write_text(json.dumps(value))
    elif change == "source-bytes":
        with (root / entry.artifact_id / "source.xml").open("ab") as stream:
            stream.write(b" ALTERED")
    else:
        (root / "another-scope").write_text("do not ignore")
    run, calls = runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert not calls


def test_valid_recorded_scope_still_requires_exact_original_compose(tmp_path):
    state, _, _ = source_state(tmp_path)
    value = json.loads((state / "compose.json").read_text())
    value["services"]["core"]["volumes"][-1]["read_only"] = False
    (state / "compose.json").write_text(json.dumps(value))
    run, calls = runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert not calls
