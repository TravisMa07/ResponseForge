"""Non-starting preparation and binding preserve legacy and private authority."""

import json
import shutil
import stat
from copy import deepcopy

import pytest

import responseforge.integrations.shuffle.recorded_bootstrap as module
from responseforge.integrations.shuffle.graphs import build_workflow
from tests.rf04.helpers import ORG, WF
from tests.rf05b.helpers import CALLBACK_APP, TASK_APP
from tests.rf05b.test_runtime import file_config
from tests.rf06b2.helpers import (
    QUALIFICATION,
    canonical,
    config_for,
    qualification_tree,
    write_bundle,
    write_prepared_config,
)


def prepared_world(tmp_path, monkeypatch):
    root, cases, cases_path, catalog = qualification_tree(tmp_path)
    state = tmp_path / "pilot"
    state.mkdir(mode=0o700)
    core, _ = file_config(tmp_path)
    (state / "core.json").write_bytes(canonical(core))
    callback = {
        "workflow_ids": [WF],
        "workflow_graphs": {WF: "b" * 64},
        "api_key": "original-workflow-secret",
    }
    (state / "callback.json").write_bytes(canonical(callback))
    manifest = {
        "authorized": True,
        "playbooks_enabled": True,
        "architecture": "arm64",
        "images": {
            key: "sha256:" + "a" * 64
            for key in ("backend", "worker", "orborus", "frontend", "opensearch", "core", "app")
        },
    }
    (state / "runtime.json").write_bytes(canonical(manifest))
    (state / "compose.json").write_bytes(canonical({"original": "preserve-before-preparation"}))
    calls = []
    rows = []

    class Runtime:
        def __init__(self, directory):
            self.directory = directory

        def _verified(self, *, mutate=False):
            assert mutate is False
            return json.loads((self.directory / "runtime.json").read_text())

        def command(self, *arguments, **keywords):
            assert not keywords.get("mutate", False)
            calls.append(arguments)
            assert arguments[:2] == ("ps", "-a")
            return "\n".join(json.dumps(value) for value in rows)

    monkeypatch.setattr(module, "DockerRuntime", Runtime)
    monkeypatch.setattr(module, "CATALOG", catalog)
    return state, root, cases, cases_path, core, callback, calls, rows


def graphs():
    values = {}
    for index, kind in enumerate(("process", "persistence", "containment"), 6):
        value = build_workflow(kind, TASK_APP, CALLBACK_APP)
        value["id"] = (
            f"{index}" * 8
            + "-"
            + f"{index}" * 4
            + "-4"
            + f"{index}" * 3
            + "-8"
            + f"{index}" * 3
            + "-"
            + f"{index}" * 12
        )
        values[kind] = value
    return values


def test_prepare_is_nonstarting_readonly_source_snapshot_and_reusable(tmp_path, monkeypatch):
    state, root, _, cases_path, before_core, before_callback, calls, _ = prepared_world(
        tmp_path, monkeypatch
    )
    result = module.prepare_recorded(state, cases_path, root)
    assert result["prepared"] is True and result["case_count"] == 14
    assert result["starts_services"] is False
    assert all(call[:2] == ("ps", "-a") for call in calls)
    assert json.loads((state / "core.json").read_text()) == before_core
    assert json.loads((state / "callback.json").read_text()) == before_callback
    snapshot = state / "recorded"
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o755
    for path in snapshot.rglob("*"):
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert module.recorded_bundle_fingerprint(snapshot) == result["source_sha256"]
    assert module.prepare_recorded(state, cases_path, root) == result
    assert not any(path.name.startswith(".recorded-") for path in state.iterdir())
    assert not (state / "recorded" / "core.json").exists()


@pytest.mark.parametrize("state_name", ["running", "restarting", "paused"])
def test_running_owned_services_prevent_preparation_without_changes(
    tmp_path, monkeypatch, state_name
):
    state, root, _, cases_path, _, _, _, rows = prepared_world(tmp_path, monkeypatch)
    before = {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}
    rows.append({"State": state_name})
    with pytest.raises(ValueError):
        module.prepare_recorded(state, cases_path, root)
    assert {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()} == before
    assert not (state / "recorded").exists()


@pytest.mark.parametrize("flag", ["authorized", "playbooks_enabled"])
def test_missing_authorized_original_pilot_refuses(tmp_path, monkeypatch, flag):
    state, root, _, cases_path, _, _, calls, _ = prepared_world(tmp_path, monkeypatch)
    value = json.loads((state / "runtime.json").read_text())
    value[flag] = False
    (state / "runtime.json").write_bytes(canonical(value))
    with pytest.raises(ValueError):
        module.prepare_recorded(state, cases_path, root)
    assert not calls and not (state / "recorded").exists()


def test_wrong_profile_record_does_not_become_a_frozen_positive(tmp_path, monkeypatch):
    state, root, cases, cases_path, _, _, _, _ = prepared_world(tmp_path, monkeypatch)
    value = cases.model_dump(mode="json")
    value["cases"][0]["event_ids"] = value["cases"][5]["event_ids"]
    cases_path.write_bytes(canonical(value))
    with pytest.raises(ValueError):
        module.prepare_recorded(state, cases_path, root)
    assert not (state / "recorded").exists()


def test_changed_existing_scope_is_preserved_not_overwritten(tmp_path, monkeypatch):
    state, root, _, cases_path, _, _, _, _ = prepared_world(tmp_path, monkeypatch)
    module.prepare_recorded(state, cases_path, root)
    marker = state / "recorded" / "do-not-delete"
    marker.write_text("retained diagnostic")
    before = (state / "runtime.json").read_bytes()
    with pytest.raises(ValueError):
        module.prepare_recorded(state, cases_path, root)
    assert marker.read_text() == "retained diagnostic"
    assert (state / "runtime.json").read_bytes() == before


def test_conflicting_old_runtime_binding_does_not_publish_new_scope(tmp_path, monkeypatch):
    state, root, _, cases_path, _, _, _, _ = prepared_world(tmp_path, monkeypatch)
    value = json.loads((state / "runtime.json").read_text())
    value["recorded_source_sha256"] = "f" * 64
    (state / "runtime.json").write_bytes(canonical(value))
    before = (state / "runtime.json").read_bytes()
    with pytest.raises(ValueError):
        module.prepare_recorded(state, cases_path, root)
    assert (state / "runtime.json").read_bytes() == before
    assert not (state / "recorded").exists()


@pytest.mark.parametrize(
    "change", ["extra-root", "extra-member", "symlink", "source", "config-path"]
)
def test_fingerprint_rejects_changed_or_unbounded_tree(tmp_path, change):
    root = tmp_path / "recorded"
    entry = write_bundle(root)
    write_prepared_config(root, config_for(root, entry))
    assert module.recorded_bundle_fingerprint(root)
    if change == "extra-root":
        (root / "unexpected").write_text("PRIVATE")
    elif change == "extra-member":
        (root / entry.artifact_id / "extra").write_text("PRIVATE")
    elif change == "symlink":
        member = root / entry.artifact_id / "source.xml"
        external = tmp_path / "preserve"
        member.rename(external)
        member.symlink_to(external)
    elif change == "source":
        with (root / entry.artifact_id / "source.xml").open("ab") as stream:
            stream.write(b"PRIVATE")
    else:
        value = json.loads((root / "cases.json").read_text())
        value["bundle_root"] = "/arbitrary/host/directory"
        (root / "cases.json").write_bytes(canonical(value))
    with pytest.raises(ValueError) as captured:
        module.recorded_bundle_fingerprint(root)
    assert "PRIVATE" not in str(captured.value)


def test_fingerprint_binds_relative_content_not_host_root(tmp_path):
    root = tmp_path / "one"
    entry = write_bundle(root)
    write_prepared_config(root, config_for(root, entry))
    other = tmp_path / "two"
    shutil.copytree(root, other)
    assert module.recorded_bundle_fingerprint(root) == module.recorded_bundle_fingerprint(other)
    with (other / "cases.json").open("ab") as stream:
        stream.write(b"\n")
    assert module.recorded_bundle_fingerprint(root) != module.recorded_bundle_fingerprint(other)


def test_binding_preserves_legacy_databases_human_grants_and_callback_secrets(
    tmp_path, monkeypatch
):
    state, root, _, cases_path, old_core, old_callback, _, _ = prepared_world(tmp_path, monkeypatch)
    module.prepare_recorded(state, cases_path, root)
    legacy = deepcopy(old_core["playbooks"])
    old_humans = {key: value for key, value in old_core["credentials"].items() if value["human"]}
    module.bind_recorded_workflows(
        state,
        graphs(),
        task_app_id=TASK_APP,
        callback_app_id=CALLBACK_APP,
        org_id=ORG,
        qualification_id=QUALIFICATION,
    )
    value = json.loads((state / "core.json").read_text())
    for field in ("source_path", "source_id", "source_sha256", "mock_path", "actors"):
        assert value["playbooks"][field] == legacy[field]
    assert {key: value["credentials"][key] for key in old_humans} == old_humans
    assert value["recorded"]["mock_path"] != legacy["mock_path"]
    assert value["recorded"]["mock_path"] != value["database_path"]
    assert value["recorded"]["bundle_root"] == "/run/responseforge/recorded"
    new_humans = [
        (key, actor)
        for key, actor in value["credentials"].items()
        if actor["actor_id"] == "rf06-qualification-human"
    ]
    assert len(new_humans) == 1
    token, human = new_humans[0]
    assert human["human"] is True and human["roles"] == ["approver"]
    assert set(human["actions"]) == {"terminate_process", "isolate_host"}
    assert len(human["endpoint_ids"]) == 5
    callback = json.loads((state / "callback.json").read_text())
    assert callback["api_key"] == old_callback["api_key"]
    assert token not in json.dumps(callback)
    assert old_callback["workflow_ids"][0] in callback["workflow_ids"]
    assert value["shuffle"]["workflow_bindings"][WF] == old_core["shuffle"]["workflow_bindings"][WF]
    before = (state / "core.json").read_bytes()
    module.bind_recorded_workflows(
        state,
        graphs(),
        task_app_id=TASK_APP,
        callback_app_id=CALLBACK_APP,
        org_id=ORG,
        qualification_id=QUALIFICATION,
    )
    assert (state / "core.json").read_bytes() == before


def test_existing_other_recorded_database_scope_is_not_rebound(tmp_path, monkeypatch):
    state, root, _, cases_path, _, _, _, _ = prepared_world(tmp_path, monkeypatch)
    module.prepare_recorded(state, cases_path, root)
    module.bind_recorded_workflows(
        state,
        graphs(),
        task_app_id=TASK_APP,
        callback_app_id=CALLBACK_APP,
        org_id=ORG,
        qualification_id=QUALIFICATION,
    )
    value = json.loads((state / "core.json").read_text())
    value["recorded"]["qualification_id"] = "44444444-4444-4444-8444-444444444444"
    value["recorded"]["mock_path"] = "/var/lib/responseforge/another-diagnostic.sqlite3"
    (state / "core.json").chmod(0o600)
    (state / "core.json").write_bytes(canonical(value))
    before = (state / "core.json").read_bytes(), (state / "callback.json").read_bytes()
    with pytest.raises(ValueError):
        module.bind_recorded_workflows(
            state,
            graphs(),
            task_app_id=TASK_APP,
            callback_app_id=CALLBACK_APP,
            org_id=ORG,
            qualification_id=QUALIFICATION,
        )
    assert ((state / "core.json").read_bytes(), (state / "callback.json").read_bytes()) == before


@pytest.mark.parametrize("conflict", ["kind", "callback-graph", "transport-graph"])
def test_conflicting_existing_binding_is_preserved_for_inspection(tmp_path, monkeypatch, conflict):
    state, root, _, cases_path, _, _, _, _ = prepared_world(tmp_path, monkeypatch)
    module.prepare_recorded(state, cases_path, root)
    documents = graphs()
    module.bind_recorded_workflows(
        state,
        documents,
        task_app_id=TASK_APP,
        callback_app_id=CALLBACK_APP,
        org_id=ORG,
        qualification_id=QUALIFICATION,
    )
    core = json.loads((state / "core.json").read_text())
    callback = json.loads((state / "callback.json").read_text())
    identity = documents["process"]["id"]
    if conflict == "kind":
        core["playbooks"]["bindings"][identity] = "persistence"
    elif conflict == "callback-graph":
        callback["workflow_graphs"][identity] = "f" * 64
    else:
        core["shuffle"]["workflow_bindings"][identity]["sha256"] = "f" * 64
    (state / "core.json").chmod(0o600)
    (state / "callback.json").chmod(0o600)
    (state / "core.json").write_bytes(canonical(core))
    (state / "callback.json").write_bytes(canonical(callback))
    before = (state / "core.json").read_bytes(), (state / "callback.json").read_bytes()
    with pytest.raises(ValueError):
        module.bind_recorded_workflows(
            state,
            documents,
            task_app_id=TASK_APP,
            callback_app_id=CALLBACK_APP,
            org_id=ORG,
            qualification_id=QUALIFICATION,
        )
    assert ((state / "core.json").read_bytes(), (state / "callback.json").read_bytes()) == before
