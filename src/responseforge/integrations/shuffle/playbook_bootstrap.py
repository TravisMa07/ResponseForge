"""Private opt-in bootstrap of fixed original replay data and native graph bindings."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from responseforge.__main__ import FileConfig
from responseforge.integrations.shuffle.graphs import validate_workflow
from responseforge.integrations.shuffle.models import canonical_uuid, workflow_artifact
from responseforge.integrations.shuffle.operations import DockerRuntime
from responseforge.integrations.shuffle.qualification import _save
from responseforge.integrations.shuffle.runtime_deployment import render_runtime
from responseforge.replay import load_replay
from responseforge.replay_contracts import ReplayBatch
from responseforge.replay_driver import _pid, _revision


def source_fixture(source: Path) -> tuple[ReplayBatch, dict[str, Any]]:
    manifest = json.loads(source.with_name("replay.manifest.json").read_text())
    if (
        manifest.get("schema_version") != "1.0"
        or manifest.get("origin") != "original-synthetic"
        or source.is_symlink()
        or not source.is_file()
        or source.stat().st_size > 4 * 1048576
    ):
        raise ValueError("Invalid original playbook fixture")
    batch = load_replay(source, source_id=manifest["source_id"])
    profiles = manifest.get("profiles")
    if (
        batch.sha256 != manifest["sha256"]
        or batch.quarantine
        or batch.duplicates
        or not isinstance(profiles, dict)
        or not profiles
        or set(profiles.values()) != {"process", "persistence", "containment"}
        or {event.scenario_id for event in batch.events} != {"rf05-" + key for key in profiles}
    ):
        raise ValueError("Original fixture hash or scenarios differ from manifest")
    return batch, manifest


def prepare_playbooks(state_dir: Path, source: Path) -> dict[str, Any]:
    runtime = DockerRuntime(state_dir)
    manifest = runtime._verified(mutate=False)
    core = json.loads((state_dir / "core.json").read_text())
    if core.get("mode") != "replay":
        raise ValueError("Domain pilot requires explicit replay mode")
    batch, fixture = source_fixture(source)
    target = state_dir / "replay.jsonl"
    if target.is_symlink():
        raise ValueError("Replay snapshot cannot be a symlink")
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != batch.sha256:
            raise ValueError("Existing replay snapshot differs; preserve it for inspection")
    else:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "wb") as output:
            output.write(source.read_bytes())
    manifest["playbooks_enabled"] = True
    manifest["playbook_source_sha256"] = batch.sha256
    _save(state_dir / "runtime.json", manifest)
    _save(state_dir / "domain-source.json", fixture)
    rendered = render_runtime(
        manifest["images"],
        state_dir,
        engine_authorized=manifest.get("authorized") is True,
        playbooks_enabled=True,
    )
    _save(state_dir / "compose.json", rendered["compose"])
    return {
        "prepared": True,
        "source_sha256": batch.sha256,
        "starts_services": False,
        "authorized": manifest.get("authorized") is True,
    }


def bind_workflows(
    state_dir: Path,
    workflows: dict[str, dict[str, Any]],
    *,
    task_app_id: str,
    callback_app_id: str,
    org_id: str,
    qualification_id: str | None = None,
) -> None:
    if set(workflows) != {"process", "persistence", "containment"}:
        raise ValueError("Exactly three domain graphs are required")
    manifest = DockerRuntime(state_dir)._verified(mutate=False)
    if manifest.get("playbooks_enabled") is not True:
        raise ValueError("Private original replay source must be prepared first")
    fixture = json.loads((state_dir / "domain-source.json").read_text())
    batch = load_replay(state_dir / "replay.jsonl", source_id=fixture["source_id"])
    if batch.sha256 != manifest["playbook_source_sha256"]:
        raise ValueError("Private replay source binding differs")
    core = json.loads((state_dir / "core.json").read_text())
    if core.get("mode") != "replay":
        raise ValueError("Domain pilot cannot enable a live mock")
    endpoints = {item["endpoint_id"]: item for item in core["endpoints"]}
    resources = {key: set(value) for key, value in core["resource_allowlist"].items()}
    for event in batch.events:
        identity = event.endpoint.endpoint_id
        value = event.endpoint.model_dump(mode="json")
        if identity in endpoints and endpoints[identity] != value:
            raise ValueError("Original endpoint collides with existing canonical identity")
        endpoints[identity] = value
        resources.setdefault(identity, set()).add("host:" + identity)
        process = _pid(event.fields.get("process_id")) if event.artifact == "process" else None
        if process is not None:
            resources[identity].add("process:" + process)
    core["endpoints"] = list(endpoints.values())
    core["resource_allowlist"] = {key: sorted(value) for key, value in resources.items()}
    all_resources = set().union(*resources.values())
    actors: dict[str, str] = {}
    for actor in core["credentials"].values():
        roles = set(actor["roles"])
        actor["endpoint_ids"] = sorted(set(actor["endpoint_ids"]) | set(endpoints))
        if roles & {"analyst", "executor", "approver"}:
            actor["actions"] = sorted(
                set(actor["actions"]) | {"terminate_process", "isolate_host", "unisolate_host"}
            )
            actor["resources"] = sorted(set(actor["resources"]) | all_resources)
        if roles == {"source"}:
            actor["sources"] = sorted(set(actor.get("sources", [])) | {"replay-fixture"})
        for role in ("analyst", "executor"):
            if roles == {role} and actor.get("human") is False:
                if role in actors:
                    raise ValueError("Ambiguous technical actor")
                actors[role] = actor["actor_id"]
    if set(actors) != {"analyst", "executor"}:
        raise ValueError("Separate nonhuman technical actors are required")
    # A synthetic qualification identity models the separate human API boundary;
    # it is never copied into a workflow/app and is not measured analyst activity.
    if not any(
        value["actor_id"] == "rf05-qualification-human" for value in core["credentials"].values()
    ):
        core["credentials"][secrets.token_urlsafe(32)] = {
            "actor_id": "rf05-qualification-human",
            "roles": ["approver"],
            "endpoint_ids": sorted({event.endpoint.endpoint_id for event in batch.events}),
            "actions": ["terminate_process", "isolate_host"],
            "resources": sorted(all_resources),
            "sources": [],
            "human": True,
        }
    callback = json.loads((state_dir / "callback.json").read_text())
    shuffle = core.get("shuffle")
    if shuffle is None:
        from responseforge.integrations.shuffle.qualification import _environment

        shuffle = {
            "base_url": "https://shuffle-frontend",
            "api_key": _environment(state_dir)["SHUFFLE_DEFAULT_APIKEY"],
            "workflow_bindings": {},
            "ca_file": "/run/responseforge/pki/ca.pem",
        }
        core["shuffle"] = shuffle
    if not isinstance(shuffle, dict):
        raise ValueError("Invalid existing Shuffle private transport")
    old_domain = core.get("playbooks", {})
    kinds = dict(old_domain.get("bindings", {}))
    graph_hashes = dict(callback.get("workflow_graphs", {}))
    for kind, document in workflows.items():
        validate_workflow(document, kind, task_app_id, callback_app_id)  # type: ignore[arg-type]
        artifact = workflow_artifact(document)
        kinds[artifact.workflow_id] = kind
        graph_hashes[artifact.workflow_id] = artifact.sha256
        shuffle["workflow_bindings"][artifact.workflow_id] = {
            "version": "rf05b-native-v1",
            "sha256": artifact.sha256,
        }
    shuffle["org_id"] = canonical_uuid(org_id)
    scope = "" if qualification_id is None else "-" + canonical_uuid(qualification_id)
    core["playbooks"] = {
        "source_path": "/run/responseforge/replay.jsonl",
        "source_id": fixture["source_id"] + scope,
        "source_sha256": batch.sha256,
        "mock_path": "/var/lib/responseforge/mock-edr" + scope + ".sqlite3",
        "bindings": kinds,
        "actors": actors,
    }
    core["revision"] = _revision()
    core["environment"] = "docker-linux-" + manifest["architecture"] + "-original-RF05B"
    FileConfig.model_validate(core)
    callback["workflow_ids"] = sorted(set(callback["workflow_ids"]) | set(kinds))
    callback["workflow_graphs"] = graph_hashes
    _save(state_dir / "core.json", core, readable=True)
    _save(state_dir / "callback.json", callback, readable=True)
