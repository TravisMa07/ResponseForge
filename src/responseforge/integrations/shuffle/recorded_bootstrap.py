"""Non-starting, source-bound recorded preparation for the reviewed pilot.

Source material and configured commands remain inert data. A prepared directory
is immutable and separately fingerprinted from the source-built image inventory.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Any, cast

from responseforge.contracts import Mode
from responseforge.dataset_contracts import DatasetArtifact
from responseforge.datasets import _publish_bundle, _read_regular, _safe_directory
from responseforge.integrations.shuffle.graphs import validate_workflow
from responseforge.integrations.shuffle.models import canonical_uuid, workflow_artifact
from responseforge.integrations.shuffle.operations import LABEL, PROJECT, DockerRuntime
from responseforge.integrations.shuffle.qualification import _save
from responseforge.integrations.shuffle.runtime_deployment import render_runtime
from responseforge.playbooks.assessment import assess
from responseforge.playbooks.models import PlaybookKind
from responseforge.playbooks.recorded import recorded_signal
from responseforge.recorded_contracts import RecordedCaseManifest, RecordedConfig
from responseforge.replay import logical_receipt, make_alerts
from responseforge.replay.registry import load_recorded_sources
from responseforge.replay_contracts import ReplayBatch
from responseforge.replay_driver import _pid, _revision

CATALOG = Path(__file__).resolve().parents[4] / "datasets" / "catalog.json"
_CONTAINER_ROOT = "/run/responseforge/recorded"
_MAX_BYTES = 1048576
_MEMBERS = {"source.xml", "LICENSE", "manifest.json"}
# These freeze the reviewed source family, never infer a verdict from a label.
_PROFILE: dict[str, tuple[str, str, str | None, str]] = {
    "powershell": ("splunk-powershell-create", "process", "powershell", "propose"),
    "lsass": ("splunk-lsass-access", "process", "lsass_access", "escalate"),
    "task": ("splunk-task-create", "persistence", "task_creation", "escalate"),
    "note": ("splunk-ransom-note", "containment", "ransom_note", "propose"),
    "dns": ("splunk-process-dns", "containment", "process_dns", "propose"),
}
for _name in ("powershell", "lsass", "task", "note", "dns"):
    _artifact, _kind, _, _ = _PROFILE[_name]
    _PROFILE[_name + "-negative"] = (_artifact, _kind, None, "no_action")
for _name in ("denied", "expired", "callback-loss", "task-failure"):
    _PROFILE[_name] = _PROFILE["powershell"]


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Ambiguous recorded configuration")
        value[key] = item
    return value


def _document(path: Path) -> Any:
    return json.loads(_read_regular(path, _MAX_BYTES), object_pairs_hook=_unique)


def _mock_path(identity: str) -> str:
    return "/var/lib/responseforge/mock-recorded-" + canonical_uuid(identity) + ".sqlite3"


def _host_config(root: Path) -> RecordedConfig:
    _safe_directory(root, create=False)
    config = RecordedConfig.model_validate(_document(root / "cases.json"))
    if config.bundle_root != _CONTAINER_ROOT or config.mock_path != _mock_path(config.qualification_id):
        raise ValueError("Recorded container paths differ from fixed preparation")
    return config.model_copy(update={"bundle_root": str(root)})


def recorded_bundle_fingerprint(root: Path) -> str:
    """Hash only an exact bounded, revalidated prepared tree; never follow links."""
    try:
        config = _host_config(root)
        artifacts = {case.artifact.artifact_id: case.artifact for case in config.cases}
        if {member.name for member in root.iterdir()} != {"cases.json", *artifacts}:
            raise ValueError("Unexpected recorded tree members")
        files = [root / "cases.json"]
        for identity in sorted(artifacts):
            directory = root / identity
            _safe_directory(directory, create=False)
            if {member.name for member in directory.iterdir()} != _MEMBERS:
                raise ValueError("Unexpected recorded bundle members")
            files.extend(directory / name for name in sorted(_MEMBERS))
        # This validates canonical metadata, license/source hashes and selected
        # source identities independently of the directory hash itself.
        load_recorded_sources(config, mode=Mode.REPLAY)
        digest = hashlib.sha256()
        total = 0
        for path in sorted(files):
            raw = _read_regular(path, _MAX_BYTES)
            total += len(raw)
            if total > 16 * _MAX_BYTES:
                raise ValueError("Recorded tree exceeds byte limit")
            relative = str(path.relative_to(root)).encode("utf-8")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(raw).to_bytes(8, "big"))
            digest.update(raw)
        return digest.hexdigest()
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        raise ValueError("Invalid prepared recorded source tree") from None


def _catalog() -> dict[str, DatasetArtifact]:
    value = _document(CATALOG)
    if not isinstance(value, dict) or set(value) != {"schema_version", "artifacts"}:
        raise ValueError("Invalid reviewed source catalog")
    if value["schema_version"] != "1.0" or not isinstance(value["artifacts"], list):
        raise ValueError("Invalid reviewed source catalog")
    items = [DatasetArtifact.model_validate(item) for item in value["artifacts"]]
    if len(items) > 32 or len({item.artifact_id for item in items}) != len(items):
        raise ValueError("Ambiguous reviewed source catalog")
    return {item.artifact_id: item for item in items}


def _reviewed_cases(config: RecordedConfig) -> tuple[ReplayBatch, ...]:
    if {case.profile for case in config.cases} != set(_PROFILE) or len(config.cases) != 14:
        raise ValueError("Exactly fourteen frozen recorded profiles are required")
    catalog = _catalog()
    batches = load_recorded_sources(config, mode=Mode.REPLAY)
    if len(batches) != len(config.cases):
        raise ValueError("Recorded cases differ from loaded source set")
    for case, batch in zip(config.cases, batches, strict=True):
        artifact_id, kind, signal, disposition = _PROFILE[case.profile]
        if (
            case.artifact.artifact_id != artifact_id
            or catalog.get(artifact_id) != case.artifact
            or case.scenario_id != "rf06-" + case.profile + "-" + config.qualification_id
            or len(batch.events) != 1
        ):
            raise ValueError("Recorded case differs from reviewed source profile")
        event = batch.events[0]
        alerts = make_alerts(batch, ingested_at=logical_receipt(batch))
        if (
            len(alerts) != 1
            or recorded_signal(event) != signal
            or assess(cast(PlaybookKind, kind), batch, alerts[0]).disposition != disposition
        ):
            raise ValueError("Recorded case fields differ from independent expectation")
    return batches


def _stopped(runtime: DockerRuntime) -> dict[str, Any]:
    manifest = runtime._verified(mutate=False)
    if manifest.get("authorized") is not True or manifest.get("playbooks_enabled") is not True:
        raise ValueError("Reviewed authorized original-playbook pilot required")
    raw = runtime.command(
        "ps", "-a", "--filter", "label=" + LABEL + "=" + PROJECT,
        "--format", "{{json .}}",
    )
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if any(
        not isinstance(row, dict)
        or str(row.get("State", "")).casefold() not in {"created", "exited", "dead"}
        for row in rows
    ):
        raise ValueError("Recorded preparation requires stopped owned services")
    return manifest


def _write_snapshot(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_recorded(state_dir: Path, cases_path: Path, bundle_root: Path) -> dict[str, Any]:
    """Prepare verified source bytes and exact fixed topology; never start a service."""
    staging: Path | None = None
    try:
        _safe_directory(state_dir, create=False)
        manifest = _stopped(DockerRuntime(state_dir))
        core = _document(state_dir / "core.json")
        _document(state_dir / "compose.json")
        if not isinstance(core, dict) or core.get("mode") != "replay" or not core.get("playbooks"):
            raise ValueError("Explicit original replay configuration is required")
        cases = RecordedCaseManifest.model_validate(_document(cases_path))
        host = RecordedConfig(
            **cases.model_dump(mode="python"), bundle_root=str(bundle_root),
            mock_path=_mock_path(cases.qualification_id),
        )
        _reviewed_cases(host)
        target = state_dir / "recorded"
        container = host.model_copy(update={"bundle_root": _CONTAINER_ROOT})
        staging = Path(tempfile.mkdtemp(prefix=".recorded-", dir=state_dir))
        # The private state parent remains0700. The mounted subtree must be
        # readable/traversable by the existing unprivileged core UID1000.
        staging.chmod(0o755)
        _write_snapshot(
            staging / "cases.json",
            (json.dumps(container.model_dump(mode="json"), indent=2) + "\n").encode(),
        )
        artifacts = {case.artifact.artifact_id for case in cases.cases}
        for identity in sorted(artifacts):
            source = bundle_root / identity
            _safe_directory(source, create=False)
            destination = staging / identity
            destination.mkdir(mode=0o755)
            for name in sorted(_MEMBERS):
                _write_snapshot(destination / name, _read_regular(source / name, _MAX_BYTES))
        expected = recorded_bundle_fingerprint(staging)
        old = manifest.get("recorded_source_sha256")
        if old not in (None, expected):
            raise ValueError("Existing recorded runtime binding differs")
        updated = dict(manifest, recorded_enabled=True, recorded_source_sha256=expected)
        rendered = render_runtime(
            updated["images"], state_dir, engine_authorized=True,
            playbooks_enabled=True, recorded_enabled=True,
        )
        if target.exists() or target.is_symlink():
            if recorded_bundle_fingerprint(target) != expected:
                raise ValueError("Existing recorded scope differs; preserve it for inspection")
        else:
            _publish_bundle(staging, target)
            staging = None
        _save(state_dir / "runtime.json", updated)
        _save(state_dir / "compose.json", rendered["compose"])
        return {
            "prepared": True, "source_sha256": expected, "case_count": 14,
            "starts_services": False, "authorized": True,
        }
    except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise ValueError("Recorded source preparation refused") from None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def bind_recorded_workflows(
    state_dir: Path, workflows: dict[str, dict[str, Any]], *, task_app_id: str,
    callback_app_id: str, org_id: str, qualification_id: str,
) -> None:
    """Merge actual reviewed graph bindings while preserving original recovery scope."""
    try:
        from responseforge.__main__ import FileConfig

        if set(workflows) != {"process", "persistence", "containment"}:
            raise ValueError("Exactly three recorded graphs required")
        manifest = DockerRuntime(state_dir)._verified(mutate=False)
        root = state_dir / "recorded"
        if (
            manifest.get("recorded_enabled") is not True
            or recorded_bundle_fingerprint(root) != manifest.get("recorded_source_sha256")
        ):
            raise ValueError("Prepared recorded source binding differs")
        host = _host_config(root)
        if canonical_uuid(qualification_id) != host.qualification_id:
            raise ValueError("Recorded qualification scope differs")
        batches = _reviewed_cases(host)
        core = _document(state_dir / "core.json")
        callback = _document(state_dir / "callback.json")
        if not isinstance(core, dict) or core.get("mode") != "replay":
            raise ValueError("Recorded mock cannot satisfy live mode")
        domain = core.get("playbooks")
        shuffle = core.get("shuffle")
        if not isinstance(domain, dict) or not isinstance(shuffle, dict):
            raise ValueError("Existing original playbook/transport configuration required")
        desired = host.model_copy(update={"bundle_root": _CONTAINER_ROOT})
        if core.get("recorded") is not None and RecordedConfig.model_validate(core["recorded"]) != desired:
            raise ValueError("Existing recorded provider/source scope differs; preserve it for restoration")
        endpoints = {item["endpoint_id"]: item for item in core["endpoints"]}
        resources = {identity: set(values) for identity, values in core["resource_allowlist"].items()}
        recorded_endpoints: dict[str, dict[str, Any]] = {}
        recorded_resources: set[str] = set()
        for batch in batches:
            for event in batch.events:
                identity = event.endpoint.endpoint_id
                value = event.endpoint.model_dump(mode="json")
                if identity in endpoints and endpoints[identity] != value:
                    raise ValueError("Recorded canonical endpoint collides with retained state")
                endpoints[identity] = value
                recorded_endpoints[identity] = value
                allowed = resources.setdefault(identity, set())
                allowed.add("host:" + identity)
                recorded_resources.add("host:" + identity)
                if event.fields.get("event_kind") == "process_create":
                    pid = _pid(event.fields.get("process_id"))
                    if pid is not None:
                        allowed.add("process:" + pid)
                        recorded_resources.add("process:" + pid)
        core["endpoints"] = list(endpoints.values())
        core["resource_allowlist"] = {identity: sorted(values) for identity, values in resources.items()}
        technical: dict[str, str] = {}
        for actor in core["credentials"].values():
            roles = set(actor["roles"])
            if actor.get("human", False) is not False or len(roles) != 1:
                continue
            role = next(iter(roles))
            if role not in {"source", "workflow", "analyst", "executor"}:
                continue
            actor["endpoint_ids"] = sorted(set(actor["endpoint_ids"]) | set(recorded_endpoints))
            if role in {"analyst", "executor"}:
                actor["resources"] = sorted(set(actor["resources"]) | recorded_resources)
                actor["actions"] = sorted(set(actor["actions"]) | {"terminate_process", "isolate_host"})
                if role in technical:
                    raise ValueError("Ambiguous recorded technical actor")
                technical[role] = actor["actor_id"]
            if role == "source":
                actor["sources"] = sorted(set(actor.get("sources", [])) | {"splunk-attack-data"})
        if set(technical) != {"analyst", "executor"} or technical != domain.get("actors"):
            raise ValueError("Original technical actor binding differs")
        human = {
            "actor_id": "rf06-qualification-human", "roles": ["approver"],
            "endpoint_ids": sorted(recorded_endpoints),
            "actions": ["terminate_process", "isolate_host"],
            "resources": sorted(recorded_resources), "sources": [], "human": True,
        }
        existing = [value for value in core["credentials"].values() if value["actor_id"] == human["actor_id"]]
        if existing and (len(existing) != 1 or existing[0] != human):
            raise ValueError("Existing recorded human fixture scope differs")
        if not existing:
            core["credentials"][secrets.token_urlsafe(32)] = human
        kinds = dict(domain["bindings"])
        graphs = dict(callback.get("workflow_graphs", {}))
        bindings = dict(shuffle["workflow_bindings"])
        for kind, document in workflows.items():
            validate_workflow(document, cast(PlaybookKind, kind), task_app_id, callback_app_id)
            artifact = workflow_artifact(document)
            binding = {"version": "rf06b2-native-v1", "sha256": artifact.sha256}
            if (
                (artifact.workflow_id in bindings and bindings[artifact.workflow_id] != binding)
                or kinds.get(artifact.workflow_id) not in (None, kind)
                or graphs.get(artifact.workflow_id) not in (None, artifact.sha256)
            ):
                raise ValueError("Existing workflow binding differs")
            kinds[artifact.workflow_id] = kind
            graphs[artifact.workflow_id] = artifact.sha256
            bindings[artifact.workflow_id] = binding
        domain["bindings"] = kinds
        shuffle["workflow_bindings"] = bindings
        canonical_org = canonical_uuid(org_id)
        if shuffle.get("org_id") not in (None, canonical_org):
            raise ValueError("Existing Shuffle organization differs")
        shuffle["org_id"] = canonical_org
        core["recorded"] = desired.model_dump(mode="json")
        core["revision"] = _revision()
        core["environment"] = "docker-linux-" + manifest["architecture"] + "-recorded-RF06B2"
        FileConfig.model_validate(core)
        callback["workflow_ids"] = sorted(set(callback["workflow_ids"]) | set(kinds))
        callback["workflow_graphs"] = graphs
        _save(state_dir / "core.json", core, readable=True)
        _save(state_dir / "callback.json", callback, readable=True)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise ValueError("Recorded graph binding refused") from None
