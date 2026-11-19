"""Start the local internal API with explicit private configuration."""

import argparse
import asyncio
import json
import os
import secrets
import sqlite3
from pathlib import Path

import uvicorn
from pydantic import Field, SecretStr, ValidationError

from responseforge.contracts import ActionType, Contract, EndpointRef, Id, Mode, Sha256
from responseforge.integrations.shuffle.models import ShuffleConfig, ShuffleError, WorkflowBinding
from responseforge.integrations.wazuh.models import WazuhConfig
from responseforge.playbooks.models import PlaybookKind
from responseforge.providers import EvidenceProvider, ResponseProvider
from responseforge.recorded_contracts import RecordedConfig, recorded_provider_name
from responseforge.replay_contracts import ReplayBatch
from responseforge.runtime import Principal, Settings


class ActorConfig(Contract):
    actor_id: Id
    roles: tuple[Id, ...]
    endpoint_ids: tuple[Id, ...]
    actions: tuple[ActionType, ...]
    resources: tuple[Id, ...]
    sources: tuple[Id, ...] = ()
    human: bool = False


class ShuffleFileConfig(Contract):
    base_url: Id = Field(repr=False)
    api_key: SecretStr = Field(repr=False)
    workflow_bindings: dict[str, WorkflowBinding]
    timeout: float = 5.0
    allow_loopback_http: bool = False
    ca_file: str | None = Field(default=None, repr=False)
    org_id: str | None = None


class ReplayPlaybookFileConfig(Contract):
    source_path: str
    source_id: Id
    source_sha256: Sha256
    mock_path: str
    bindings: dict[str, PlaybookKind]
    actors: dict[str, Id]


class FileConfig(Contract):
    database_path: str
    mode: Mode = Mode.REPLAY
    endpoints: tuple[EndpointRef, ...]
    credentials: dict[str, ActorConfig]
    resource_allowlist: dict[str, tuple[Id, ...]]
    revision: Id = "development"
    environment: Id = "local"
    shuffle: ShuffleFileConfig | None = None
    playbooks: ReplayPlaybookFileConfig | None = None
    recorded: RecordedConfig | None = None
    wazuh: WazuhConfig | None = None


def load_settings(path: Path) -> Settings:
    config = FileConfig.model_validate_json(path.read_text())
    principals = {
        token: Principal(
            actor_id=actor.actor_id,
            roles=frozenset(actor.roles),
            endpoint_ids=frozenset(actor.endpoint_ids),
            actions=frozenset(actor.actions),
            resources=frozenset(actor.resources),
            sources=frozenset(actor.sources),
            human=actor.human,
        )
        for token, actor in config.credentials.items()
    }
    shuffle = config.shuffle
    shuffle_config = (
        None
        if shuffle is None
        else ShuffleConfig(
            base_url=shuffle.base_url,
            api_key=shuffle.api_key.get_secret_value(),
            workflow_ids=frozenset(shuffle.workflow_bindings),
            timeout=shuffle.timeout,
            allow_loopback_http=shuffle.allow_loopback_http,
            ca_file=shuffle.ca_file,
            org_id=shuffle.org_id,
        )
    )
    # The only file-enabled provider is an explicit replay-only fixed mock.
    providers: dict[str, ResponseProvider] = {}
    versions: dict[str, str] = {}
    evidence_provider: EvidenceProvider | None = None
    batch: ReplayBatch | None = None
    domain = config.playbooks
    recorded_batches: tuple[ReplayBatch, ...] = ()
    recorded_config = config.recorded
    if recorded_config is not None:
        from responseforge.replay.registry import load_recorded_sources
        if (
            config.mode != Mode.REPLAY or domain is None
            or Path(recorded_config.mock_path).resolve() in {
                Path(config.database_path).resolve(), Path(domain.mock_path).resolve()
            }
            or Path(recorded_config.mock_path).resolve().is_relative_to(
                Path(recorded_config.bundle_root).resolve()
            )
            or Path(recorded_config.mock_path).is_symlink()
            or any(parent.is_symlink() for parent in Path(recorded_config.mock_path).absolute().parents)
        ):
            raise ValueError("Recorded mock/source configuration is not isolated")
        recorded_batches = load_recorded_sources(recorded_config, mode=config.mode)
    if domain is not None:
        from responseforge.integrations.mock_edr import MockResponseProvider
        from responseforge.investigation import ReplayEvidenceProvider
        from responseforge.replay import load_replay
        from responseforge.replay_driver import _pid

        source = Path(domain.source_path)
        if (
            config.mode != Mode.REPLAY
            or shuffle is None
            or Path(domain.mock_path).resolve() == Path(config.database_path).resolve()
            or source.is_symlink()
            or source.stat().st_size > 4 * 1048576
        ):
            raise ValueError("Unqualified playbook replay configuration")
        batch = load_replay(source, source_id=domain.source_id)
        if batch.sha256 != domain.source_sha256 or batch.quarantine or not batch.events:
            raise ValueError("Playbook source hash or records are invalid")
        registered = {endpoint.endpoint_id: endpoint for endpoint in config.endpoints}
        processes: dict[str, set[str]] = {}
        for event in batch.events:
            if registered.get(event.endpoint.endpoint_id) != event.endpoint:
                raise ValueError("Playbook source endpoint is not configured")
            processes.setdefault(event.endpoint.endpoint_id, set())
            pid = _pid(event.fields.get("process_id")) if event.artifact == "process" else None
            if pid is not None:
                processes[event.endpoint.endpoint_id].add(pid)
        if recorded_batches:
            from responseforge.replay.registry import ReplayRegistry
            ReplayRegistry((batch,) + recorded_batches)
            for source_batch in recorded_batches:
                for event in source_batch.events:
                    if registered.get(event.endpoint.endpoint_id) != event.endpoint:
                        raise ValueError("Recorded endpoint is not explicitly configured")
        adapter = MockResponseProvider(domain.mock_path)
        for identity, pids in processes.items():
            adapter.seed_endpoint(registered[identity], processes=tuple(sorted(pids)))
        providers = {adapter.name: adapter}
        versions = {adapter.name: adapter.version}
        evidence_provider = ReplayEvidenceProvider(batch)
    if recorded_config is not None:
        from responseforge.replay.registry import RecordedMockResponseProvider, ReplayRegistry
        from responseforge.replay_driver import _pid
        assert batch is not None
        source_processes: dict[str, set[str]] = {}
        endpoint_values = {endpoint.endpoint_id: endpoint for endpoint in config.endpoints}
        for source_batch in recorded_batches:
            for event in source_batch.events:
                source_processes.setdefault(event.endpoint.endpoint_id, set())
                pid = _pid(event.fields.get("process_id")) if (
                    event.artifact == "process" and event.fields.get("event_kind") == "process_create"
                ) else None
                if pid is not None:
                    source_processes[event.endpoint.endpoint_id].add(pid)
        recorded_adapter = RecordedMockResponseProvider(recorded_config.mock_path)
        recorded_adapter.name = recorded_provider_name(recorded_config)
        for identity, pids in source_processes.items():
            recorded_adapter.seed_endpoint(endpoint_values[identity], processes=tuple(sorted(pids)))
        providers[recorded_adapter.name] = recorded_adapter
        versions[recorded_adapter.name] = recorded_adapter.version
        evidence_provider = ReplayRegistry((batch,) + recorded_batches)
    return Settings(
        database_path=config.database_path,
        wazuh=config.wazuh,
        mode=config.mode,
        endpoints=config.endpoints,
        credentials=principals,
        resource_allowlist={k: frozenset(v) for k, v in config.resource_allowlist.items()},
        revision=config.revision,
        environment=config.environment,
        shuffle_config=shuffle_config,
        shuffle_bindings={} if shuffle is None else shuffle.workflow_bindings,
        providers=providers,
        provider_versions=versions,
        evidence_provider=evidence_provider,
        replay_batch=batch,
        replay_sources=recorded_batches,
        recorded_playbook_provider=recorded_adapter.name if recorded_batches else None,
        playbook_bindings={} if domain is None else dict(domain.bindings),
        playbook_actors={} if domain is None else domain.actors,
        playbook_provider=None if domain is None else "mock-edr",
    )


def write_initial_config(path: Path) -> None:
    actors = {}
    for role in ("source", "analyst", "approver", "executor", "workflow"):
        actors[secrets.token_urlsafe(32)] = {
            "actor_id": f"local-{role}",
            "roles": [role],
            "endpoint_ids": ["synthetic-host"],
            "actions": ["test_marker"],
            "resources": ["marker:demo"],
            "sources": ["synthetic-fixture"] if role == "source" else [],
            "human": role == "approver",
        }
    content = {
        "database_path": ".local/responseforge.sqlite3",
        "mode": "replay",
        "endpoints": [{"endpoint_id": "synthetic-host", "hostname": "lab-example"}],
        "credentials": actors,
        "resource_allowlist": {"synthetic-host": ["marker:demo"]},
        "revision": "development",
        "environment": "local",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite existing credentials, and never print them to the terminal.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(content, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Private JSON config (never commit)")
    parser.add_argument("--init-config", type=Path, help="Generate a new private replay config")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--export-openapi", type=Path, help="Write OpenAPI without starting a server"
    )
    parser.add_argument("--replay", type=Path, help="Original local JSON/JSONL replay fixture")
    parser.add_argument("--source-id", default="local-original-fixture")
    parser.add_argument("--database", type=Path, default=Path(".local/replay-cases.sqlite3"))
    parser.add_argument("--mock-database", type=Path, default=Path(".local/replay-mock.sqlite3"))
    parser.add_argument("--output-dir", type=Path, default=Path("reports/replay"))
    parser.add_argument("--decision", choices=("none", "approve", "reject"), default="none")
    parser.add_argument("--speed", type=float, default=0)
    args = parser.parse_args()
    if args.replay is not None:
        if (
            args.config is not None
            or args.init_config is not None
            or args.export_openapi is not None
        ):
            parser.error("replay and server/config commands are separate explicit modes")
        from responseforge.replay import load_replay
        from responseforge.replay_driver import run_replay
        from responseforge.storage import StorageError

        try:
            batch = load_replay(args.replay, source_id=args.source_id)
            if not batch.events:
                print(
                    json.dumps(
                        {
                            "simulated": True,
                            "verified_live": False,
                            "incident_ids": [],
                            "quarantine": [x.model_dump(mode="json") for x in batch.quarantine],
                        }
                    )
                )
                parser.exit(2, "No valid replay events; no case or response created.\n")
            result = asyncio.run(
                run_replay(
                    batch,
                    database_path=args.database,
                    mock_path=args.mock_database,
                    output_dir=args.output_dir,
                    decision=args.decision,
                    speed=args.speed,
                )
            )
        except (OSError, ValueError, sqlite3.Error, StorageError):
            parser.exit(
                2,
                "Offline replay failed; inspect private state before retrying. No live fallback.\n",
            )
        print(result.model_dump_json())
        return 0

    if args.init_config:
        try:
            write_initial_config(args.init_config)
        except OSError:
            parser.exit(2, "Cannot create config; existing files are never overwritten.\n")
        print(f"Created private replay configuration at {args.init_config}")
        return 0
    if args.config is None:
        parser.error("--config is required to run the API or export OpenAPI")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        settings = load_settings(args.config)
    except (OSError, ValueError, ValidationError, ShuffleError):
        parser.exit(2, "Invalid or unreadable private configuration.\n")
    from responseforge.api import create_app

    app = create_app(settings)
    if args.export_openapi:
        args.export_openapi.parent.mkdir(parents=True, exist_ok=True)
        args.export_openapi.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")
        return 0
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
