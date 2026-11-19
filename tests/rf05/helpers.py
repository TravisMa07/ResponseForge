"""Bound core worlds from original synthetic source bytes; no vendor runtime."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from responseforge.contracts import ActionType, EndpointRef
from responseforge.core import CaseService
from responseforge.integrations.mock_edr import MockResponseProvider
from responseforge.integrations.shuffle.models import (
    DeliveryRecord,
    ShuffleArgument,
    WorkflowBinding,
)
from responseforge.investigation import ReplayEvidenceProvider
from responseforge.playbooks.models import PlaybookStepRequest
from responseforge.playbooks.service import PlaybookService
from responseforge.replay import load_replay, make_alerts
from responseforge.runtime import Principal, Settings
from responseforge.storage import Store
from tests.rf02.helpers import NOW, TOKENS, Clock
from tests.rf04.helpers import RUN, WF, config

ENDPOINT = EndpointRef(endpoint_id="rf05-host", hostname="original-synthetic-host")
RESOURCES = frozenset({"process:42", "host:rf05-host"})


def event(event_id="process-1", *, artifact="process", fields=None, **changes):
    return {
        "event_id": event_id,
        "scenario_id": "rf05-original",
        "endpoint": ENDPOINT.model_dump(mode="json"),
        "observed_at": "2025-01-01T12:00:00Z",
        "artifact": artifact,
        "fields": fields
        if fields is not None
        else {
            "image": "powershell.exe",
            "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand U1lOVEhFVElD",
            "process_id": "42",
            "process_guid": "original-process-guid",
            "parent_process_guid": "unrecorded-parent",
        },
    } | changes


def source(tmp_path, records=None):
    path = tmp_path / "original.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in (records or [event()])) + "\n")
    batch = load_replay(path, source_id="rf05-original")
    alert = next(
        item
        for item in make_alerts(batch, ingested_at=NOW)
        if item.endpoint == ENDPOINT and item.scenario_id == "rf05-original"
    )
    return batch, alert


def world(tmp_path: Path, *, kind="process", records=None, fault="none", timeout=0.05):
    batch, alert = source(tmp_path, records)
    clock = Clock()
    provider = MockResponseProvider(tmp_path / "mock.sqlite", clock=clock, fault=fault)
    provider.seed_endpoint(ENDPOINT, processes=("42",))
    actors = {
        role: Principal(
            actor_id="rf05-" + role,
            roles=frozenset({role}),
            endpoint_ids=frozenset({ENDPOINT.endpoint_id}),
            actions=frozenset(ActionType),
            resources=RESOURCES,
            sources=frozenset({"replay-fixture"}) if role == "source" else frozenset(),
            human=role == "approver",
        )
        for role in TOKENS
    }
    settings = Settings(
        database_path=tmp_path / "core.sqlite",
        endpoints=(ENDPOINT,),
        credentials={TOKENS[role]: actor for role, actor in actors.items()},
        resource_allowlist={ENDPOINT.endpoint_id: RESOURCES},
        providers={provider.name: provider},
        provider_versions={provider.name: provider.version},
        provider_timeout=timeout,
        evidence_provider=ReplayEvidenceProvider(batch, clock=clock),
        replay_batch=batch,
        shuffle_config=config(),
        shuffle_bindings={WF: WorkflowBinding(version="rf05-test-v1", sha256="b" * 64)},
        playbook_bindings={WF: kind},
        playbook_actors={role: actors[role].actor_id for role in ("analyst", "executor")},
        playbook_provider=provider.name,
        revision="rf05-original-test",
        environment="offline-synthetic",
    )
    core = CaseService(Store(settings.database_path), settings, clock=clock)
    intake = core.intake(alert, actors["source"])
    core.register_workflow(intake.incident_id, RUN, WF, "rf05-test-v1", actors["analyst"])
    argument = ShuffleArgument(
        incident_id=intake.incident_id,
        run_id=RUN,
        correlation_id=intake.correlation_id,
        mode="replay",
    )
    delivery = DeliveryRecord(
        argument=argument,
        workflow_id=WF,
        workflow_version="rf05-test-v1",
        workflow_sha256="b" * 64,
        origin=settings.shuffle_config.base_url,
        state="accepted",
        created_at=clock(),
        updated_at=clock(),
    )
    with core.store.transaction() as tx:
        tx.insert("callbacks", "shuffle:" + RUN, delivery.model_dump(mode="json"))
    request = PlaybookStepRequest(**argument.model_dump(mode="json"), workflow_id=WF)
    return SimpleNamespace(
        core=core,
        service=PlaybookService(core),
        settings=settings,
        clock=clock,
        actors=actors,
        provider=provider,
        batch=batch,
        alert=alert,
        incident_id=intake.incident_id,
        request=request,
    )


def reopened(w, **changes):
    settings = replace(w.settings, **changes)
    core = CaseService(Store(settings.database_path), settings, clock=w.clock)
    return PlaybookService(core)


def effects(w):
    return w.provider.snapshot(ENDPOINT)["effect_count"]
