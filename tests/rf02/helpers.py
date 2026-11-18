"""Synthetic RF-02 fixtures; controlled effects never imply vendor/live proof."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from responseforge.contracts import (
    ActionCapability,
    ActionExecution,
    ActionProposal,
    ActionType,
    Alert,
    ApprovedAction,
    EndpointRef,
    IncidentStatus,
    Mode,
    VerificationResult,
)
from responseforge.core import CaseService
from responseforge.runtime import Principal, Settings
from responseforge.storage import Store

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
ENDPOINT = EndpointRef(endpoint_id="lab-1", hostname="synthetic-host", agent_id="agent-1")
ACTIONS = frozenset(ActionType)
RESOURCES = frozenset({"process:42", "host:lab-1", "marker:rf-test"})
TOKENS = {
    role: f"synthetic-{role}-credential-".ljust(48, "x")
    for role in ("source", "analyst", "approver", "executor", "workflow")
}


def principal(role: str, **changes: Any) -> Principal:
    return Principal(
        **(
            {
                "actor_id": role + "-actor",
                "roles": frozenset({role}),
                "endpoint_ids": frozenset({ENDPOINT.endpoint_id}),
                "actions": ACTIONS,
                "resources": RESOURCES,
                "sources": frozenset({"synthetic", "other-synthetic"}),
                "human": role == "approver",
            }
            | changes
        )
    )


@dataclass
class Clock:
    now: datetime = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


class SimulatedCrash(BaseException):
    """Controlled crash bypasses ordinary exception handling, no real process exit."""


class ControlledProvider:
    def __init__(self, clock: Clock, *, mode: Mode = Mode.REPLAY) -> None:
        self.clock = clock
        self.mode = mode
        self.name = "controlled"
        self.version = "test-v1"
        self.capability_calls = 0
        self.execute_calls = 0
        self.verify_calls = 0
        self.effect_count = 0
        self.execute_behavior = "success"
        self.verify_behavior = "success"
        self.capability_changes: dict[str, Any] = {}
        self.result_changes: dict[str, Any] = {}
        self.effect_ids: set[str] = set()
        self.started: asyncio.Event | None = None
        self.release: asyncio.Event | None = None
        self.store_path: Path | None = None

    async def capabilities(self, endpoint: EndpointRef) -> tuple[ActionCapability, ...]:
        self.capability_calls += 1
        return tuple(
            ActionCapability.model_validate(
                {
                    "provider": self.name,
                    "provider_version": self.version,
                    "mode": self.mode,
                    "action": action,
                }
                | self.capability_changes
            )
            for action in ActionType
        )

    async def execute(self, action: ApprovedAction) -> ActionExecution:
        self.execute_calls += 1
        if self.store_path is not None:
            # A separate connection can observe committed reservation before effect.
            with Store(self.store_path).transaction() as tx:
                saved = tx.get("executions", action.proposal.proposal_id)
                assert saved is not None
                assert saved["dispatch_state"] == "pending"
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            await self.release.wait()
        if self.execute_behavior == "crash_before_effect":
            raise SimulatedCrash("after durable reservation, before effect")
        if self.execute_behavior == "error_before_effect":
            raise RuntimeError("SECRET-provider-token-before-effect")
        self.effect_count += 1
        self.effect_ids.add(action.proposal.proposal_id)
        if self.execute_behavior == "effect_then_error":
            raise RuntimeError("SECRET-provider-token-after-effect")
        if self.execute_behavior == "effect_then_crash":
            raise SimulatedCrash("effect accepted, acknowledgement lost")
        if self.execute_behavior == "effect_then_timeout":
            await asyncio.Event().wait()
        proof = self._verification("pending")
        if self.execute_behavior == "claimed_verified":
            proof = self._verification("verified")
        return ActionExecution.model_validate(
            {
                "execution_id": "exec-" + action.proposal.proposal_id,
                "proposal_id": action.proposal.proposal_id,
                "incident_id": action.proposal.incident_id,
                "provider": self.name,
                "mode": self.mode,
                "dispatch_state": "acknowledged",
                "requested_at": self.clock(),
                "updated_at": self.clock(),
                "verification": proof,
            }
            | self.result_changes
        )

    def _verification(self, status: str) -> VerificationResult:
        return VerificationResult.model_validate(
            {
                "status": status,
                "simulated": self.mode == Mode.REPLAY,
                "verified_live": self.mode == Mode.LIVE and status == "verified",
                "checked_at": self.clock() if status != "pending" else None,
                "detail": "Controlled synthetic adapter observation",
            }
        )

    async def verify(self, execution: ActionExecution) -> VerificationResult:
        self.verify_calls += 1
        if self.verify_behavior == "error":
            raise RuntimeError("SECRET-provider-verification-token")
        if self.verify_behavior == "timeout":
            await asyncio.Event().wait()
        if self.verify_behavior == "pending":
            return self._verification("pending")
        if self.verify_behavior == "failed":
            return self._verification("failed")
        if self.verify_behavior == "old_time":
            return self._verification("verified").model_copy(
                update={"checked_at": self.clock() - timedelta(days=1)}
            )
        return self._verification(
            "verified" if execution.proposal_id in self.effect_ids else "pending"
        )


@dataclass
class World:
    settings: Settings
    service: CaseService
    clock: Clock
    provider: ControlledProvider
    actors: dict[str, Principal]

    def reopened(self, **changes: Any) -> "World":
        values = {
            "database_path": self.settings.database_path,
            "mode": self.settings.mode,
            "endpoints": self.settings.endpoints,
            "credentials": self.settings.credentials,
            "resource_allowlist": self.settings.resource_allowlist,
            "providers": self.settings.providers,
            "provider_versions": self.settings.provider_versions,
            "live_dispatch_enabled": self.settings.live_dispatch_enabled,
            "provider_timeout": self.settings.provider_timeout,
            "revision": self.settings.revision,
            "environment": self.settings.environment,
        } | changes
        config = Settings(**values)
        return World(
            config,
            CaseService(Store(config.database_path), config, clock=self.clock),
            self.clock,
            self.provider,
            self.actors,
        )


def world(path: Path, *, mode: Mode = Mode.REPLAY, timeout: float = 0.05) -> World:
    clock = Clock()
    adapter = ControlledProvider(clock, mode=mode)
    actors = {role: principal(role) for role in TOKENS}
    settings = Settings(
        database_path=path,
        mode=mode,
        endpoints=(ENDPOINT,),
        credentials={TOKENS[role]: actor for role, actor in actors.items()},
        resource_allowlist={ENDPOINT.endpoint_id: RESOURCES},
        providers={"controlled": adapter},
        provider_versions={"controlled": "test-v1"},
        provider_timeout=timeout,
        revision="synthetic-rf02-test",
        environment="offline-controlled-adapter",
    )
    return World(settings, CaseService(Store(path), settings, clock=clock), clock, adapter, actors)


def alert(**changes: Any) -> Alert:
    return Alert.model_validate(
        {
            "alert_id": "synthetic-alert-1",
            "mode": "replay",
            "source": "synthetic",
            "scenario_id": "synthetic-scenario",
            "endpoint": ENDPOINT,
            "event_time": NOW - timedelta(days=10),
            "ingested_at": NOW - timedelta(days=1),
            "rule_id": "rule-synthetic",
            "severity": "high",
            "provenance": {
                "source": "synthetic",
                "source_ref": "fixture:rf02-original",
                "sha256": "a" * 64,
                "original_event_ids": ["synthetic-event-1"],
            },
        }
        | changes
    )


def prepared(w: World, *, action: str = "terminate_process", suffix: str = "1") -> ActionProposal:
    result = w.service.intake(
        alert(alert_id="alert-" + suffix, mode=w.settings.mode), w.actors["source"]
    )
    w.service.transition(result.incident_id, IncidentStatus.TRIAGING, w.actors["analyst"])
    w.service.transition(result.incident_id, IncidentStatus.INVESTIGATING, w.actors["analyst"])
    proposed = ActionProposal.model_validate(
        {
            "proposal_id": "proposal-" + suffix,
            "incident_id": result.incident_id,
            "mode": w.settings.mode,
            "target": {"endpoint": ENDPOINT, "resource": "process:42"},
            "action": action,
            "rationale": "Synthetic incident proposal",
            "risk": "disruptive",
            "created_at": w.clock(),
            "expires_at": w.clock() + timedelta(minutes=30),
            "idempotency_key": "effect-key-" + suffix,
        }
    )
    return w.service.propose(result.incident_id, proposed, w.actors["analyst"])


def approved(w: World, **kwargs: Any) -> ActionProposal:
    proposed = prepared(w, **kwargs)
    w.service.decide(
        proposed.proposal_id, "approved", w.clock() + timedelta(minutes=20), w.actors["approver"]
    )
    return proposed
