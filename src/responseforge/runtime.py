"""Trusted server settings and internal HTTP envelopes, separate from vendor schemas."""

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import StrictBool

from responseforge.contracts import (
    ActionExecution,
    ActionProposal,
    ActionType,
    Approval,
    Contract,
    EndpointRef,
    Id,
    IncidentStatus,
    Mode,
    UtcDateTime,
)
from responseforge.providers import ResponseProvider


@dataclass(frozen=True)
class Principal:
    actor_id: str
    roles: frozenset[str]
    endpoint_ids: frozenset[str]
    actions: frozenset[ActionType]
    resources: frozenset[str]
    sources: frozenset[str] = frozenset()
    human: bool = False

    def __post_init__(self) -> None:
        if not self.actor_id or self.actor_id != self.actor_id.strip():
            raise ValueError("actor_id must be a nonempty canonical identity")
        if not self.roles <= {"source", "analyst", "approver", "executor", "workflow"}:
            raise ValueError("unknown role")
        if type(self.human) is not bool:
            raise ValueError("human must be boolean")
        for name in ("roles", "endpoint_ids", "actions", "resources", "sources"):
            object.__setattr__(self, name, frozenset(getattr(self, name)))
        object.__setattr__(self, "actions", frozenset(ActionType(x) for x in self.actions))


@dataclass(frozen=True)
class Settings:
    database_path: str | Path
    mode: Mode = Mode.REPLAY
    endpoints: tuple[EndpointRef, ...] = ()
    credentials: dict[str, Principal] = field(default_factory=dict, repr=False)
    resource_allowlist: dict[str, frozenset[str]] = field(default_factory=dict)
    providers: dict[str, ResponseProvider] = field(default_factory=dict, repr=False)
    provider_versions: dict[str, str] = field(default_factory=dict)
    live_dispatch_enabled: bool = False
    provider_timeout: float = 5.0
    revision: str = "development"
    environment: str = "local"

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", Mode(self.mode))
        endpoints = tuple(
            EndpointRef.model_validate(x.model_dump(mode="json")) for x in self.endpoints
        )
        if len({x.endpoint_id for x in endpoints}) != len(endpoints):
            raise ValueError("duplicate configured endpoint identity")
        object.__setattr__(self, "endpoints", endpoints)
        if any(not isinstance(token, str) or len(token) < 32 for token in self.credentials):
            raise ValueError("credentials must be at least 32 characters")
        actors = [x.actor_id for x in self.credentials.values()]
        if len(set(actors)) != len(actors):
            raise ValueError("duplicate configured actor identity")
        if not math.isfinite(self.provider_timeout) or self.provider_timeout <= 0:
            raise ValueError("provider_timeout must be positive and finite")
        if type(self.live_dispatch_enabled) is not bool:
            raise ValueError("live_dispatch_enabled must be boolean")
        if not self.revision.strip() or not self.environment.strip():
            raise ValueError("revision and environment required")
        if set(self.providers) != set(self.provider_versions):
            raise ValueError("every configured provider must have exactly one pinned version")
        if any(not x or x != x.strip() for x in self.provider_versions.values()):
            raise ValueError("provider version must be a nonempty identity")
        object.__setattr__(self, "credentials", dict(self.credentials))
        object.__setattr__(self, "providers", dict(self.providers))
        object.__setattr__(self, "provider_versions", dict(self.provider_versions))
        object.__setattr__(
            self,
            "resource_allowlist",
            {key: frozenset(value) for key, value in self.resource_allowlist.items()},
        )


class IntakeResult(Contract):
    incident_id: Id
    duplicate: StrictBool
    correlation_id: Id


class ActionView(Contract):
    proposal: ActionProposal
    approval: Approval | None = None
    execution: ActionExecution | None = None


class TransitionRequest(Contract):
    status: IncidentStatus
    reviewed: StrictBool = False


class DecisionRequest(Contract):
    expires_at: UtcDateTime


class ExecuteRequest(Contract):
    provider: Id


class WorkflowRegistration(Contract):
    run_id: Id
    workflow_id: Id
    workflow_version: Id


class WorkflowCallback(Contract):
    run_id: Id
    incident_id: Id
    workflow_id: Id
    correlation_id: Id
    status: Literal["succeeded", "failed", "timeout"]
