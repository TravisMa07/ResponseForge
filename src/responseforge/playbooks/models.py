"""Frozen internal playbook step envelopes; caller inputs never select an action."""

from typing import Literal, Self

from pydantic import model_validator

from responseforge.contracts import (
    ActionExecution,
    ActionType,
    Contract,
    Id,
    Sha256,
    UtcDateTime,
)
from responseforge.integrations.shuffle.models import ShuffleArgument, UUIDString

PlaybookKind = Literal["process", "persistence", "containment"]


class PlaybookStepRequest(ShuffleArgument):
    workflow_id: UUIDString


class Assessment(Contract):
    kind: PlaybookKind
    disposition: Literal["propose", "escalate", "no_action"]
    action: ActionType | None = None
    resource: Id | None = None
    rationale: Id
    event_ids: tuple[Id, ...] = ()
    known_gaps: tuple[Id, ...] = ()

    @model_validator(mode="after")
    def action_scope(self) -> Self:
        if self.disposition == "propose":
            if self.action is None or self.resource is None:
                raise ValueError("A recommendation needs an action and resource")
        elif self.action is not None or self.resource is not None:
            raise ValueError("Escalation/no-action cannot carry an executable target")
        return self


class PlaybookPlan(Contract):
    record_type: Literal["playbook_plan"] = "playbook_plan"
    request: PlaybookStepRequest
    kind: PlaybookKind
    source_sha256: Sha256
    assessment: Assessment
    evidence_refs: tuple[Id, ...]
    known_gaps: tuple[Id, ...]
    proposal_id: Id | None = None
    provider: Id
    provider_version: Id
    created_at: UtcDateTime
    readiness_event_id: Id

    @model_validator(mode="after")
    def plan_scope(self) -> Self:
        if self.kind != self.assessment.kind:
            raise ValueError("Plan and assessment kinds differ")
        if bool(self.proposal_id) != (self.assessment.disposition == "propose"):
            raise ValueError("Only a supported recommendation carries a proposal")
        if not self.evidence_refs:
            raise ValueError("A prepared plan requires source evidence")
        return self


class PlaybookProgress(Contract):
    request: PlaybookStepRequest
    kind: PlaybookKind
    status: Literal[
        "no_action",
        "awaiting_approval",
        "denied",
        "expired",
        "ready",
        "uncertain",
        "completed",
        "failed",
    ]
    proposal_id: Id | None = None
    execution: ActionExecution | None = None
