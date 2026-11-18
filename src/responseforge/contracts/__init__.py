"""Version 1 immutable wire contracts for the shared replay/live core."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    model_validator,
)


def _identity(value: str) -> str:
    if value != value.strip():
        raise ValueError("identity must not have leading or trailing whitespace")
    return value


def _timestamp_input(value: object) -> object:
    if isinstance(value, str):
        # Pydantic otherwise also accepts numeric strings as Unix epochs.
        return datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        raise ValueError("timestamp must be an aware datetime or ISO timestamp")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must have a timezone")
    return value.astimezone(UTC)


Id = Annotated[str, StringConstraints(strict=True, min_length=1), AfterValidator(_identity)]
UtcDateTime = Annotated[datetime, BeforeValidator(_timestamp_input), AfterValidator(_utc)]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]


class Mode(StrEnum):
    REPLAY = "replay"
    LIVE = "live"


class IncidentStatus(StrEnum):
    RECEIVED = "RECEIVED"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    RESPONDING = "RESPONDING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    CLOSED = "CLOSED"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(StrEnum):
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_INDICATOR = "block_indicator"
    ISOLATE_HOST = "isolate_host"
    UNISOLATE_HOST = "unisolate_host"
    DISABLE_PERSISTENCE = "disable_persistence"
    TEST_MARKER = "test_marker"


class Risk(StrEnum):
    NON_DISRUPTIVE = "non_disruptive"
    DISRUPTIVE = "disruptive"


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"


class EndpointRef(Contract):
    endpoint_id: Id
    hostname: Id
    agent_id: Id | None = None


class Provenance(Contract):
    source: Id
    source_ref: Id
    sha256: Sha256
    original_event_ids: tuple[Id, ...] = Field(min_length=1)


class Alert(Contract):
    alert_id: Id
    mode: Mode
    source: Id
    scenario_id: Id
    endpoint: EndpointRef
    event_time: UtcDateTime
    ingested_at: UtcDateTime
    rule_id: Id
    severity: Severity
    provenance: Provenance
    evidence_refs: tuple[Id, ...] = ()

    @property
    def dedup_identity(self) -> tuple[Mode, str, str, str]:
        """Source identities cannot collide across modes or scenarios."""
        return self.mode, self.source, self.scenario_id, self.alert_id


class Incident(Contract):
    incident_id: Id
    alert_id: Id
    mode: Mode
    scenario_id: Id
    endpoint: EndpointRef
    status: IncidentStatus = IncidentStatus.RECEIVED
    priority: Severity
    assessment: Id
    created_at: UtcDateTime


class Evidence(Contract):
    evidence_id: Id
    incident_id: Id
    mode: Mode
    endpoint: EndpointRef
    observed_at: UtcDateTime | None
    collected_at: UtcDateTime
    availability: Literal["available", "unavailable"]
    provenance: Provenance | None
    unavailable_reason: Id | None
    classification: Literal["public", "sensitive"] = "sensitive"

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.availability == "available":
            if self.observed_at is None or self.provenance is None:
                raise ValueError("available evidence requires observed time and provenance")
            if self.unavailable_reason is not None:
                raise ValueError("available evidence cannot have an unavailable reason")
        elif self.unavailable_reason is None or self.provenance is not None:
            raise ValueError("unavailable evidence requires a reason and cannot have provenance")
        return self


class Enrichment(Contract):
    enrichment_id: Id
    incident_id: Id
    indicator: Id
    provider: Id
    queried_at: UtcDateTime
    status: Literal["success", "unavailable", "timeout", "failed"]
    result: str | None = None
    error: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.status == "success":
            if self.result is None or not self.result.strip():
                raise ValueError("successful enrichment requires a result")
        elif self.result is not None or self.error is None or not self.error.strip():
            raise ValueError("unsuccessful enrichment requires an error and no result")
        return self


class PlaybookRun(Contract):
    run_id: Id
    incident_id: Id
    workflow_id: Id
    workflow_version: Id
    correlation_id: Id
    started_at: UtcDateTime
    ended_at: UtcDateTime | None = None
    status: Literal["running", "succeeded", "failed", "timeout"]

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if (self.status == "running") != (self.ended_at is None):
            raise ValueError("only running playbooks have no end time")
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("playbook end precedes start")
        return self


class ActionTarget(Contract):
    endpoint: EndpointRef
    resource: Id


class ActionProposal(Contract):
    proposal_id: Id
    incident_id: Id
    mode: Mode
    target: ActionTarget
    action: ActionType
    rationale: Id
    risk: Risk
    created_at: UtcDateTime
    expires_at: UtcDateTime
    idempotency_key: Id

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        ttl = self.expires_at - self.created_at
        if not timedelta(0) < ttl <= timedelta(hours=1):
            raise ValueError("proposal TTL must be positive and at most one hour")
        if self.action != ActionType.TEST_MARKER and self.risk != Risk.DISRUPTIVE:
            raise ValueError("only test_marker may be non-disruptive")
        return self


class Approval(Contract):
    approval_id: Id
    proposal: ActionProposal
    approver_id: Id
    decision: Literal["approved", "rejected", "cancelled"]
    decided_at: UtcDateTime
    expires_at: UtcDateTime

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if self.decided_at < self.proposal.created_at:
            raise ValueError("approval decision precedes proposal creation")
        if not self.decided_at < self.expires_at <= self.proposal.expires_at:
            raise ValueError("approval expiry must follow decision and fit within proposal expiry")
        return self


class ActionCapability(Contract):
    provider: Id
    provider_version: Id
    mode: Mode
    action: ActionType


class VerificationResult(Contract):
    status: Literal["pending", "verified", "failed", "timeout", "unsupported"]
    simulated: StrictBool
    verified_live: StrictBool
    checked_at: UtcDateTime | None = None
    detail: Id

    @model_validator(mode="after")
    def validate_claim(self) -> Self:
        if self.simulated and self.verified_live:
            raise ValueError("simulation cannot establish live verification")
        if self.verified_live and self.status != "verified":
            raise ValueError("live proof requires verified status")
        if self.status == "verified" and self.checked_at is None:
            raise ValueError("verified effect requires a check time")
        return self


class ActionExecution(Contract):
    execution_id: Id
    proposal_id: Id
    incident_id: Id
    provider: Id
    mode: Mode
    dispatch_state: Literal["pending", "dispatched", "acknowledged", "uncertain", "failed"]
    requested_at: UtcDateTime
    updated_at: UtcDateTime
    verification: VerificationResult
    error: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.updated_at < self.requested_at:
            raise ValueError("execution update precedes request")
        if self.mode == Mode.REPLAY:
            if not self.verification.simulated or self.verification.verified_live:
                raise ValueError("replay execution must be simulated without live proof")
        elif self.verification.simulated:
            raise ValueError("live execution cannot substitute simulation")
        if self.verification.status == "verified" and self.dispatch_state != "acknowledged":
            raise ValueError("verified effect requires acknowledged dispatch")
        if self.dispatch_state in {"uncertain", "failed"} and (
            self.error is None or not self.error.strip()
        ):
            raise ValueError("uncertain or failed dispatch requires an error")
        return self


class AuditEvent(Contract):
    event_id: Id
    incident_id: Id
    correlation_id: Id
    actor: Id
    operation: Id
    occurred_at: UtcDateTime
    detail: Id


class CaseReadiness(Contract):
    evidence_refs: tuple[Id, ...] = Field(min_length=1)
    known_gaps: tuple[Id, ...]
    proposal_ids: tuple[Id, ...]
    no_action_reason: Id | None = None
    audit_event_id: Id

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if bool(self.proposal_ids) == (self.no_action_reason is not None):
            raise ValueError("ready case requires either proposals or a no-action reason")
        return self


class MetricEvent(Contract):
    event_id: Id
    kind: Literal["alert_accepted", "case_ready"]
    incident_id: Id
    alert_id: Id
    correlation_id: Id
    scenario_id: Id
    mode: Mode
    revision: Id
    environment: Id
    occurred_at: UtcDateTime
    readiness: CaseReadiness | None = None

    @model_validator(mode="after")
    def validate_readiness(self) -> Self:
        if (self.kind == "case_ready") != (self.readiness is not None):
            raise ValueError("readiness is required only for case_ready events")
        return self


class CollectionRequest(Contract):
    incident_id: Id
    mode: Mode
    scenario_id: Id
    endpoint: EndpointRef
    start: UtcDateTime
    end: UtcDateTime
    artifact: Literal["process", "network", "file", "persistence"]

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if not timedelta(0) <= self.end - self.start <= timedelta(hours=24):
            raise ValueError("collection window must be ordered and at most 24 hours")
        return self


class CollectionResult(Contract):
    evidence: tuple[Evidence, ...]
    gaps: tuple[Id, ...]


class ApprovedAction(Contract):
    """Internal carrier; constructing this model does not authorize dispatch."""

    proposal: ActionProposal
    approval: Approval
