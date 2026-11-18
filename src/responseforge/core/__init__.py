"""Durable case operations and conservative response dispatch recovery."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import uuid4

from pydantic import ValidationError

from responseforge.contracts import (
    ActionCapability,
    ActionExecution,
    ActionProposal,
    ActionType,
    Alert,
    Approval,
    AuditEvent,
    CaseReadiness,
    Contract,
    Evidence,
    Incident,
    IncidentStatus,
    MetricEvent,
    Mode,
    PlaybookRun,
    VerificationResult,
)
from responseforge.policy import (
    AuthorizationContext,
    PolicyError,
    validate_approval,
    validate_transition,
)
from responseforge.runtime import ActionView, IntakeResult, Principal, Settings, WorkflowCallback
from responseforge.storage import ConflictError, Store, Transaction

T = TypeVar("T", bound=Contract)


class ServiceError(Exception):
    """A deliberately sanitized boundary error."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _dump(value: Contract) -> dict[str, Any]:
    return value.model_dump(mode="json", warnings="none")


def _validated(model: type[T], value: T) -> T:
    try:
        return model.model_validate(_dump(value))
    except (ValidationError, ValueError, TypeError) as exc:
        raise ServiceError(422, "Invalid input contract") from exc


def _read(model: type[T], value: dict[str, Any] | None) -> T:
    if value is None:
        raise ServiceError(404, "Record not found")
    try:
        return model.model_validate(value)
    except (ValidationError, ValueError, TypeError) as exc:
        raise ServiceError(409, "Stored record is invalid") from exc


class CaseService:
    def __init__(
        self, store: Store, settings: Settings, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ServiceError(503, "Server clock is invalid")
        return now.astimezone(UTC)

    def _principal(self, actor: Principal, roles: set[str]) -> None:
        configured = [p for p in self.settings.credentials.values() if p.actor_id == actor.actor_id]
        if len(configured) != 1 or configured[0] != actor or not actor.roles.intersection(roles):
            raise ServiceError(403, "Actor is not authorized")

    def _endpoint(self, endpoint: Any, actor: Principal) -> None:
        canonical = next(
            (e for e in self.settings.endpoints if e.endpoint_id == endpoint.endpoint_id), None
        )
        if canonical != endpoint or endpoint.endpoint_id not in actor.endpoint_ids:
            raise ServiceError(403, "Endpoint is not authorized")

    def _scope(self, proposal: ActionProposal, actor: Principal) -> None:
        self._endpoint(proposal.target.endpoint, actor)
        resource = proposal.target.resource
        endpoint_id = proposal.target.endpoint.endpoint_id
        if (
            proposal.mode != self.settings.mode
            or proposal.action not in actor.actions
            or resource not in actor.resources
            or resource not in self.settings.resource_allowlist.get(endpoint_id, frozenset())
        ):
            raise ServiceError(403, "Action scope is not authorized")

    def _incident(self, tx: Transaction, incident_id: str, actor: Principal) -> Incident:
        incident = _read(Incident, tx.get("incidents", incident_id))
        self._endpoint(incident.endpoint, actor)
        if incident.mode != self.settings.mode:
            raise ServiceError(409, "Case mode differs from runtime")
        return incident

    def _audit(
        self, tx: Transaction, incident_id: str, actor: Principal, operation: str, detail: str
    ) -> None:
        meta = tx.get("case_meta", incident_id) or {}
        event = AuditEvent(
            event_id=str(uuid4()),
            incident_id=incident_id,
            correlation_id=meta.get("correlation_id", "system"),
            actor=actor.actor_id,
            operation=operation,
            occurred_at=self._now(),
            detail=detail,
        )
        tx.insert("audit", event.event_id, _dump(event))

    def _proposal_case(self, proposal_id: str) -> str | None:
        # Resolve only the audit destination; this grants no read/dispatch authority.
        with self.store.transaction() as tx:
            value = tx.get("proposals", proposal_id)
        destination = None if value is None else value.get("incident_id")
        return destination if isinstance(destination, str) else None

    def _denial(self, incident_id: str | None, actor: Principal) -> None:
        if incident_id is None:
            return
        with self.store.transaction() as tx:
            if tx.get("incidents", incident_id) is not None:
                self._audit(tx, incident_id, actor, "denied", "Operation denied by policy")

    @contextmanager
    def _operation(
        self, incident_id: str | None | Callable[[], str | None], actor: Principal
    ) -> Iterator[None]:
        try:
            yield
        except ServiceError:
            self._denial(incident_id() if callable(incident_id) else incident_id, actor)
            raise
        except (ConflictError, PolicyError) as exc:
            self._denial(incident_id() if callable(incident_id) else incident_id, actor)
            raise ServiceError(409, "Operation conflicts with stored state or policy") from exc
        except ValidationError as exc:
            self._denial(incident_id() if callable(incident_id) else incident_id, actor)
            raise ServiceError(422, "Invalid input contract") from exc

    def intake(self, alert: Alert, actor: Principal) -> IntakeResult:
        with self._operation(None, actor):
            self._principal(actor, {"source"})
            alert = _validated(Alert, alert)
            self._endpoint(alert.endpoint, actor)
            if alert.source not in actor.sources or alert.mode != self.settings.mode:
                raise ServiceError(403, "Alert source or mode is not authorized")
            key = json.dumps(alert.dedup_identity, separators=(",", ":"))
            with self.store.transaction() as tx:
                existing = tx.get_key("intake", key)
                if existing is not None:
                    original = _read(Alert, tx.get("alerts", existing))
                    if original != alert:
                        raise ServiceError(409, "Alert identity has conflicting content")
                    meta = tx.get("case_meta", existing)
                    if meta is None:
                        raise ServiceError(409, "Case metadata is missing")
                    return IntakeResult(
                        incident_id=existing, duplicate=True, correlation_id=meta["correlation_id"]
                    )
                incident_id, correlation = str(uuid4()), str(uuid4())
                now = self._now()
                incident = Incident(
                    incident_id=incident_id,
                    alert_id=alert.alert_id,
                    mode=alert.mode,
                    scenario_id=alert.scenario_id,
                    endpoint=alert.endpoint,
                    priority=alert.severity,
                    assessment="Awaiting triage",
                    created_at=now,
                )
                meta = dict(
                    incident_id=incident_id,
                    alert_id=alert.alert_id,
                    correlation_id=correlation,
                    scenario_id=alert.scenario_id,
                    mode=alert.mode.value,
                )
                tx.insert("alerts", incident_id, _dump(alert))
                tx.insert("incidents", incident_id, _dump(incident))
                tx.insert("case_meta", incident_id, meta)
                if not tx.claim_key("intake", key, incident_id):
                    raise ServiceError(409, "Concurrent alert identity conflict")
                self._audit(
                    tx, incident_id, actor, "alert_accepted", "Alert accepted into durable case"
                )
                metric = MetricEvent(
                    event_id=str(uuid4()),
                    kind="alert_accepted",
                    occurred_at=now,
                    revision=self.settings.revision,
                    environment=self.settings.environment,
                    **meta,
                )
                tx.insert("metrics", metric.event_id, _dump(metric))
                return IntakeResult(
                    incident_id=incident_id, duplicate=False, correlation_id=correlation
                )

    def get_incident(self, incident_id: str, actor: Principal) -> Incident:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            with self.store.transaction() as tx:
                return self._incident(tx, incident_id, actor)

    def list_incidents(self, actor: Principal) -> tuple[Incident, ...]:
        self._principal(actor, {"analyst"})
        with self.store.transaction() as tx:
            incidents = tuple(_read(Incident, value) for value in tx.list("incidents"))
        canonical = {item.endpoint_id: item for item in self.settings.endpoints}
        return tuple(
            value
            for value in incidents
            if value.endpoint.endpoint_id in actor.endpoint_ids
            and canonical.get(value.endpoint.endpoint_id) == value.endpoint
            and value.mode == self.settings.mode
        )

    def _case_records(
        self, collection: str, model: type[T], incident_id: str, actor: Principal
    ) -> tuple[T, ...]:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            with self.store.transaction() as tx:
                self._incident(tx, incident_id, actor)
                return tuple(
                    _read(model, value)
                    for value in tx.list(collection)
                    if value.get("incident_id") == incident_id
                )

    def audit(self, incident_id: str, actor: Principal) -> tuple[AuditEvent, ...]:
        return self._case_records("audit", AuditEvent, incident_id, actor)

    def metrics(self, incident_id: str, actor: Principal) -> tuple[MetricEvent, ...]:
        return self._case_records("metrics", MetricEvent, incident_id, actor)

    def evidence(self, incident_id: str, actor: Principal) -> tuple[Evidence, ...]:
        return self._case_records("evidence", Evidence, incident_id, actor)

    def transition(
        self, incident_id: str, status: IncidentStatus, actor: Principal, *, reviewed: bool = False
    ) -> Incident:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            with self.store.transaction() as tx:
                incident = self._incident(tx, incident_id, actor)
                validate_transition(incident.status, status, reviewed=reviewed)
                if status == IncidentStatus.RESPONDING:
                    raise ServiceError(409, "Dispatch owns responding transition")
                if status == IncidentStatus.CONTAINED or (
                    status == IncidentStatus.RESOLVED
                    and incident.status == IncidentStatus.RESPONDING
                ):
                    settled = []
                    for value in tx.list("executions"):
                        execution = _read(ActionExecution, value)
                        if execution.incident_id != incident_id:
                            continue
                        proposal = _read(ActionProposal, tx.get("proposals", execution.proposal_id))
                        if execution.verification.status != "verified":
                            continue
                        if incident.mode == Mode.LIVE and not execution.verification.verified_live:
                            continue
                        if (
                            status == IncidentStatus.CONTAINED
                            and proposal.action != ActionType.ISOLATE_HOST
                        ):
                            continue
                        settled.append(execution)
                    if not settled:
                        raise ServiceError(409, "Verified effect is required")
                changed = _read(Incident, _dump(incident) | {"status": status})
                tx.replace("incidents", incident_id, _dump(changed))
                self._audit(
                    tx, incident_id, actor, "incident_transition", "Incident transition accepted"
                )
                return changed

    def propose(
        self, incident_id: str, proposal: ActionProposal, actor: Principal
    ) -> ActionProposal:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            proposal = _validated(ActionProposal, proposal)
            self._scope(proposal, actor)
            with self.store.transaction() as tx:
                incident = self._incident(tx, incident_id, actor)
                if (
                    proposal.incident_id != incident_id
                    or proposal.target.endpoint != incident.endpoint
                    or proposal.mode != incident.mode
                ):
                    raise ServiceError(409, "Proposal differs from case scope")
                old = tx.get("proposals", proposal.proposal_id)
                key = json.dumps([proposal.mode.value, proposal.idempotency_key])
                keyed = tx.get_key("action", key)
                if old is not None or keyed is not None:
                    original = _read(ActionProposal, old or tx.get("proposals", keyed or ""))
                    if original != proposal:
                        raise ServiceError(409, "Action identity has conflicting content")
                    return original
                now = self._now()
                if not proposal.created_at <= now < proposal.expires_at:
                    raise ServiceError(409, "Proposal is not currently valid")
                if incident.status not in {
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.AWAITING_APPROVAL,
                }:
                    raise ServiceError(409, "Case is not ready for an action proposal")
                tx.insert("proposals", proposal.proposal_id, _dump(proposal))
                if not tx.claim_key("action", key, proposal.proposal_id):
                    raise ServiceError(409, "Action identity conflict")
                if incident.status == IncidentStatus.INVESTIGATING:
                    changed = _read(Incident, _dump(incident) | {"status": "AWAITING_APPROVAL"})
                    tx.replace("incidents", incident_id, _dump(changed))
                self._audit(
                    tx, incident_id, actor, "action_proposed", "Scoped action proposal stored"
                )
                return proposal

    def decide(
        self, proposal_id: str, decision: str, expires_at: datetime, actor: Principal
    ) -> Approval:
        incident_id = self._proposal_case(proposal_id)
        with self._operation(lambda: incident_id, actor):
            self._principal(actor, {"approver"})
            if actor.human is not True:
                raise ServiceError(403, "Human approver is required")
            with self.store.transaction() as tx:
                proposal = _read(ActionProposal, tx.get("proposals", proposal_id))
                if proposal.proposal_id != proposal_id:
                    raise ServiceError(409, "Stored proposal identity is invalid")
                incident_id = proposal.incident_id
                self._incident(tx, incident_id, actor)
                self._scope(proposal, actor)
                old = tx.get("approvals", proposal_id)
                if old is not None:
                    original = _read(Approval, old)
                    if (
                        original.proposal != proposal
                        or original.approver_id != actor.actor_id
                        or original.decision != decision
                        or original.expires_at != expires_at
                    ):
                        raise ServiceError(409, "Approval decision is immutable")
                    return original
                now = self._now()
                if not proposal.created_at <= now < proposal.expires_at:
                    raise ServiceError(409, "Proposal is not currently valid")
                approval = Approval.model_validate(
                    dict(
                        approval_id=str(uuid4()),
                        proposal=_dump(proposal),
                        approver_id=actor.actor_id,
                        decision=decision,
                        decided_at=now,
                        expires_at=expires_at,
                    )
                )
                tx.insert("approvals", proposal_id, _dump(approval))
                self._audit(tx, incident_id, actor, "approval_decided", "Human decision stored")
                return approval

    def action(self, proposal_id: str, actor: Principal) -> ActionView:
        with self._operation(self._proposal_case(proposal_id), actor):
            self._principal(actor, {"analyst", "executor", "approver"})
            with self.store.transaction() as tx:
                proposal = _read(ActionProposal, tx.get("proposals", proposal_id))
                incident = self._incident(tx, proposal.incident_id, actor)
                self._scope(proposal, actor)
                if proposal.target.endpoint != incident.endpoint or proposal.mode != incident.mode:
                    raise ServiceError(409, "Stored proposal differs from case scope")
                approval_data, execution_data = (
                    tx.get("approvals", proposal_id),
                    tx.get("executions", proposal_id),
                )
                if proposal.proposal_id != proposal_id:
                    raise ServiceError(409, "Stored proposal identity is invalid")
                approval = None if approval_data is None else _read(Approval, approval_data)
                if approval is not None and approval.proposal != proposal:
                    raise ServiceError(409, "Stored approval scope differs from proposal")
                return ActionView(
                    proposal=proposal,
                    approval=approval,
                    execution=None
                    if execution_data is None
                    else self._bound_execution(
                        execution_data, proposal, execution_data.get("provider", "")
                    ),
                )

    def add_evidence(self, incident_id: str, item: Evidence, actor: Principal) -> Evidence:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            item = _validated(Evidence, item)
            with self.store.transaction() as tx:
                incident = self._incident(tx, incident_id, actor)
                if (
                    item.incident_id != incident_id
                    or item.mode != incident.mode
                    or item.endpoint != incident.endpoint
                ):
                    raise ServiceError(409, "Evidence differs from case scope")
                old = tx.get("evidence", item.evidence_id)
                if old is not None:
                    original = _read(Evidence, old)
                    if original != item:
                        raise ServiceError(409, "Evidence identity has conflicting content")
                    return original
                tx.insert("evidence", item.evidence_id, _dump(item))
                self._audit(tx, incident_id, actor, "evidence_added", "Evidence reference stored")
                return item

    def mark_ready(
        self, incident_id: str, readiness: CaseReadiness, actor: Principal
    ) -> MetricEvent:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            readiness = _validated(CaseReadiness, readiness)
            with self.store.transaction() as tx:
                incident = self._incident(tx, incident_id, actor)
                for ref in readiness.evidence_refs:
                    item = _read(Evidence, tx.get("evidence", ref))
                    if (
                        item.incident_id != incident_id
                        or item.mode != incident.mode
                        or item.endpoint != incident.endpoint
                        or item.availability != "available"
                    ):
                        raise ServiceError(409, "Readiness evidence is not available in this case")
                for ref in readiness.proposal_ids:
                    proposal = _read(ActionProposal, tx.get("proposals", ref))
                    if (
                        proposal.incident_id != incident_id
                        or proposal.mode != incident.mode
                        or proposal.target.endpoint != incident.endpoint
                    ):
                        raise ServiceError(409, "Readiness proposal differs from this case")
                audit = _read(AuditEvent, tx.get("audit", readiness.audit_event_id))
                if audit.incident_id != incident_id:
                    raise ServiceError(409, "Readiness audit differs from this case")
                existing_key = tx.get_key("ready", incident_id)
                if existing_key is not None:
                    existing = _read(MetricEvent, tx.get("metrics", existing_key))
                    if existing.readiness != readiness:
                        raise ServiceError(409, "Case readiness has conflicting content")
                    return existing
                meta = tx.get("case_meta", incident_id)
                if meta is None:
                    raise ServiceError(409, "Case metadata is missing")
                metric = MetricEvent(
                    event_id=str(uuid4()),
                    kind="case_ready",
                    occurred_at=self._now(),
                    revision=self.settings.revision,
                    environment=self.settings.environment,
                    readiness=readiness,
                    **meta,
                )
                tx.insert("metrics", metric.event_id, _dump(metric))
                if not tx.claim_key("ready", incident_id, metric.event_id):
                    raise ServiceError(409, "Case readiness conflict")
                self._audit(
                    tx, incident_id, actor, "case_ready", "Case review requirements recorded"
                )
                return metric

    def register_workflow(
        self,
        incident_id: str,
        run_id: str,
        workflow_id: str,
        workflow_version: str,
        actor: Principal,
    ) -> PlaybookRun:
        with self._operation(incident_id, actor):
            self._principal(actor, {"analyst"})
            with self.store.transaction() as tx:
                self._incident(tx, incident_id, actor)
                meta = tx.get("case_meta", incident_id)
                if meta is None:
                    raise ServiceError(409, "Case metadata is missing")
                old = tx.get("workflows", run_id)
                if old is not None:
                    original = _read(PlaybookRun, old)
                    if (
                        original.incident_id != incident_id
                        or original.workflow_id != workflow_id
                        or original.workflow_version != workflow_version
                        or original.correlation_id != meta["correlation_id"]
                    ):
                        raise ServiceError(409, "Workflow identity has conflicting content")
                    return original
                run = PlaybookRun(
                    run_id=run_id,
                    incident_id=incident_id,
                    workflow_id=workflow_id,
                    workflow_version=workflow_version,
                    correlation_id=meta["correlation_id"],
                    started_at=self._now(),
                    status="running",
                )
                tx.insert("workflows", run_id, _dump(run))
                self._audit(
                    tx, incident_id, actor, "workflow_registered", "Workflow correlation registered"
                )
                return run

    def callback(
        self, item: WorkflowCallback, actor: Principal, *, nonce: str, sent_at: datetime
    ) -> PlaybookRun:
        with self._operation(item.incident_id, actor):
            self._principal(actor, {"workflow"})
            item = _validated(WorkflowCallback, item)
            now = self._now()
            if (
                not nonce
                or len(nonce) > 128
                or nonce != nonce.strip()
                or sent_at.tzinfo is None
                or sent_at.utcoffset() is None
                or abs((now - sent_at).total_seconds()) > 300
            ):
                raise ServiceError(409, "Callback freshness is invalid")
            with self.store.transaction() as tx:
                self._incident(tx, item.incident_id, actor)
                run = _read(PlaybookRun, tx.get("workflows", item.run_id))
                if (
                    run.incident_id != item.incident_id
                    or run.workflow_id != item.workflow_id
                    or run.correlation_id != item.correlation_id
                ):
                    raise ServiceError(409, "Callback correlation is invalid")
                if not tx.claim_key("callback", json.dumps([actor.actor_id, nonce]), item.run_id):
                    raise ServiceError(409, "Callback nonce was already consumed")
                if run.status != "running":
                    if run.status != item.status:
                        raise ServiceError(409, "Workflow terminal outcome conflicts")
                    return run
                updated = _read(PlaybookRun, _dump(run) | {"status": item.status, "ended_at": now})
                tx.replace("workflows", run.run_id, _dump(updated))
                self._audit(
                    tx,
                    item.incident_id,
                    actor,
                    "workflow_callback",
                    "Correlated workflow result stored",
                )
                return updated

    def _approval_subject(self, approval: Approval, proposal: ActionProposal) -> Principal:
        principal = next(
            (p for p in self.settings.credentials.values() if p.actor_id == approval.approver_id),
            None,
        )
        if principal is None or principal.human is not True:
            raise ServiceError(403, "Approval subject is no longer authorized")
        self._principal(principal, {"approver"})
        self._scope(proposal, principal)
        return principal

    def _reservation(self, proposal: ActionProposal, provider: str) -> ActionExecution:
        now = self._now()
        return ActionExecution(
            execution_id="exec-" + proposal.proposal_id,
            proposal_id=proposal.proposal_id,
            incident_id=proposal.incident_id,
            provider=provider,
            mode=proposal.mode,
            dispatch_state="pending",
            requested_at=now,
            updated_at=now,
            verification=VerificationResult(
                status="pending",
                simulated=proposal.mode == Mode.REPLAY,
                verified_live=False,
                detail="Dispatch reserved; effect not yet established",
            ),
        )

    def _bound_execution(
        self, value: dict[str, Any], proposal: ActionProposal, provider: str
    ) -> ActionExecution:
        execution = _read(ActionExecution, value)
        if (
            execution.proposal_id != proposal.proposal_id
            or execution.execution_id != "exec-" + proposal.proposal_id
            or execution.incident_id != proposal.incident_id
            or execution.provider != provider
            or execution.mode != proposal.mode
        ):
            raise ServiceError(409, "Stored execution correlation is invalid")
        checked = execution.verification.checked_at
        if checked is not None and not execution.requested_at <= checked <= execution.updated_at:
            raise ServiceError(409, "Stored execution chronology is invalid")
        if (
            execution.mode == Mode.LIVE
            and execution.verification.status == "verified"
            and not execution.verification.verified_live
        ):
            raise ServiceError(409, "Stored live verification lacks proof")
        return execution

    def _dispatch_inputs(
        self, tx: Transaction, proposal_id: str, provider: str, actor: Principal
    ) -> tuple[ActionProposal, ActionExecution | None]:
        proposal = _read(ActionProposal, tx.get("proposals", proposal_id))
        if proposal.proposal_id != proposal_id:
            raise ServiceError(409, "Stored proposal identity is invalid")
        incident = self._incident(tx, proposal.incident_id, actor)
        self._scope(proposal, actor)
        if proposal.target.endpoint != incident.endpoint or proposal.mode != incident.mode:
            raise ServiceError(409, "Stored proposal differs from case scope")
        old = tx.get("executions", proposal_id)
        execution = None if old is None else self._bound_execution(old, proposal, provider)
        return proposal, execution

    def _provider(self, name: str) -> Any:
        adapter = self.settings.providers.get(name)
        if adapter is None or name not in self.settings.provider_versions:
            raise ServiceError(503, "Configured provider is unavailable")
        return adapter

    async def execute(self, proposal_id: str, provider: str, actor: Principal) -> ActionExecution:
        incident_id = self._proposal_case(proposal_id)
        try:
            self._principal(actor, {"executor"})
            with self.store.transaction() as tx:
                proposal, old = self._dispatch_inputs(tx, proposal_id, provider, actor)
                incident_id = proposal.incident_id
                if old is not None:
                    return old
            if self.settings.mode == Mode.LIVE and not self.settings.live_dispatch_enabled:
                raise ServiceError(403, "Live dispatch is disabled")
            adapter = self._provider(provider)
            try:
                raw = await asyncio.wait_for(
                    adapter.capabilities(proposal.target.endpoint),
                    timeout=self.settings.provider_timeout,
                )
                capabilities = tuple(_validated(ActionCapability, item) for item in raw)
            except Exception as exc:
                raise ServiceError(503, "Provider capability lookup failed") from exc
            selected = tuple(
                cap
                for cap in capabilities
                if cap.provider == provider
                and cap.provider_version == self.settings.provider_versions[provider]
            )
            with self.store.transaction() as tx:
                self._principal(actor, {"executor"})
                proposal, old = self._dispatch_inputs(tx, proposal_id, provider, actor)
                if old is not None:
                    return old
                incident = self._incident(tx, proposal.incident_id, actor)
                if incident.status != IncidentStatus.AWAITING_APPROVAL:
                    raise ServiceError(409, "Case is not awaiting dispatch approval")
                approval = _read(Approval, tx.get("approvals", proposal_id))
                approver = self._approval_subject(approval, proposal)
                approved = validate_approval(
                    proposal,
                    approval,
                    context=AuthorizationContext(
                        actor_id=approver.actor_id,
                        authenticated=True,
                        roles=approver.roles,
                        allowed_endpoint_ids=approver.endpoint_ids,
                        allowed_actions=approver.actions,
                    ),
                    stored_approval=approval,
                    capabilities=selected,
                    runtime_mode=self.settings.mode,
                    now=self._now(),
                )
                execution = self._reservation(proposal, provider)
                if not tx.claim_key(
                    "execution_provider_version",
                    proposal_id,
                    self.settings.provider_versions[provider],
                ):
                    raise ServiceError(409, "Original execution provider version already reserved")
                tx.insert("executions", proposal_id, _dump(execution))
                changed = _read(Incident, _dump(incident) | {"status": "RESPONDING"})
                tx.replace("incidents", incident.incident_id, _dump(changed))
                self._audit(
                    tx,
                    incident.incident_id,
                    actor,
                    "dispatch_reserved",
                    "Response delivery durably reserved",
                )
            try:
                returned = await asyncio.wait_for(
                    adapter.execute(approved), timeout=self.settings.provider_timeout
                )
                result = self._validate_execution(returned, execution)
                # Effect claims made by execute are never sufficient; verify is separate.
                result = _read(
                    ActionExecution, _dump(result) | {"verification": _dump(execution.verification)}
                )
                result = self._save_execution(result, actor, "dispatch_result")
            except Exception:
                return self._uncertain(execution, actor)
            if result.dispatch_state == "acknowledged":
                return await self._verify(result, adapter, actor)
            return result
        except ServiceError:
            self._denial(incident_id, actor)
            raise
        except (PolicyError, ConflictError) as exc:
            self._denial(incident_id, actor)
            raise ServiceError(409, "Dispatch conflicts with stored approval or policy") from exc

    def _validate_execution(
        self, result: ActionExecution, reserved: ActionExecution
    ) -> ActionExecution:
        result = _validated(ActionExecution, result)
        if any(
            getattr(result, key) != getattr(reserved, key)
            for key in ("execution_id", "proposal_id", "incident_id", "provider", "mode")
        ):
            raise ServiceError(409, "Provider result correlation is invalid")
        now = self._now()
        if not reserved.requested_at <= result.requested_at <= result.updated_at <= now:
            raise ServiceError(409, "Provider result chronology is invalid")
        checked = result.verification.checked_at
        if checked is not None and not result.requested_at <= checked <= result.updated_at:
            raise ServiceError(409, "Provider verification chronology is invalid")
        return _read(
            ActionExecution,
            _dump(result)
            | {
                "requested_at": reserved.requested_at,
                "error": "provider_reported_error" if result.error else None,
            },
        )

    def _save_execution(
        self, result: ActionExecution, actor: Principal, operation: str
    ) -> ActionExecution:
        with self.store.transaction() as tx:
            proposal = _read(ActionProposal, tx.get("proposals", result.proposal_id))
            existing_data = tx.get("executions", result.proposal_id)
            if existing_data is None:
                raise ServiceError(409, "Original execution reservation is missing")
            existing = self._bound_execution(existing_data, proposal, result.provider)
            if existing.verification.status == "verified":
                return existing
            result = self._bound_execution(
                _dump(_validated(ActionExecution, result)), proposal, result.provider
            )
            if result.requested_at != existing.requested_at or result.updated_at > self._now():
                raise ServiceError(409, "New execution chronology is invalid")
            if result.updated_at < existing.updated_at:
                return existing
            tx.replace("executions", result.proposal_id, _dump(result))
            self._audit(tx, result.incident_id, actor, operation, "Provider outcome recorded")
            incident = _read(Incident, tx.get("incidents", result.incident_id))
            target: IncidentStatus | None = None
            if result.verification.status == "verified":
                proposal = _read(ActionProposal, tx.get("proposals", result.proposal_id))
                target = (
                    IncidentStatus.CONTAINED
                    if proposal.action == ActionType.ISOLATE_HOST
                    else IncidentStatus.RESOLVED
                )
            elif result.dispatch_state == "failed" or result.verification.status in {
                "failed",
                "unsupported",
            }:
                target = IncidentStatus.FAILED
            if target is not None and incident.status == IncidentStatus.RESPONDING:
                validate_transition(incident.status, target)
                tx.replace(
                    "incidents",
                    incident.incident_id,
                    _dump(_read(Incident, _dump(incident) | {"status": target})),
                )
                self._audit(
                    tx,
                    incident.incident_id,
                    actor,
                    "incident_transition",
                    "Response outcome updated case",
                )
            return result

    def _uncertain(self, execution: ActionExecution, actor: Principal) -> ActionExecution:
        result = _read(
            ActionExecution,
            _dump(execution)
            | {
                "dispatch_state": "uncertain",
                "updated_at": self._now(),
                "error": "provider_error",
                "verification": {
                    "status": "timeout",
                    "simulated": execution.mode == Mode.REPLAY,
                    "verified_live": False,
                    "detail": "Provider outcome uncertain; reconcile before retry",
                },
            },
        )
        return self._save_execution(result, actor, "dispatch_uncertain")

    async def _verify(
        self, execution: ActionExecution, adapter: Any, actor: Principal
    ) -> ActionExecution:
        with self.store.transaction() as tx:
            self._audit(
                tx,
                execution.incident_id,
                actor,
                "verification_requested",
                "Original response effect verification requested",
            )
        try:
            value = await asyncio.wait_for(
                adapter.verify(execution), timeout=self.settings.provider_timeout
            )
            verification = _validated(VerificationResult, value)
            verification = _read(
                VerificationResult,
                _dump(verification)
                | {
                    "detail": "Provider verification outcome recorded",
                },
            )
            now = self._now()
            if (
                verification.checked_at is not None
                and not execution.requested_at <= verification.checked_at <= now
            ) or (verification.status != "pending" and verification.checked_at is None):
                raise ServiceError(409, "Verification chronology is invalid")
            if verification.simulated != (execution.mode == Mode.REPLAY) or (
                execution.mode == Mode.LIVE
                and verification.status == "verified"
                and not verification.verified_live
            ):
                raise ServiceError(409, "Verification mode proof is invalid")
            changed = _read(
                ActionExecution,
                _dump(execution)
                | {
                    "verification": _dump(verification),
                    "updated_at": now,
                    "dispatch_state": "acknowledged"
                    if verification.status == "verified"
                    else execution.dispatch_state,
                },
            )
            return self._save_execution(changed, actor, "verification_result")
        except Exception:
            now = self._now()
            fallback = VerificationResult(
                status="timeout",
                simulated=execution.mode == Mode.REPLAY,
                verified_live=False,
                detail="Verification unavailable; reconcile original execution",
            )
            changed = _read(
                ActionExecution,
                _dump(execution)
                | {
                    "verification": _dump(fallback),
                    "updated_at": now,
                },
            )
            return self._save_execution(changed, actor, "verification_unavailable")

    async def reconcile(self, proposal_id: str, provider: str, actor: Principal) -> ActionExecution:
        incident_id = self._proposal_case(proposal_id)
        try:
            self._principal(actor, {"executor"})
            with self.store.transaction() as tx:
                proposal, execution = self._dispatch_inputs(tx, proposal_id, provider, actor)
                incident_id = proposal.incident_id
                if execution is None:
                    raise ServiceError(409, "No original execution exists to reconcile")
                if execution.verification.status == "verified":
                    return execution
                original_version = tx.get_key("execution_provider_version", proposal_id)
                if (
                    original_version is None
                    or original_version != self.settings.provider_versions.get(provider)
                ):
                    raise ServiceError(409, "Original execution provider version is unavailable")
            if self.settings.mode == Mode.LIVE and not self.settings.live_dispatch_enabled:
                raise ServiceError(403, "Live reconciliation is disabled")
            adapter = self._provider(provider)
            return await self._verify(execution, adapter, actor)
        except ServiceError:
            self._denial(incident_id, actor)
            raise
