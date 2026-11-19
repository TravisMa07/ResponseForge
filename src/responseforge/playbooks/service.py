"""Bounded workflow steps reusing the core's evidence, approval and dispatch authority."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import TypeVar, cast

from responseforge.contracts import (
    ActionCapability,
    ActionProposal,
    Alert,
    CaseReadiness,
    CollectionRequest,
    Contract,
    Evidence,
    Incident,
    IncidentStatus,
    MetricEvent,
    Mode,
    PlaybookRun,
)
from responseforge.core import CaseService, ServiceError
from responseforge.integrations.shuffle.models import DeliveryRecord, ShuffleArgument
from responseforge.playbooks.assessment import assess
from responseforge.playbooks.models import (
    Assessment,
    PlaybookKind,
    PlaybookPlan,
    PlaybookProgress,
    PlaybookStepRequest,
)
from responseforge.replay import make_alerts, replay_provenance
from responseforge.replay_contracts import ReplayBatch, digest
from responseforge.runtime import Principal
from responseforge.storage import Transaction

T = TypeVar("T", bound=Contract)


def _read(model: type[T], value: object) -> T:
    try:
        return model.model_validate(value)
    except (ValueError, TypeError):
        raise ServiceError(409, "Stored playbook binding is invalid") from None


@dataclass(frozen=True)
class _Context:
    request: PlaybookStepRequest
    kind: PlaybookKind
    incident: Incident
    alert: Alert
    batch: ReplayBatch
    run: PlaybookRun
    delivery: DeliveryRecord
    analyst: Principal
    executor: Principal
    provider: str
    provider_version: str


class PlaybookService:
    def __init__(self, core: CaseService) -> None:
        self.core = core

    def _context(
        self, incident_id: str, request: PlaybookStepRequest, actor: Principal
    ) -> _Context:
        core, settings = self.core, self.core.settings
        core._principal(actor, {"workflow"})
        if actor.roles != frozenset({"workflow"}) or actor.human:
            raise ServiceError(403, "A scoped non-human workflow caller is required")
        request = _read(PlaybookStepRequest, request.model_dump(mode="json", warnings=False))
        if request.incident_id != incident_id:
            raise ServiceError(409, "Playbook path differs from request")
        if settings.mode != Mode.REPLAY or request.mode != Mode.REPLAY:
            raise ServiceError(409, "No qualified playbook source for this mode")
        if settings.shuffle_config is None or (settings.replay_batch is None and not settings.replay_sources):
            raise ServiceError(503, "Playbook source and transport are not configured")
        if settings.evidence_provider is None or (
            settings.playbook_provider is None and settings.recorded_playbook_provider is None
        ):
            raise ServiceError(503, "Playbook evidence and response providers are required")
        try:
            value = settings.playbook_bindings[request.workflow_id]
            if value not in {"process", "persistence", "containment"}:
                raise ValueError
            kind = cast(PlaybookKind, value)
            binding = settings.shuffle_bindings[request.workflow_id]
            if request.workflow_id not in settings.shuffle_config.workflow_ids:
                raise KeyError
            principals: dict[str, Principal] = {}
            for role in ("analyst", "executor"):
                identity = settings.playbook_actors[role]
                matches = [p for p in settings.credentials.values() if p.actor_id == identity]
                if len(matches) != 1:
                    raise KeyError
                principal = matches[0]
                if principal.roles != frozenset({role}) or principal.human:
                    raise KeyError
                core._principal(principal, {role})
                principals[role] = principal
        except (KeyError, ValueError, TypeError):
            raise ServiceError(
                403, "Playbook binding or technical actor is not authorized"
            ) from None
        with core.store.transaction() as tx:
            incident = core._incident(tx, incident_id, actor)
            core._endpoint(incident.endpoint, principals["analyst"])
            core._endpoint(incident.endpoint, principals["executor"])
            alert = _read(Alert, tx.get("alerts", incident_id))
            meta = tx.get("case_meta", incident_id)
            run = _read(PlaybookRun, tx.get("workflows", request.run_id))
            delivery = _read(DeliveryRecord, tx.get("callbacks", "shuffle:" + request.run_id))
        argument = ShuffleArgument.model_validate(request.model_dump(exclude={"workflow_id"}))
        now = core._now()
        if (
            incident.mode != request.mode
            or incident.alert_id != alert.alert_id
            or incident.scenario_id != alert.scenario_id
            or incident.endpoint != alert.endpoint
            or alert.mode != request.mode
            or meta is None
            or meta.get("incident_id") != incident_id
            or meta.get("alert_id") != alert.alert_id
            or meta.get("scenario_id") != alert.scenario_id
            or meta.get("mode") != request.mode.value
            or meta.get("correlation_id") != request.correlation_id
            or run.run_id != request.run_id
            or run.incident_id != incident_id
            or run.workflow_id != request.workflow_id
            or run.workflow_version != binding.version
            or run.correlation_id != request.correlation_id
            or delivery.argument != argument
            or delivery.workflow_id != request.workflow_id
            or delivery.workflow_version != binding.version
            or delivery.workflow_sha256 != binding.sha256
            or delivery.origin != settings.shuffle_config.base_url
            or not run.started_at <= delivery.created_at <= delivery.updated_at <= now
        ):
            raise ServiceError(409, "Original playbook run scope cannot change")
        try:
            batch = settings.source_for_alert(alert)
            provider = settings.provider_for_source(batch)
            if provider is None or provider not in settings.providers:
                raise ValueError("Missing source provider")
            version = settings.provider_versions[provider]
            expected = next(
                (
                    a
                    for a in make_alerts(batch, ingested_at=alert.ingested_at)
                    if a.alert_id == alert.alert_id
                ),
                None,
            )
        except (ValueError, TypeError, KeyError):
            raise ServiceError(409, "Registered playbook replay source is invalid") from None
        if expected != alert:
            raise ServiceError(409, "Playbook alert differs from registered source")
        return _Context(
            request,
            kind,
            incident,
            alert,
            batch,
            run,
            delivery,
            principals["analyst"],
            principals["executor"],
            provider,
            version,
        )

    @staticmethod
    def _active(context: _Context) -> None:
        if context.run.status != "running" or context.delivery.state in {
            "rejected",
            "finished",
            "failed",
        }:
            raise ServiceError(409, "A terminal workflow cannot authorize a new operation")

    @staticmethod
    def _proposal_id(context: _Context, decision: Assessment) -> str:
        return "proposal-" + digest(
            [
                context.incident.incident_id,
                context.kind,
                context.batch.sha256,
                decision.action.value if decision.action is not None else None,
                decision.resource,
            ]
        )

    @staticmethod
    def _unsupported(decision: Assessment) -> Assessment:
        assert decision.action is not None
        reason = "Provider does not support " + decision.action.value
        return Assessment(
            kind=decision.kind,
            disposition="escalate",
            rationale=reason,
            event_ids=decision.event_ids,
            known_gaps=tuple(sorted(set(decision.known_gaps) | {reason})),
        )

    def _cached(self, context: _Context) -> PlaybookPlan | None:
        core = self.core
        with core.store.transaction() as tx:
            value = tx.get("callbacks", "playbook-plan:" + context.request.run_id)
            if value is None:
                return None
            plan = _read(PlaybookPlan, value)
            if (
                plan.request != context.request
                or plan.kind != context.kind
                or plan.source_sha256 != context.batch.sha256
                or plan.provider != context.provider
                or plan.provider_version != context.provider_version
                or plan.created_at > core._now()
            ):
                raise ServiceError(409, "Stored playbook plan scope cannot change")
            metric = _read(MetricEvent, tx.get("metrics", plan.readiness_event_id))
            readiness = metric.readiness
            if (
                metric.event_id != plan.readiness_event_id
                or metric.kind != "case_ready"
                or metric.alert_id != context.alert.alert_id
                or metric.scenario_id != context.incident.scenario_id
                or metric.incident_id != context.incident.incident_id
                or metric.correlation_id != context.request.correlation_id
                or metric.mode != context.request.mode
                or not context.run.started_at <= plan.created_at <= core._now()
                or metric.occurred_at > plan.created_at
                or readiness is None
                or readiness.evidence_refs != plan.evidence_refs
                or readiness.known_gaps != plan.known_gaps
                or readiness.proposal_ids != ((plan.proposal_id,) if plan.proposal_id else ())
                or readiness.no_action_reason
                != (None if plan.proposal_id else plan.assessment.rationale)
            ):
                raise ServiceError(409, "Stored playbook readiness differs from the plan")
            try:
                start = context.alert.event_time - timedelta(minutes=5)
                end = context.alert.event_time + timedelta(minutes=5)
            except OverflowError:
                raise ServiceError(409, "Stored evidence window is invalid") from None
            recorded = {
                "evidence-"
                + digest(
                    [
                        context.batch.source_id,
                        context.batch.sha256,
                        context.incident.incident_id,
                        event.scenario_id,
                        event.endpoint.model_dump(mode="json"),
                        event.event_id,
                    ]
                ): event
                for event in context.batch.events
                if event.scenario_id == context.incident.scenario_id
                and event.endpoint == context.incident.endpoint
                and start <= event.observed_at <= end
            }
            if plan.evidence_refs != tuple(sorted(recorded)):
                raise ServiceError(409, "Stored evidence set differs from recorded scope")
            for ref in plan.evidence_refs:
                item = _read(Evidence, tx.get("evidence", ref))
                if (
                    item.evidence_id != ref
                    or item.incident_id != context.incident.incident_id
                    or item.mode != context.request.mode
                    or item.endpoint != context.incident.endpoint
                    or item.availability != "available"
                    or item.provenance is None
                    or item.provenance
                    != replay_provenance(context.batch, (recorded[ref].event_id,))
                    or item.observed_at != recorded[ref].observed_at
                    or item.collected_at > plan.created_at
                    or item.classification != "sensitive"
                ):
                    raise ServiceError(409, "Stored playbook evidence differs from source")
        try:
            expected = assess(context.kind, context.batch, context.alert)
        except (ValueError, TypeError):
            raise ServiceError(409, "Stored playbook assessment source is invalid") from None
        if plan.assessment != expected and (
            expected.disposition != "propose" or plan.assessment != self._unsupported(expected)
        ):
            raise ServiceError(409, "Stored playbook assessment differs from source")
        if plan.proposal_id is not None:
            if plan.proposal_id != self._proposal_id(context, plan.assessment):
                raise ServiceError(409, "Stored playbook proposal identity differs from source")
            proposal = self._proposal(context, plan.assessment, create=False)
            core._scope(proposal, context.executor)
            if proposal.created_at > metric.occurred_at:
                raise ServiceError(409, "Original proposal chronology differs from readiness")
        return plan

    def _candidate(self, context: _Context, decision: Assessment) -> ActionProposal:
        now = self.core._now()
        identity = self._proposal_id(context, decision)
        return ActionProposal(
            proposal_id=identity,
            incident_id=context.incident.incident_id,
            mode=context.request.mode,
            target={"endpoint": context.incident.endpoint, "resource": decision.resource},
            action=decision.action,
            rationale=decision.rationale,
            risk="disruptive",
            created_at=now,
            expires_at=now + timedelta(minutes=30),
            idempotency_key=identity,
        )

    def _check_supported_scope(self, context: _Context, decision: Assessment) -> None:
        if decision.disposition == "propose":
            candidate = self._candidate(context, decision)
            self.core._scope(candidate, context.analyst)
            self.core._scope(candidate, context.executor)

    def _refresh(self, original: _Context, actor: Principal) -> _Context:
        fresh = self._context(original.incident.incident_id, original.request, actor)
        if (
            fresh.provider != original.provider
            or fresh.provider_version != original.provider_version
            or fresh.kind != original.kind
            or fresh.batch != original.batch
            or fresh.alert != original.alert
        ):
            raise ServiceError(409, "Playbook configuration changed during preparation")
        return fresh

    def _proposal(self, context: _Context, decision: Assessment, *, create: bool) -> ActionProposal:
        core = self.core
        identity = self._proposal_id(context, decision)
        with core.store.transaction() as tx:
            value = tx.get("proposals", identity)
        if value is None:
            if not create:
                raise ServiceError(409, "Original playbook proposal is missing")
            proposal = self._candidate(context, decision)
            return core.propose(context.incident.incident_id, proposal, context.analyst)
        proposal = _read(ActionProposal, value)
        if (
            proposal.proposal_id != identity
            or proposal.idempotency_key != identity
            or proposal.incident_id != context.incident.incident_id
            or proposal.mode != context.request.mode
            or proposal.target.endpoint != context.incident.endpoint
            or proposal.target.resource != decision.resource
            or proposal.action != decision.action
            or proposal.rationale != decision.rationale
            or proposal.risk.value != "disruptive"
            or proposal.expires_at - proposal.created_at != timedelta(minutes=30)
        ):
            raise ServiceError(409, "Original playbook proposal content cannot change")
        core._scope(proposal, context.analyst)
        return proposal

    def _audit(self, context: _Context, actor: Principal, operation: str) -> None:
        with self.core.store.transaction() as tx:
            self.core._audit(
                tx,
                context.incident.incident_id,
                actor,
                operation,
                "Bound " + context.kind + " playbook step for run " + context.request.run_id,
            )

    async def prepare(
        self, incident_id: str, request: PlaybookStepRequest, actor: Principal
    ) -> PlaybookPlan:
        with self.core._operation(incident_id, actor):
            context = self._context(incident_id, request, actor)
            old = self._cached(context)
            if old is not None:
                return old
            self._active(context)
            try:
                decision = assess(context.kind, context.batch, context.alert)
            except (ValueError, TypeError):
                raise ServiceError(409, "Playbook assessment source is invalid") from None
            if decision.disposition == "propose":
                try:
                    adapter = self.core._provider(context.provider)
                    raw = await asyncio.wait_for(
                        adapter.capabilities(context.incident.endpoint),
                        timeout=self.core.settings.provider_timeout,
                    )
                    capabilities = tuple(
                        _read(ActionCapability, value.model_dump(mode="json", warnings=False))
                        for value in raw
                    )
                except Exception:
                    raise ServiceError(503, "Playbook capability lookup is unavailable") from None
                if not any(
                    cap.provider == context.provider
                    and cap.provider_version == context.provider_version
                    and cap.mode == context.request.mode
                    and cap.action == decision.action
                    for cap in capabilities
                ):
                    decision = self._unsupported(decision)
            # Revalidate after asynchronous reads before any evidence/proposal mutation.
            context = self._refresh(context, actor)
            self._active(context)
            self._check_supported_scope(context, decision)
            incident = self.core.get_incident(incident_id, context.analyst)
            for before, after in (
                (IncidentStatus.RECEIVED, IncidentStatus.TRIAGING),
                (IncidentStatus.TRIAGING, IncidentStatus.INVESTIGATING),
            ):
                if incident.status == before:
                    incident = self.core.transition(incident_id, after, context.analyst)
            available: set[str] = set()
            gaps = set(decision.known_gaps)
            try:
                start, end = (
                    context.alert.event_time - timedelta(minutes=5),
                    context.alert.event_time + timedelta(minutes=5),
                )
            except OverflowError:
                raise ServiceError(409, "Playbook evidence window is invalid") from None
            for artifact in ("process", "network", "file", "persistence"):
                result = await self.core.collect(
                    incident_id,
                    CollectionRequest(
                        incident_id=incident_id,
                        mode=context.request.mode,
                        scenario_id=context.incident.scenario_id,
                        endpoint=context.incident.endpoint,
                        start=start,
                        end=end,
                        artifact=artifact,
                    ),
                    context.analyst,
                )
                available.update(
                    item.evidence_id for item in result.evidence if item.availability == "available"
                )
                gaps.update(result.gaps)
            if not available:
                raise ServiceError(409, "A prepared playbook requires recorded evidence")
            context = self._refresh(context, actor)
            self._active(context)
            self._check_supported_scope(context, decision)
            proposal = (
                self._proposal(context, decision, create=True)
                if decision.disposition == "propose"
                else None
            )
            audit = next(
                (
                    item
                    for item in self.core.audit(incident_id, context.analyst)
                    if item.operation == "alert_accepted"
                ),
                None,
            )
            if audit is None:
                raise ServiceError(409, "Original case intake audit is missing")
            readiness = CaseReadiness(
                evidence_refs=tuple(sorted(available)),
                known_gaps=tuple(sorted(gaps)),
                proposal_ids=(proposal.proposal_id,) if proposal else (),
                no_action_reason=None if proposal else decision.rationale,
                audit_event_id=audit.event_id,
            )
            metric = self.core.mark_ready(incident_id, readiness, context.analyst)
            plan = PlaybookPlan(
                request=context.request,
                kind=context.kind,
                source_sha256=context.batch.sha256,
                assessment=decision,
                evidence_refs=readiness.evidence_refs,
                known_gaps=readiness.known_gaps,
                proposal_id=proposal.proposal_id if proposal else None,
                provider=context.provider,
                provider_version=context.provider_version,
                created_at=self.core._now(),
                readiness_event_id=metric.event_id,
            )
            with self.core.store.transaction() as tx:
                key = "playbook-plan:" + request.run_id
                value = tx.get("callbacks", key)
                if value is not None:
                    existing = _read(PlaybookPlan, value)
                    if existing != plan:
                        raise ServiceError(
                            409, "Concurrent playbook preparation must retry original plan"
                        )
                    return existing
                tx.insert("callbacks", key, plan.model_dump(mode="json"))
                self.core._audit(
                    tx,
                    incident_id,
                    actor,
                    "playbook_prepared",
                    "Bound " + context.kind + " playbook prepared for run " + request.run_id,
                )
            return plan

    def _progress(self, context: _Context, plan: PlaybookPlan) -> PlaybookProgress:
        common = {"request": plan.request, "kind": plan.kind, "proposal_id": plan.proposal_id}
        if plan.proposal_id is None:
            return PlaybookProgress(**common, status="no_action")
        view = self.core.action(plan.proposal_id, context.analyst)
        if view.execution is not None:
            execution = view.execution
            if execution.provider != plan.provider:
                raise ServiceError(409, "Original playbook execution provider cannot change")
            with self.core.store.transaction() as tx:
                original_version = tx.get_key("execution_provider_version", plan.proposal_id)
            if original_version != plan.provider_version:
                raise ServiceError(409, "Original playbook execution version cannot change")
            status = (
                "completed"
                if execution.verification.status == "verified"
                else "failed"
                if execution.dispatch_state == "failed"
                or execution.verification.status in {"failed", "unsupported"}
                else "uncertain"
            )
            return PlaybookProgress(**common, status=status, execution=execution)
        now, approval = self.core._now(), view.approval
        if now >= view.proposal.expires_at or (approval is not None and now >= approval.expires_at):
            return PlaybookProgress(**common, status="expired")
        if approval is None:
            return PlaybookProgress(**common, status="awaiting_approval")
        self.core._approval_subject(approval, view.proposal)
        return PlaybookProgress(
            **common, status="ready" if approval.decision == "approved" else "denied"
        )

    def inspect(
        self, incident_id: str, request: PlaybookStepRequest, actor: Principal
    ) -> PlaybookPlan:
        """Read an existing bound plan without preparing or auditing another step."""
        context = self._context(incident_id, request, actor)
        plan = self._cached(context)
        if plan is None:
            raise ServiceError(409, "Original playbook plan is unavailable")
        return plan

    def gate(
        self, incident_id: str, request: PlaybookStepRequest, actor: Principal
    ) -> PlaybookProgress:
        with self.core._operation(incident_id, actor):
            context = self._context(incident_id, request, actor)
            plan = self._cached(context)
            if plan is None:
                raise ServiceError(409, "Original playbook plan is missing")
            result = self._progress(context, plan)
            self._audit(context, actor, "playbook_gate")
            return result

    def _dispatch_guard(self, context: _Context, actor: Principal, tx: Transaction) -> None:
        """Fresh workflow authority in the core's atomic reservation transaction."""
        core, settings, request = self.core, self.core.settings, context.request
        core._principal(actor, {"workflow"})
        core._principal(context.analyst, {"analyst"})
        core._principal(context.executor, {"executor"})
        if actor.roles != frozenset({"workflow"}) or actor.human:
            raise ServiceError(403, "Workflow authority changed before dispatch")
        binding = settings.shuffle_bindings.get(request.workflow_id)
        cfg = settings.shuffle_config
        try:
            current_source = settings.source_for_alert(context.alert)
            current_provider = settings.provider_for_source(current_source)
        except (ValueError, TypeError, KeyError):
            raise ServiceError(409, "Original source changed before dispatch") from None
        if (
            cfg is None
            or binding is None
            or request.workflow_id not in cfg.workflow_ids
            or settings.playbook_bindings.get(request.workflow_id) != context.kind
            or current_provider != context.provider
            or settings.provider_versions.get(context.provider) != context.provider_version
            or settings.mode != Mode.REPLAY
            or current_source != context.batch
            or settings.playbook_actors.get("analyst") != context.analyst.actor_id
            or settings.playbook_actors.get("executor") != context.executor.actor_id
        ):
            raise ServiceError(409, "Playbook configuration changed before dispatch")
        incident = core._incident(tx, request.incident_id, actor)
        run = _read(PlaybookRun, tx.get("workflows", request.run_id))
        delivery = _read(DeliveryRecord, tx.get("callbacks", "shuffle:" + request.run_id))
        alert = _read(Alert, tx.get("alerts", request.incident_id))
        meta = tx.get("case_meta", request.incident_id)
        argument = ShuffleArgument.model_validate(request.model_dump(exclude={"workflow_id"}))
        if (
            incident.endpoint != context.incident.endpoint
            or incident.mode != request.mode
            or incident.alert_id != context.alert.alert_id
            or incident.scenario_id != context.incident.scenario_id
            or alert != context.alert
            or meta is None
            or meta.get("incident_id") != request.incident_id
            or meta.get("alert_id") != alert.alert_id
            or meta.get("scenario_id") != incident.scenario_id
            or meta.get("correlation_id") != request.correlation_id
            or meta.get("mode") != request.mode.value
            or run.run_id != request.run_id
            or run.incident_id != request.incident_id
            or run.workflow_id != request.workflow_id
            or run.correlation_id != request.correlation_id
            or run.workflow_version != binding.version
            or run.status != "running"
            or delivery.argument != argument
            or delivery.workflow_id != request.workflow_id
            or delivery.workflow_version != binding.version
            or delivery.workflow_sha256 != binding.sha256
            or delivery.origin != cfg.base_url
            or delivery.state in {"finished", "failed", "rejected"}
            or not run.started_at <= delivery.created_at <= delivery.updated_at <= core._now()
        ):
            raise ServiceError(409, "Workflow authority ended or changed before dispatch")

    async def dispatch(
        self, incident_id: str, request: PlaybookStepRequest, actor: Principal
    ) -> PlaybookProgress:
        with self.core._operation(incident_id, actor):
            context = self._context(incident_id, request, actor)
            plan = self._cached(context)
            if plan is None:
                raise ServiceError(409, "Original playbook plan is missing")
            progress = self._progress(context, plan)
            if progress.status in {"no_action", "completed", "failed"}:
                return progress
            if plan.proposal_id is None:
                raise ServiceError(409, "Original response proposal is missing")
            if progress.execution is not None:
                await self.core.reconcile(plan.proposal_id, plan.provider, context.executor)
            else:
                self._active(context)
                if progress.status != "ready":
                    raise ServiceError(409, "Current human approval is required for dispatch")
                await self.core.execute(
                    plan.proposal_id,
                    plan.provider,
                    context.executor,
                    pre_dispatch=lambda tx: self._dispatch_guard(context, actor, tx),
                )
            self._audit(context, actor, "playbook_dispatch")
            return self._progress(context, plan)
