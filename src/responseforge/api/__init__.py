"""Authenticated internal HTTP API; no vendor transport compatibility claim."""

import hmac
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import TypeAdapter, ValidationError

from responseforge.contracts import (
    ActionExecution,
    ActionProposal,
    Approval,
    AuditEvent,
    CaseReadiness,
    CollectionRequest,
    CollectionResult,
    Evidence,
    Incident,
    MetricEvent,
    PlaybookRun,
    UtcDateTime,
)
from responseforge.core import CaseService, ServiceError
from responseforge.integrations.shuffle.coordinator import ShuffleCoordinator
from responseforge.runtime import (
    ActionView,
    CallbackAcknowledgement,
    DecisionRequest,
    ExecuteRequest,
    IntakeResult,
    Principal,
    Settings,
    TransitionRequest,
    WorkflowCallback,
    WorkflowRegistration,
)
from responseforge.storage import ConflictError, StorageError, Store


def create_app(
    settings: Settings,
    *,
    clock: Callable[[], datetime] | None = None,
    shuffle_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    now = clock or (lambda: datetime.now(UTC))
    store = Store(settings.database_path)
    service = CaseService(store, settings, clock=now)
    app = FastAPI(
        title="ResponseForge internal case API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.service = service
    app.state.store = store

    def system_denial(actor: str, detail: str) -> None:
        event = AuditEvent(
            event_id=str(uuid4()),
            incident_id="_system",
            correlation_id="_system",
            actor=actor,
            operation="denied",
            occurred_at=now(),
            detail=detail,
        )
        with store.transaction() as tx:
            tx.insert("audit", event.event_id, event.model_dump(mode="json"))

    bearer = HTTPBearer(auto_error=False)

    def authenticate(
        request: Request,
        credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Principal:
        token = credential.credentials if credential is not None else ""
        actor = None
        if token:
            for candidate, principal in settings.credentials.items():
                if hmac.compare_digest(candidate.encode(), token.encode()):
                    actor = principal
        if actor is None:
            system_denial("anonymous", "Authentication rejected")
            raise HTTPException(
                401, "Authentication required", headers={"WWW-Authenticate": "Bearer"}
            )
        with store.transaction() as tx:
            permitted = tx.consume_rate(actor.actor_id, now())
        if not permitted:
            system_denial(actor.actor_id, "Request rate exceeded")
            raise HTTPException(429, "Request rate exceeded")
        return actor

    Actor = Annotated[Principal, Depends(authenticate)]

    @app.exception_handler(ServiceError)
    async def service_error(request: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default error details include the untrusted input. Do not echo it.
        system_denial("request", "Request schema rejected")
        return JSONResponse(status_code=422, content={"detail": "Invalid request schema"})

    @app.exception_handler(ValidationError)
    async def invalid_domain(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=409, content={"detail": "Stored or submitted contract invalid"}
        )

    @app.exception_handler(ConflictError)
    async def conflict(request: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": "Conflicting stored record"})

    @app.exception_handler(StorageError)
    @app.exception_handler(sqlite3.Error)
    async def storage_error(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "Case storage unavailable"})

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def ready() -> dict[str, str]:
        with store.transaction():
            pass
        return {"status": "ready", "mode": settings.mode.value}

    # Import here keeps request model reference explicit without coupling adapters.
    from responseforge.contracts import Alert

    @app.post(
        "/v1/alerts",
        response_model=IntakeResult,
        responses={201: {"model": IntakeResult, "description": "New durable case"}},
    )
    def intake(item: Alert, response: Response, actor: Actor) -> IntakeResult:
        result = service.intake(item, actor)
        response.status_code = 200 if result.duplicate else 201
        return result

    @app.post(
        "/v1/integrations/wazuh/alerts", response_model=IntakeResult,
        responses={201: {"model": IntakeResult, "description": "New native source case"}},
        openapi_extra={"requestBody": {"required": True, "content": {
            "application/json": {"schema": {"type": "object"}}}}},
    )
    async def wazuh_intake(request: Request, response: Response, actor: Actor) -> IntakeResult:
        from responseforge.integrations.wazuh.service import WazuhService
        if settings.wazuh is None:
            raise HTTPException(404, "Native integration is disabled")
        if actor.actor_id != settings.wazuh.source_actor_id or actor.roles != {"source"}:
            raise HTTPException(403, "Native source actor is not authorized")
        media = request.headers.get("content-type", "").lower().split(";")
        parameters = [part.strip() for part in media[1:]]
        if (media[0].strip() != "application/json"
                or any(part not in {"charset=utf-8", 'charset="utf-8"'} for part in parameters)
                or request.headers.get("content-encoding", "identity").strip().lower() != "identity"):
            raise HTTPException(415, "Unsupported native representation")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > 262144:
                raise HTTPException(413, "Native alert exceeds byte limit")
            data.extend(chunk)
        try:
            result = WazuhService(service).intake(bytes(data), actor)
        except ServiceError:
            system_denial(actor.actor_id, "Native source intake rejected")
            raise
        response.status_code = 200 if result.duplicate else 201
        return result

    @app.get("/v1/incidents", response_model=tuple[Incident, ...])
    def incidents(actor: Actor) -> tuple[Incident, ...]:
        return service.list_incidents(actor)

    @app.get("/v1/incidents/{incident_id}", response_model=Incident)
    def incident(incident_id: str, actor: Actor) -> Incident:
        return service.get_incident(incident_id, actor)

    @app.get("/v1/incidents/{incident_id}/audit", response_model=tuple[AuditEvent, ...])
    def audit(incident_id: str, actor: Actor) -> tuple[AuditEvent, ...]:
        return service.audit(incident_id, actor)

    @app.get("/v1/incidents/{incident_id}/metrics", response_model=tuple[MetricEvent, ...])
    def metrics(incident_id: str, actor: Actor) -> tuple[MetricEvent, ...]:
        return service.metrics(incident_id, actor)

    @app.get("/v1/incidents/{incident_id}/evidence", response_model=tuple[Evidence, ...])
    def evidence(incident_id: str, actor: Actor) -> tuple[Evidence, ...]:
        return service.evidence(incident_id, actor)

    @app.post("/v1/incidents/{incident_id}/evidence", response_model=Evidence)
    def add_evidence(incident_id: str, item: Evidence, actor: Actor) -> Evidence:
        return service.add_evidence(incident_id, item, actor)

    @app.post("/v1/incidents/{incident_id}/transition", response_model=Incident)
    def transition(incident_id: str, item: TransitionRequest, actor: Actor) -> Incident:
        return service.transition(incident_id, item.status, actor, reviewed=item.reviewed)

    @app.post("/v1/incidents/{incident_id}/ready", response_model=MetricEvent)
    def mark_ready(incident_id: str, item: CaseReadiness, actor: Actor) -> MetricEvent:
        return service.mark_ready(incident_id, item, actor)

    @app.post("/v1/incidents/{incident_id}/workflows", response_model=PlaybookRun)
    def register_workflow(
        incident_id: str, item: WorkflowRegistration, actor: Actor
    ) -> PlaybookRun:
        return service.register_workflow(
            incident_id, item.run_id, item.workflow_id, item.workflow_version, actor
        )

    @app.post("/v1/incidents/{incident_id}/actions/propose", response_model=ActionProposal)
    def propose(incident_id: str, item: ActionProposal, actor: Actor) -> ActionProposal:
        return service.propose(incident_id, item, actor)

    @app.get("/v1/actions/{proposal_id}", response_model=ActionView)
    def action(proposal_id: str, actor: Actor) -> ActionView:
        return service.action(proposal_id, actor)

    @app.post("/v1/actions/{proposal_id}/approve", response_model=Approval)
    def approve(proposal_id: str, item: DecisionRequest, actor: Actor) -> Approval:
        return service.decide(proposal_id, "approved", item.expires_at, actor)

    @app.post("/v1/actions/{proposal_id}/reject", response_model=Approval)
    def reject(proposal_id: str, item: DecisionRequest, actor: Actor) -> Approval:
        return service.decide(proposal_id, "rejected", item.expires_at, actor)

    @app.post("/v1/actions/{proposal_id}/cancel", response_model=Approval)
    def cancel(proposal_id: str, item: DecisionRequest, actor: Actor) -> Approval:
        return service.decide(proposal_id, "cancelled", item.expires_at, actor)

    @app.post("/v1/actions/{proposal_id}/execute", response_model=ActionExecution)
    async def execute(proposal_id: str, item: ExecuteRequest, actor: Actor) -> ActionExecution:
        return await service.execute(proposal_id, item.provider, actor)

    @app.post("/v1/actions/{proposal_id}/reconcile", response_model=ActionExecution)
    async def reconcile(proposal_id: str, item: ExecuteRequest, actor: Actor) -> ActionExecution:
        return await service.reconcile(proposal_id, item.provider, actor)

    @app.post("/v1/integrations/shuffle/callback", response_model=CallbackAcknowledgement)
    def callback(
        item: WorkflowCallback,
        actor: Actor,
        x_request_timestamp: str = Header(default=""),
        x_request_nonce: str = Header(default=""),
    ) -> CallbackAcknowledgement:
        try:
            sent_at = TypeAdapter(UtcDateTime).validate_python(x_request_timestamp)
        except ValidationError:
            system_denial(actor.actor_id, "Callback timestamp rejected")
            raise HTTPException(422, "Invalid callback timestamp") from None
        service.callback(item, actor, nonce=x_request_nonce, sent_at=sent_at)
        return CallbackAcknowledgement(**item.model_dump(mode="json"), received_at=now())

    @app.post("/v1/incidents/{incident_id}/collect", response_model=CollectionResult)
    async def collect(incident_id: str, item: CollectionRequest, actor: Actor) -> CollectionResult:
        return await service.collect(incident_id, item, actor)

    @app.get(
        "/v1/incidents/{incident_id}/report",
        response_model=None,
        responses={
            200: {
                "content": {
                    "application/json": {"schema": {"type": "object"}},
                    "text/html": {"schema": {"type": "string"}},
                }
            }
        },
    )
    def report(
        incident_id: str, actor: Actor, format: Literal["json", "html"] = "json"
    ) -> Response:
        from responseforge.reports import build_report, render_html

        report_secrets = tuple(settings.credentials)
        if settings.shuffle_config is not None:
            report_secrets += (settings.shuffle_config.api_key,)
        value = build_report(service, incident_id, actor, secrets=report_secrets)
        if format == "html":
            return HTMLResponse(render_html(value))
        return JSONResponse(value)

    def shuffle_coordinator() -> ShuffleCoordinator:
        from responseforge.integrations.shuffle.client import ShuffleTransport

        if settings.shuffle_config is None:
            raise ServiceError(503, "Shuffle transport is not configured")
        return ShuffleCoordinator(
            service,
            ShuffleTransport(settings.shuffle_config, transport=shuffle_transport),
            settings.shuffle_bindings,
        )

    from responseforge.integrations.shuffle.models import (
        DeliveryRecord,
        ShuffleReconcileRequest,
        ShuffleStartRequest,
    )

    @app.post("/v1/incidents/{incident_id}/shuffle/start", response_model=DeliveryRecord)
    async def shuffle_start(
        incident_id: str, item: ShuffleStartRequest, actor: Actor
    ) -> DeliveryRecord:
        return await shuffle_coordinator().start(incident_id, item.workflow_id, item.run_id, actor)

    @app.post("/v1/incidents/{incident_id}/shuffle/reconcile", response_model=DeliveryRecord)
    async def shuffle_reconcile(
        incident_id: str, item: ShuffleReconcileRequest, actor: Actor
    ) -> DeliveryRecord:
        return await shuffle_coordinator().reconcile(incident_id, item.run_id, actor)

    from responseforge.playbooks.models import PlaybookPlan, PlaybookProgress, PlaybookStepRequest
    from responseforge.playbooks.service import PlaybookService

    @app.post("/v1/incidents/{incident_id}/playbooks/prepare", response_model=PlaybookPlan)
    async def playbook_prepare(
        incident_id: str, item: PlaybookStepRequest, actor: Actor
    ) -> PlaybookPlan:
        return await PlaybookService(service).prepare(incident_id, item, actor)

    @app.post("/v1/incidents/{incident_id}/playbooks/inspect", response_model=PlaybookPlan)
    def playbook_inspect(
        incident_id: str, item: PlaybookStepRequest, actor: Actor
    ) -> PlaybookPlan:
        return PlaybookService(service).inspect(incident_id, item, actor)

    @app.post("/v1/incidents/{incident_id}/playbooks/gate", response_model=PlaybookProgress)
    def playbook_gate(
        incident_id: str, item: PlaybookStepRequest, actor: Actor
    ) -> PlaybookProgress:
        return PlaybookService(service).gate(incident_id, item, actor)

    @app.post("/v1/incidents/{incident_id}/playbooks/dispatch", response_model=PlaybookProgress)
    async def playbook_dispatch(
        incident_id: str, item: PlaybookStepRequest, actor: Actor
    ) -> PlaybookProgress:
        return await PlaybookService(service).dispatch(incident_id, item, actor)

    return app
