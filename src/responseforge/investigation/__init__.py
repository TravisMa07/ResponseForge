"""Replay evidence is bounded existing data, never a fabricated live collection."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from pydantic import TypeAdapter

from responseforge.contracts import (
    CollectionRequest,
    CollectionResult,
    Contract,
    EndpointRef,
    Evidence,
    Incident,
    Mode,
    Provenance,
    UtcDateTime,
)
from responseforge.replay import ReplayError, logical_receipt, make_alerts
from responseforge.replay_contracts import RecordedEvent, ReplayBatch, digest

T = TypeVar("T", bound=Contract)


def _validated(model: type[T], value: T) -> T:
    try:
        return model.model_validate(value.model_dump(mode="json", warnings=False))
    except (ValueError, TypeError) as exc:
        raise ReplayError("Invalid replay evidence contract") from exc


class ReplayEvidenceProvider:
    """A detached immutable source snapshot with strict mode/scenario/host scope."""

    def __init__(self, batch: ReplayBatch, *, clock: Callable[[], datetime] | None = None) -> None:
        snapshot = _validated(ReplayBatch, batch)
        self._source_json = snapshot.model_dump_json()
        self._clock = clock or (lambda: datetime.now(UTC))

    def _batch(self) -> ReplayBatch:
        return ReplayBatch.model_validate_json(self._source_json)

    def _now(self) -> datetime:
        try:
            return TypeAdapter(UtcDateTime).validate_python(self._clock())
        except (ValueError, TypeError) as exc:
            raise ReplayError("Replay evidence clock must be aware") from exc

    def _scope(
        self, batch: ReplayBatch, scenario_id: str, endpoint: EndpointRef
    ) -> tuple[RecordedEvent, ...]:
        events = tuple(
            event
            for event in batch.events
            if event.scenario_id == scenario_id and event.endpoint == endpoint
        )
        if not events:
            raise ReplayError("Unknown replay evidence scope")
        return tuple(sorted(events, key=lambda event: (event.observed_at, event.event_id)))

    def _available(
        self, batch: ReplayBatch, incident_id: str, event: RecordedEvent, now: datetime
    ) -> Evidence:
        return Evidence(
            evidence_id="evidence-"
            + digest(
                [
                    batch.source_id,
                    batch.sha256,
                    incident_id,
                    event.scenario_id,
                    event.endpoint.model_dump(mode="json"),
                    event.event_id,
                ]
            ),
            incident_id=incident_id,
            mode=Mode.REPLAY,
            endpoint=event.endpoint,
            observed_at=event.observed_at,
            collected_at=now,
            availability="available",
            provenance=Provenance(
                source="synthetic-fixture",
                source_ref="fixture:" + batch.source_id,
                sha256=batch.sha256,
                original_event_ids=(event.event_id,),
            ),
            unavailable_reason=None,
        )

    async def list_evidence(self, incident: Incident) -> tuple[Evidence, ...]:
        incident = _validated(Incident, incident)
        if incident.mode != Mode.REPLAY:
            raise ReplayError("Replay evidence cannot satisfy live mode")
        batch = self._batch()
        events = self._scope(batch, incident.scenario_id, incident.endpoint)
        alerts = make_alerts(batch, ingested_at=logical_receipt(batch))
        alert = next(
            (
                item
                for item in alerts
                if item.scenario_id == incident.scenario_id
                and item.endpoint == incident.endpoint
                and item.alert_id == incident.alert_id
            ),
            None,
        )
        if alert is None:
            raise ReplayError("Incident does not match replay alert")
        now = self._now()
        try:
            start, end = (
                alert.event_time - timedelta(minutes=5),
                alert.event_time + timedelta(minutes=5),
            )
        except OverflowError as exc:
            raise ReplayError("Replay evidence window exceeds timestamp range") from exc
        return tuple(
            self._available(batch, incident.incident_id, event, now)
            for event in events
            if start <= event.observed_at <= end
        )

    async def collect(self, request: CollectionRequest) -> CollectionResult:
        request = _validated(CollectionRequest, request)
        if request.mode != Mode.REPLAY:
            raise ReplayError("Replay evidence cannot satisfy live mode")
        batch = self._batch()
        scoped = self._scope(batch, request.scenario_id, request.endpoint)
        selected = tuple(
            event
            for event in scoped
            if event.artifact == request.artifact
            and request.start <= event.observed_at <= request.end
        )
        now = self._now()
        if selected:
            return CollectionResult(
                evidence=tuple(
                    self._available(batch, request.incident_id, event, now) for event in selected
                ),
                gaps=(),
            )
        reason = "No recorded " + request.artifact + " events in requested scope"
        times = request.model_dump(mode="json")
        missing = Evidence(
            evidence_id="evidence-"
            + digest(
                [
                    batch.source_id,
                    batch.sha256,
                    request.incident_id,
                    request.scenario_id,
                    request.endpoint.model_dump(mode="json"),
                    "unavailable",
                    request.artifact,
                    times["start"],
                    times["end"],
                ]
            ),
            incident_id=request.incident_id,
            mode=Mode.REPLAY,
            endpoint=request.endpoint,
            observed_at=None,
            collected_at=now,
            availability="unavailable",
            provenance=None,
            unavailable_reason=reason,
        )
        return CollectionResult(evidence=(missing,), gaps=(reason,))
