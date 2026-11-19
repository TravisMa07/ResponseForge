"""Detached replay sources resolved by original alert authority, never a default."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TypeVar

from responseforge.contracts import (
    Alert,
    CollectionRequest,
    CollectionResult,
    Contract,
    EndpointRef,
    Evidence,
    Incident,
    Mode,
)
from responseforge.datasets import _manifest_bytes, _read_regular, _reuse_bundle, _safe_directory
from responseforge.integrations.mock_edr import MockResponseProvider
from responseforge.investigation import ReplayEvidenceProvider
from responseforge.recorded_contracts import RecordedConfig
from responseforge.replay import ReplayError, logical_receipt, make_alerts
from responseforge.replay.selection import select_recorded
from responseforge.replay.windows import normalize_windows
from responseforge.replay_contracts import ReplayBatch

T = TypeVar("T", bound=Contract)


def _detached(model: type[T], value: T) -> T:
    return model.model_validate(value.model_dump(mode="json", warnings=False))


def _scope(scenario: str, endpoint: EndpointRef) -> tuple[str, str]:
    return scenario, json.dumps(endpoint.model_dump(mode="json"), sort_keys=True)


class RecordedMockResponseProvider(MockResponseProvider):
    """The existing mock logic under a distinct durable receipt namespace."""

    name = "recorded-mock-edr"


class ReplayRegistry:
    """Immutable source snapshots with unambiguous scoped evidence routing."""

    def __init__(
        self, batches: tuple[ReplayBatch, ...], *, clock: Callable[[], datetime] | None = None
    ) -> None:
        try:
            if (
                not isinstance(batches, tuple)
                or not 1 <= len(batches) <= 33
                or (clock is not None and not callable(clock))
            ):
                raise ReplayError("Invalid replay registry")
            snapshots: list[str] = []
            scopes: dict[tuple[str, str], int] = {}
            alert_ids: dict[str, int] = {}
            identities: dict[str, tuple[str, str | None]] = {}
            records: dict[tuple[str, str, str], str] = {}
            for batch in batches:
                snapshot = _detached(ReplayBatch, batch)
                if not snapshot.events:
                    raise ReplayError("Empty replay source cannot be registered")
                origin = None if snapshot.origin is None else snapshot.origin.model_dump_json()
                descriptor = snapshot.sha256, origin
                previous = identities.get(snapshot.source_id)
                if previous is not None and previous != descriptor:
                    raise ReplayError("Conflicting replay source identity")
                identities[snapshot.source_id] = descriptor
                index = len(snapshots)
                batch_scopes: set[tuple[str, str]] = set()
                event_keys: set[tuple[str, str, str]] = set()
                for event in snapshot.events:
                    endpoint = _scope(event.scenario_id, event.endpoint)[1]
                    key = snapshot.source_id, endpoint, event.event_id
                    # Only the operator's scenario namespace may differ when
                    # registering the same recorded observation for another case.
                    content = json.dumps(
                        event.model_dump(mode="json", exclude={"scenario_id"}), sort_keys=True
                    )
                    if key in records and records[key] != content:
                        raise ReplayError("Conflicting recorded source event")
                    records[key] = content
                    local_key = event.scenario_id, endpoint, event.event_id
                    if local_key in event_keys:
                        raise ReplayError("Duplicate recorded event identity")
                    event_keys.add(local_key)
                    batch_scopes.add(_scope(event.scenario_id, event.endpoint))
                for scope in batch_scopes:
                    if scope in scopes:
                        raise ReplayError("Ambiguous replay collection scope")
                    scopes[scope] = index
                for alert in make_alerts(snapshot, ingested_at=logical_receipt(snapshot)):
                    if alert.alert_id in alert_ids:
                        raise ReplayError("Ambiguous replay alert identity")
                    alert_ids[alert.alert_id] = index
                snapshots.append(snapshot.model_dump_json())
            self._snapshots = tuple(snapshots)
            self._scopes = scopes
            self._alert_ids = alert_ids
            self._clock = clock
        except ReplayError:
            raise
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            raise ReplayError("Invalid replay registry") from None

    def _batch(self, index: int) -> ReplayBatch:
        return ReplayBatch.model_validate_json(self._snapshots[index])

    def resolve(self, alert: Alert) -> ReplayBatch:
        """Require the complete original alert, including its source proof."""
        try:
            alert = _detached(Alert, alert)
            if alert.mode != Mode.REPLAY or alert.alert_id not in self._alert_ids:
                raise ReplayError("Unknown replay alert")
            batch = self._batch(self._alert_ids[alert.alert_id])
            matches = tuple(
                value
                for value in make_alerts(batch, ingested_at=alert.ingested_at)
                if value == alert
            )
            if len(matches) != 1:
                raise ReplayError("Replay alert differs from registered source")
            return batch
        except ReplayError:
            raise
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            raise ReplayError("Invalid replay alert") from None

    async def collect(self, request: CollectionRequest) -> CollectionResult:
        try:
            request = _detached(CollectionRequest, request)
            if request.mode != Mode.REPLAY:
                raise ReplayError("Recorded evidence cannot satisfy live mode")
            index = self._scopes.get(_scope(request.scenario_id, request.endpoint))
            if index is None:
                raise ReplayError("Unknown recorded collection scope")
            provider = ReplayEvidenceProvider(self._batch(index), clock=self._clock)
            return await provider.collect(request)
        except ReplayError:
            raise
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            raise ReplayError("Invalid recorded collection request") from None

    async def list_evidence(self, incident: Incident) -> tuple[Evidence, ...]:
        try:
            incident = _detached(Incident, incident)
            if incident.mode != Mode.REPLAY:
                raise ReplayError("Recorded evidence cannot satisfy live mode")
            index = self._alert_ids.get(incident.alert_id)
            if index is None or self._scopes.get(
                _scope(incident.scenario_id, incident.endpoint)
            ) != index:
                raise ReplayError("Unknown recorded incident scope")
            provider = ReplayEvidenceProvider(self._batch(index), clock=self._clock)
            return await provider.list_evidence(incident)
        except ReplayError:
            raise
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            raise ReplayError("Invalid recorded incident") from None


def load_recorded_sources(config: RecordedConfig, *, mode: Mode) -> tuple[ReplayBatch, ...]:
    """Verify explicit local bundles offline before registering selected source facts."""
    try:
        if Mode(mode) != Mode.REPLAY:
            raise ReplayError("Recorded sources require explicit replay mode")
        config = _detached(RecordedConfig, config)
        root = Path(config.bundle_root)
        if (
            not root.is_absolute()
            or ".." in root.parts
            or any(ord(character) < 32 or ord(character) == 127 for character in str(root))
        ):
            raise ReplayError("Invalid recorded bundle root")
        _safe_directory(root, create=False)
        sources: list[ReplayBatch] = []
        for case in config.cases:
            artifact = case.artifact
            bundle = root / artifact.artifact_id
            source = _reuse_bundle(bundle, artifact, _manifest_bytes(artifact))
            raw = _read_regular(source, artifact.size_bytes)
            batch = normalize_windows(raw, artifact=artifact, scenario_id=case.scenario_id)
            if batch.quarantine or not batch.events:
                raise ReplayError("Recorded source contains invalid or unavailable records")
            selected = select_recorded(batch, event_ids=case.event_ids)
            if len(make_alerts(selected, ingested_at=logical_receipt(selected))) != 1:
                raise ReplayError("Recorded case must bind exactly one alert")
            sources.append(selected)
        ReplayRegistry(tuple(sources))
        return tuple(sources)
    except ReplayError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise ReplayError("Recorded source loading failed") from None
