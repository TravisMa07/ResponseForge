"""Bounded local fixture replay; command strings are inert recorded data."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from responseforge.contracts import Alert, Provenance, UtcDateTime
from responseforge.replay_contracts import QuarantineItem, RecordedEvent, ReplayBatch, digest

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 1000
MAX_LINE_BYTES = 16 * 1024


class ReplayError(ValueError):
    """A safe replay refusal; never include source bytes or exception details."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _detached(batch: ReplayBatch) -> ReplayBatch:
    try:
        return ReplayBatch.model_validate(batch.model_dump(mode="json", warnings=False))
    except (ValueError, TypeError) as exc:
        raise ReplayError("Invalid replay batch") from exc


def load_replay(path: str | Path, *, source_id: str) -> ReplayBatch:
    """Read explicitly supplied local JSON/JSONL and retain exact-byte integrity."""
    source = Path(path)
    if source.suffix.lower() not in {".json", ".jsonl"}:
        raise ReplayError("Unsupported replay format")
    try:
        with source.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise ReplayError("Replay source cannot be read") from exc
    if len(raw) > MAX_BYTES:
        raise ReplayError("Replay source exceeds byte limit")
    try:
        content = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ReplayError("Replay source must be UTF-8") from exc
    issues: list[QuarantineItem] = []
    records: list[tuple[int, Any]] = []
    if source.suffix.lower() == ".json":
        try:
            document = json.loads(content)
        except (ValueError, RecursionError) as exc:
            decode_line = exc.lineno if isinstance(exc, json.JSONDecodeError) else 1
            issues.append(QuarantineItem(line=decode_line, code="invalid_json"))
            document = []
        if not isinstance(document, list):
            raise ReplayError("JSON replay source must be an array")
        if len(document) > MAX_RECORDS:
            raise ReplayError("Replay source exceeds record limit")
        records = list(enumerate(document, 1))
    else:
        nonempty = 0
        for number, line in enumerate(content.split("\n"), 1):
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise ReplayError("Replay line exceeds byte limit")
            if not line.strip():
                continue
            nonempty += 1
            if nonempty > MAX_RECORDS:
                raise ReplayError("Replay source exceeds record limit")
            try:
                value = json.loads(line)
            except (ValueError, RecursionError):
                issues.append(QuarantineItem(line=number, code="invalid_json"))
                continue
            records.append((number, value))
    events: list[tuple[int, RecordedEvent]] = []
    seen: dict[tuple[str, str, str], RecordedEvent] = {}
    duplicates = 0
    for number, record in records:
        try:
            event = RecordedEvent.model_validate(record)
        except (ValidationError, ValueError, TypeError):
            issues.append(QuarantineItem(line=number, code="invalid_schema"))
            continue
        identity = (
            event.scenario_id,
            _canonical(event.endpoint.model_dump(mode="json")),
            event.event_id,
        )
        previous = seen.get(identity)
        if previous is not None:
            if previous == event:
                duplicates += 1
            else:
                issues.append(QuarantineItem(line=number, code="duplicate_conflict"))
            continue
        seen[identity] = event
        events.append((number, event))
    events.sort(
        key=lambda pair: (
            pair[1].observed_at,
            pair[1].scenario_id,
            pair[1].endpoint.endpoint_id,
            pair[1].event_id,
            pair[0],
        )
    )
    issues.sort(key=lambda item: item.line)
    try:
        return ReplayBatch(
            source_id=source_id,
            sha256=hashlib.sha256(raw).hexdigest(),
            events=tuple(event for _, event in events),
            quarantine=tuple(issues),
            duplicates=duplicates,
        )
    except (ValidationError, ValueError, TypeError) as exc:
        raise ReplayError("Invalid replay source identity") from exc


def logical_receipt(batch: ReplayBatch) -> datetime:
    snapshot = _detached(batch)
    if not snapshot.events:
        raise ReplayError("Replay source has no valid events")
    try:
        return max(event.observed_at for event in snapshot.events) + timedelta(seconds=1)
    except OverflowError as exc:
        raise ReplayError("Replay clock exceeds timestamp range") from exc


def _signal(event: RecordedEvent) -> bool:
    image = event.fields.get("image", "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
    command = event.fields.get("command_line", "").casefold()
    return (
        event.artifact == "process"
        and image == "powershell.exe"
        and "-encodedcommand" in command
        and "-windowstyle hidden" in command
    )


def replay_provenance(batch: ReplayBatch, event_ids: tuple[str, ...]) -> Provenance:
    """Bind original source bytes and event identities without relabeling recordings."""
    return Provenance(
        source="synthetic-fixture" if batch.origin is None else batch.origin.source,
        source_ref="fixture:" + batch.source_id if batch.origin is None else batch.origin.source_ref,
        sha256=batch.sha256,
        original_event_ids=event_ids,
    )


def make_alerts(batch: ReplayBatch, *, ingested_at: datetime) -> tuple[Alert, ...]:
    snapshot = _detached(batch)
    try:
        receipt = TypeAdapter(UtcDateTime).validate_python(ingested_at)
    except (ValidationError, ValueError, TypeError) as exc:
        raise ReplayError("Replay receipt time must be aware") from exc
    groups: dict[tuple[str, str], list[RecordedEvent]] = {}
    for event in snapshot.events:
        key = event.scenario_id, _canonical(event.endpoint.model_dump(mode="json"))
        groups.setdefault(key, []).append(event)
    alerts = []
    for (scenario, _), records in groups.items():
        ordered = sorted(records, key=lambda row: (row.observed_at, row.event_id))
        suspicious = [event for event in ordered if _signal(event)]
        anchor = suspicious[0] if suspicious else ordered[0]
        identity = [
            snapshot.source_id,
            snapshot.sha256,
            scenario,
            anchor.endpoint.model_dump(mode="json"),
        ]
        alerts.append(
            Alert(
                alert_id="replay-" + digest(identity),
                mode="replay",
                source="replay-fixture" if snapshot.origin is None else snapshot.origin.source,
                scenario_id=scenario,
                endpoint=anchor.endpoint,
                event_time=anchor.observed_at,
                ingested_at=receipt,
                rule_id="RF-REPLAY-ENCODED-PS" if suspicious else "RF-REPLAY-OBSERVATION",
                severity="high" if suspicious else "low",
                provenance=replay_provenance(
                    snapshot, tuple(event.event_id for event in ordered)
                ),
            )
        )
    return tuple(sorted(alerts, key=lambda alert: (alert.event_time, alert.alert_id)))


class ReplaySource:
    def __init__(
        self,
        batch: ReplayBatch,
        *,
        ingested_at: datetime,
        speed: float = 0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        try:
            valid_speed = not isinstance(speed, bool) and math.isfinite(speed) and speed >= 0
        except (TypeError, OverflowError):
            valid_speed = False
        if not valid_speed:
            raise ReplayError("Replay speed must be finite and nonnegative")
        self._alerts = make_alerts(batch, ingested_at=ingested_at)
        self._speed = speed
        self._sleep = sleep

    async def ingest(self) -> AsyncIterator[Alert]:
        previous: datetime | None = None
        for alert in self._alerts:
            if previous is not None and self._speed > 0:
                delay = max(0.0, (alert.event_time - previous).total_seconds()) / self._speed
                if delay:
                    await self._sleep(delay)
            yield Alert.model_validate(alert.model_dump(mode="json"))
            previous = alert.event_time
