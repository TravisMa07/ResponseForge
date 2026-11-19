"""Internal replay shapes. Source fields are data, never executable instructions."""

import hashlib
import json
import re
from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, StringConstraints, model_validator

from responseforge.contracts import Contract, EndpointRef, Id, Sha256, UtcDateTime
from responseforge.dataset_contracts import validate_source_path

FieldName = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
FieldValue = Annotated[str, StringConstraints(strict=True, max_length=4096)]


class RecordedEvent(Contract):
    event_id: Id
    scenario_id: Id
    endpoint: EndpointRef
    observed_at: UtcDateTime
    artifact: Literal["process", "network", "file", "persistence"]
    fields: dict[FieldName, FieldValue] = Field(max_length=32)


class QuarantineItem(Contract):
    line: Annotated[StrictInt, Field(ge=1)]
    code: Literal["invalid_json", "invalid_schema", "duplicate_conflict"]


class ReplayOrigin(Contract):
    source: Literal["splunk-attack-data"] = "splunk-attack-data"
    source_ref: Id
    transformation: Literal["sysmon-event1-v1", "windows-events-v1"] = "sysmon-event1-v1"
    selected_event_ids: tuple[Id, ...] | None = None

    @model_validator(mode="after")
    def pinned_source(self) -> Self:
        match = re.fullmatch(
            r"https://github\.com/splunk/attack_data/blob/[0-9a-f]{40}/(datasets/.+)",
            self.source_ref,
        )
        if match is None:
            raise ValueError("Recorded source must be a pinned dataset URL")
        validate_source_path(match[1])
        if self.selected_event_ids is not None and (
            self.transformation != "windows-events-v1"
            or not self.selected_event_ids
            or tuple(sorted(set(self.selected_event_ids))) != self.selected_event_ids
        ):
            raise ValueError("Invalid recorded source selection")
        return self


class ReplayBatch(Contract):
    source_id: Id
    sha256: Sha256
    origin: ReplayOrigin | None = None
    events: tuple[RecordedEvent, ...]
    quarantine: tuple[QuarantineItem, ...]
    duplicates: Annotated[StrictInt, Field(ge=0)]

    @model_validator(mode="after")
    def bounded_events(self) -> Self:
        if len(self.events) > 1000:
            raise ValueError("replay record limit exceeded")
        if self.origin is not None and self.origin.selected_event_ids is not None:
            if (
                len(self.events) != len(self.origin.selected_event_ids)
                or tuple(sorted({event.event_id for event in self.events})) != self.origin.selected_event_ids
            ):
                raise ValueError("Recorded selection differs from events")
        return self


class ReplayRunSummary(Contract):
    incident_ids: tuple[Id, ...]
    report_paths: tuple[str, ...]
    quarantine: tuple[QuarantineItem, ...]
    duplicates: Annotated[StrictInt, Field(ge=0)]
    simulated: Literal[True] = True
    verified_live: Literal[False] = False


def digest(value: object) -> str:
    """Canonical identity hashing shared across replay and its integration."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
