"""Internal replay shapes. Source fields are data, never executable instructions."""

import hashlib
import json
from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, StringConstraints, model_validator

from responseforge.contracts import Contract, EndpointRef, Id, Sha256, UtcDateTime

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


class ReplayBatch(Contract):
    source_id: Id
    sha256: Sha256
    events: tuple[RecordedEvent, ...]
    quarantine: tuple[QuarantineItem, ...]
    duplicates: Annotated[StrictInt, Field(ge=0)]

    @model_validator(mode="after")
    def bounded_events(self) -> Self:
        if len(self.events) > 1000:
            raise ValueError("replay record limit exceeded")
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
