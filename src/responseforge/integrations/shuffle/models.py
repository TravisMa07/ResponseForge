"""Strict transport boundaries. Vendor receipts are never endpoint-effect proof."""

import hashlib
import ipaddress
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AfterValidator, Field, StrictInt, model_validator

from responseforge.contracts import Contract, Id, Mode, Sha256, UtcDateTime


def canonical_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise ValueError("Canonical nonempty UUID required") from None
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("Canonical nonempty UUID required")
    return value


UUIDString = Annotated[Id, AfterValidator(canonical_uuid)]


class ShuffleError(Exception):
    def __init__(
        self, kind: Literal["invalid", "rejected", "unavailable", "uncertain"], message: str
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class ShuffleConfig:
    base_url: str = field(repr=False)
    api_key: str = field(repr=False)
    workflow_ids: frozenset[str]
    timeout: float = 5.0
    read_attempts: int = 3
    max_response_bytes: int = 1048576
    allow_loopback_http: bool = False
    ca_file: str | Path | None = field(default=None, repr=False)
    org_id: str | None = None

    def __post_init__(self) -> None:
        try:
            url = urlsplit(self.base_url)
            port = url.port
            if (
                not url.hostname
                or url.username is not None
                or url.password is not None
                or url.query
                or url.fragment
                or url.path not in {"", "/"}
                or any(ord(c) <= 32 or ord(c) >= 127 for c in self.base_url)
                or url.scheme not in {"http", "https"}
                or (port is not None and not 1 <= port <= 65535)
            ):
                raise ValueError
            if type(self.allow_loopback_http) is not bool:
                raise ValueError
            if url.scheme == "http" and not (
                self.allow_loopback_http and ipaddress.ip_address(url.hostname).is_loopback
            ):
                raise ValueError
            if not 36 <= len(self.api_key) <= 4096 or any(
                ord(c) <= 32 or ord(c) >= 127 for c in self.api_key
            ):
                raise ValueError
            if (
                isinstance(self.timeout, bool)
                or not math.isfinite(self.timeout)
                or not 0 < self.timeout <= 60
            ):
                raise ValueError
            if type(self.read_attempts) is not int or not 1 <= self.read_attempts <= 3:
                raise ValueError
            if (
                type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= 1048576
            ):
                raise ValueError
            allowed = frozenset(canonical_uuid(x) for x in self.workflow_ids)
            if self.org_id is not None:
                canonical_uuid(self.org_id)
        except (TypeError, ValueError, AttributeError):
            raise ShuffleError("invalid", "Invalid Shuffle transport configuration") from None
        object.__setattr__(self, "workflow_ids", allowed)
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))


class ShuffleArgument(Contract):
    incident_id: Id
    run_id: UUIDString
    correlation_id: Id
    mode: Mode


class WorkflowArtifact(Contract):
    workflow_id: UUIDString
    sha256: Sha256
    action_count: Annotated[StrictInt, Field(ge=1)]


class StartReceipt(Contract):
    workflow_id: UUIDString
    execution_id: UUIDString
    accepted: Literal[True] = True


class VendorExecution(Contract):
    workflow_id: UUIDString
    execution_id: UUIDString
    argument: ShuffleArgument
    workflow_sha256: Sha256 | None = None
    vendor_status: Literal["EXECUTING", "WAITING", "FINISHED", "FAILURE", "ABORTED", "SUCCESS"]

    @model_validator(mode="after")
    def correlated(self) -> Self:
        if self.execution_id != self.argument.run_id:
            raise ValueError("Execution argument differs from run identity")
        return self


class WorkflowBinding(Contract):
    version: Id
    sha256: Sha256


class DeliveryRecord(Contract):
    record_type: Literal["shuffle_delivery"] = "shuffle_delivery"
    argument: ShuffleArgument
    workflow_id: UUIDString
    workflow_version: Id
    workflow_sha256: Sha256
    origin: Id
    state: Literal["reserved", "accepted", "uncertain", "rejected", "finished", "failed"]
    created_at: UtcDateTime
    updated_at: UtcDateTime
    vendor_status: (
        Literal["EXECUTING", "WAITING", "FINISHED", "FAILURE", "ABORTED", "SUCCESS"] | None
    ) = None

    @model_validator(mode="after")
    def chronology(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("Delivery update precedes reservation")
        if self.state == "finished" and self.vendor_status not in {"FINISHED", "SUCCESS"}:
            raise ValueError("Finished delivery requires a finished workflow status")
        if self.state == "failed" and self.vendor_status not in {"FAILURE", "ABORTED"}:
            raise ValueError("Failed delivery requires a failed workflow status")
        return self


class ShuffleStartRequest(Contract):
    workflow_id: UUIDString
    run_id: UUIDString


class ShuffleReconcileRequest(Contract):
    run_id: UUIDString


def workflow_artifact(document: dict[str, Any]) -> WorkflowArtifact:
    try:
        workflow_id = canonical_uuid(document["id"])
        actions = document["actions"]
        if (
            not isinstance(actions, list)
            or not actions
            or any(not isinstance(x, dict) for x in actions)
        ):
            raise ValueError
        projection = {"id": workflow_id, "actions": actions}
        for name in ("branches", "triggers", "workflow_variables", "execution_variables"):
            value = document.get(name, [])
            if not isinstance(value, list):
                raise ValueError
            projection[name] = value
        projection["start"] = document.get("start", "")
        projection["configuration"] = document.get("configuration", {})
        if not isinstance(projection["start"], str) or not isinstance(
            projection["configuration"], dict
        ):
            raise ValueError
        raw = json.dumps(
            projection, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(raw) > 1048576:
            raise ValueError
        return WorkflowArtifact(
            workflow_id=workflow_id,
            sha256=hashlib.sha256(raw).hexdigest(),
            action_count=len(actions),
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ShuffleError("invalid", "Invalid Shuffle workflow artifact") from None
