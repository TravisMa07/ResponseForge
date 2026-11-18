"""Durable simulated response adapter: never contacts or modifies an endpoint.

The SQLite file contains only lab state. Carrier validation here does not replace
server authentication/authorization in CaseService.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import StrictBool, TypeAdapter, ValidationError

from responseforge.contracts import (
    ActionCapability,
    ActionExecution,
    ActionProposal,
    ActionType,
    ApprovedAction,
    Contract,
    EndpointRef,
    Id,
    Mode,
    VerificationResult,
)

_APPLICATION_ID = 0x52464D4B  # RFMK, separate from the core case database.
_VERSION = 1
_SUPPORTED = frozenset(
    {
        ActionType.TERMINATE_PROCESS,
        ActionType.ISOLATE_HOST,
        ActionType.UNISOLATE_HOST,
        ActionType.TEST_MARKER,
    }
)
T = TypeVar("T", bound=Contract)


class MockError(ValueError):
    """A sanitized failure in the simulated adapter."""


class _State(Contract):
    running_processes: tuple[Id, ...]
    isolated: StrictBool
    markers: tuple[Id, ...] = ()


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _validated(model: type[T], value: T) -> T:
    if not isinstance(value, model):
        raise MockError("Invalid simulated adapter contract")
    try:
        return model.model_validate(value.model_dump(mode="json", warnings=False))
    except (ValidationError, ValueError, TypeError):
        raise MockError("Invalid simulated adapter contract") from None


def _read(model: type[T], value: str) -> T:
    try:
        return model.model_validate_json(value)
    except (ValidationError, ValueError, TypeError):
        raise MockError("Invalid stored simulated adapter contract") from None


class MockResponseProvider:
    """Persistent replay-only state and receipts, with explicit fault injection."""

    name = "mock-edr"
    version = "1.0"

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        fault: Literal[
            "none", "fail_before_effect", "error_after_effect", "timeout_after_effect"
        ] = "none",
    ) -> None:
        if str(path) == ":memory:":
            raise MockError("Simulated state requires a file-backed database")
        if fault not in {
            "none",
            "fail_before_effect",
            "error_after_effect",
            "timeout_after_effect",
        }:
            raise MockError("Unknown simulated fault mode")
        self.path = Path(path)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.fault = fault
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._transaction() as connection:
                application = connection.execute("PRAGMA application_id").fetchone()[0]
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                names = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                    )
                }
                if application == 0 and version == 0 and not names:
                    connection.execute(
                        "CREATE TABLE endpoints (endpoint_id TEXT PRIMARY KEY, "
                        "canonical TEXT NOT NULL, seed TEXT NOT NULL, state TEXT NOT NULL)"
                    )
                    connection.execute(
                        "CREATE TABLE receipts (proposal_id TEXT PRIMARY KEY, "
                        "idempotency_key TEXT NOT NULL UNIQUE, proposal TEXT NOT NULL, "
                        "receipt TEXT NOT NULL, endpoint_id TEXT NOT NULL, "
                        "changed INTEGER NOT NULL CHECK(changed IN (0,1)), "
                        "FOREIGN KEY(endpoint_id) REFERENCES endpoints(endpoint_id))"
                    )
                    connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {_VERSION}")
                elif not (
                    application == _APPLICATION_ID
                    and version == _VERSION
                    and {"endpoints", "receipts"} <= names
                ):
                    raise MockError("Foreign or unsupported simulated state database")
        except (OSError, sqlite3.Error):
            raise MockError("Simulated state database unavailable") from None

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise MockError("Simulated adapter clock must be aware")
        return value.astimezone(UTC)

    def seed_endpoint(
        self, endpoint: EndpointRef, *, processes: tuple[str, ...] = (), isolated: bool = False
    ) -> None:
        endpoint = _validated(EndpointRef, endpoint)
        try:
            process_ids = tuple(sorted(set(TypeAdapter(tuple[Id, ...]).validate_python(processes))))
            state = _State(running_processes=process_ids, isolated=isolated)
        except (ValidationError, ValueError, TypeError):
            raise MockError("Invalid simulated endpoint seed") from None
        canonical = _json(endpoint.model_dump(mode="json"))
        seed = _json(state.model_dump(mode="json"))
        try:
            with self._transaction() as connection:
                old = connection.execute(
                    "SELECT canonical,seed FROM endpoints WHERE endpoint_id=?",
                    (endpoint.endpoint_id,),
                ).fetchone()
                if old is not None:
                    if old != (canonical, seed):
                        raise MockError("Simulated endpoint seed conflicts with original identity")
                    return
                connection.execute(
                    "INSERT INTO endpoints(endpoint_id,canonical,seed,state) VALUES (?,?,?,?)",
                    (endpoint.endpoint_id, canonical, seed, seed),
                )
        except sqlite3.Error:
            raise MockError("Simulated endpoint seed unavailable") from None

    def _endpoint(
        self, connection: sqlite3.Connection, endpoint: EndpointRef
    ) -> tuple[_State, _State]:
        row = connection.execute(
            "SELECT canonical,seed,state FROM endpoints WHERE endpoint_id=?",
            (endpoint.endpoint_id,),
        ).fetchone()
        if row is None or _read(EndpointRef, row[0]) != endpoint:
            raise MockError("Unknown simulated endpoint identity")
        return _read(_State, row[1]), _read(_State, row[2])

    def snapshot(self, endpoint: EndpointRef) -> dict[str, Any]:
        endpoint = _validated(EndpointRef, endpoint)
        try:
            with self._transaction() as connection:
                _, state = self._endpoint(connection, endpoint)
                count = connection.execute(
                    "SELECT COALESCE(SUM(changed),0) FROM receipts WHERE endpoint_id=?",
                    (endpoint.endpoint_id,),
                ).fetchone()[0]
                return {
                    "endpoint_id": endpoint.endpoint_id,
                    "isolated": state.isolated,
                    "running_processes": list(state.running_processes),
                    "markers": list(state.markers),
                    "effect_count": int(count),
                }
        except sqlite3.Error:
            raise MockError("Simulated endpoint state unavailable") from None

    async def capabilities(self, endpoint: EndpointRef) -> tuple[ActionCapability, ...]:
        endpoint = _validated(EndpointRef, endpoint)
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    "SELECT canonical FROM endpoints WHERE endpoint_id=?", (endpoint.endpoint_id,)
                ).fetchone()
                if row is None or _read(EndpointRef, row[0]) != endpoint:
                    return ()
        except sqlite3.Error:
            raise MockError("Simulated capabilities unavailable") from None
        return tuple(
            ActionCapability(
                provider=self.name, provider_version=self.version, mode=Mode.REPLAY, action=action
            )
            for action in sorted(_SUPPORTED)
        )

    @staticmethod
    def _resource(proposal: ActionProposal, seed: _State) -> None:
        resource = proposal.target.resource
        if proposal.action not in _SUPPORTED:
            raise MockError("Unsupported simulated action")
        if proposal.action == ActionType.TERMINATE_PROCESS:
            allowed = {"process:" + value for value in seed.running_processes}
        elif proposal.action in {ActionType.ISOLATE_HOST, ActionType.UNISOLATE_HOST}:
            allowed = {"host:" + proposal.target.endpoint.endpoint_id}
        else:
            allowed = {"marker:demo"}
        if resource not in allowed:
            raise MockError("Simulated action resource is not allowlisted")

    @staticmethod
    def _effect(proposal: ActionProposal, state: _State) -> _State:
        values = state.model_dump(mode="json")
        if proposal.action == ActionType.TERMINATE_PROCESS:
            process = proposal.target.resource.removeprefix("process:")
            values["running_processes"] = [p for p in state.running_processes if p != process]
        elif proposal.action == ActionType.ISOLATE_HOST:
            values["isolated"] = True
        elif proposal.action == ActionType.UNISOLATE_HOST:
            values["isolated"] = False
        elif proposal.action == ActionType.TEST_MARKER:
            values["markers"] = sorted(set(state.markers) | {proposal.target.resource})
        return _State.model_validate(values)

    def _receipt(self, proposal: ActionProposal, *, failed: bool) -> ActionExecution:
        now = self._now()
        return ActionExecution(
            execution_id="exec-" + proposal.proposal_id,
            proposal_id=proposal.proposal_id,
            incident_id=proposal.incident_id,
            provider=self.name,
            mode=Mode.REPLAY,
            dispatch_state="failed" if failed else "acknowledged",
            requested_at=now,
            updated_at=now,
            verification=VerificationResult(
                status="pending",
                simulated=True,
                verified_live=False,
                detail="Simulated delivery receipt; independent verification required",
            ),
            error="injected_failure_before_effect" if failed else None,
        )

    def _bound_receipt(self, proposal: ActionProposal, payload: str) -> ActionExecution:
        receipt = _read(ActionExecution, payload)
        if (
            receipt.execution_id != "exec-" + proposal.proposal_id
            or receipt.proposal_id != proposal.proposal_id
            or receipt.incident_id != proposal.incident_id
            or receipt.provider != self.name
            or receipt.mode != Mode.REPLAY
            or proposal.mode != Mode.REPLAY
            or receipt.requested_at < proposal.created_at
            or receipt.dispatch_state not in {"acknowledged", "failed"}
            or receipt.verification.status != "pending"
            or receipt.requested_at != receipt.updated_at
        ):
            raise MockError("Stored simulated receipt does not match proposal scope")
        return receipt

    async def execute(self, action: ApprovedAction) -> ActionExecution:
        action = _validated(ApprovedAction, action)
        proposal, approval = action.proposal, action.approval
        if proposal.mode != Mode.REPLAY:
            raise MockError("Simulated provider refuses live mode")
        if approval.proposal != proposal or approval.decision != "approved":
            raise MockError("Simulated action requires an exact approved snapshot")
        try:
            with self._transaction() as connection:
                rows = connection.execute(
                    "SELECT proposal,receipt FROM receipts WHERE proposal_id=? OR idempotency_key=?",
                    (proposal.proposal_id, proposal.idempotency_key),
                ).fetchall()
                if rows:
                    if len(rows) != 1 or _read(ActionProposal, rows[0][0]) != proposal:
                        raise MockError("Simulated action idempotency scope conflicts")
                    return self._bound_receipt(proposal, rows[0][1])
                now = self._now()
                if (
                    not proposal.created_at
                    <= approval.decided_at
                    <= now
                    < approval.expires_at
                    <= proposal.expires_at
                ):
                    raise MockError("Simulated action approval is not currently valid")
                seed, state = self._endpoint(connection, proposal.target.endpoint)
                self._resource(proposal, seed)
                failed = self.fault == "fail_before_effect"
                changed = state if failed else self._effect(proposal, state)
                receipt = self._receipt(proposal, failed=failed)
                connection.execute(
                    "UPDATE endpoints SET state=? WHERE endpoint_id=?",
                    (_json(changed.model_dump(mode="json")), proposal.target.endpoint.endpoint_id),
                )
                connection.execute(
                    "INSERT INTO receipts(proposal_id,idempotency_key,proposal,receipt,endpoint_id,changed) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        proposal.proposal_id,
                        proposal.idempotency_key,
                        _json(proposal.model_dump(mode="json")),
                        _json(receipt.model_dump(mode="json")),
                        proposal.target.endpoint.endpoint_id,
                        int(changed != state),
                    ),
                )
        except sqlite3.Error:
            raise MockError("Simulated response persistence failed") from None
        # Effects and receipts have committed; injected uncertainty is never rollback.
        if self.fault == "error_after_effect":
            raise MockError("Injected simulated delivery uncertainty")
        if self.fault == "timeout_after_effect":
            await asyncio.Event().wait()
        return receipt

    async def verify(self, execution: ActionExecution) -> VerificationResult:
        execution = _validated(ActionExecution, execution)
        if (
            execution.mode != Mode.REPLAY
            or execution.provider != self.name
            or execution.execution_id != "exec-" + execution.proposal_id
        ):
            raise MockError("Simulated execution identity does not match provider")
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    "SELECT proposal,receipt FROM receipts WHERE proposal_id=?",
                    (execution.proposal_id,),
                ).fetchone()
                if row is None:
                    return VerificationResult(
                        status="pending",
                        simulated=True,
                        verified_live=False,
                        detail="No original simulated delivery receipt exists",
                    )
                proposal = _read(ActionProposal, row[0])
                receipt = self._bound_receipt(proposal, row[1])
                if any(
                    getattr(execution, name) != getattr(receipt, name)
                    for name in ("execution_id", "proposal_id", "incident_id", "provider", "mode")
                ):
                    raise MockError(
                        "Simulated execution correlation conflicts with original receipt"
                    )
                if execution.requested_at > receipt.requested_at:
                    raise MockError(
                        "Simulated execution request time conflicts with original receipt"
                    )
                if receipt.dispatch_state == "failed":
                    verified = False
                else:
                    seed, state = self._endpoint(connection, proposal.target.endpoint)
                    self._resource(proposal, seed)
                    verified = self._effect(proposal, state) == state
                return VerificationResult(
                    status="verified" if verified else "failed",
                    simulated=True,
                    verified_live=False,
                    checked_at=self._now(),
                    detail="Original simulated effect state verified"
                    if verified
                    else "Original simulated effect is not present",
                )
        except sqlite3.Error:
            raise MockError("Simulated verification unavailable") from None
