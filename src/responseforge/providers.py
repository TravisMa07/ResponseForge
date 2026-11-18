"""Adapter interfaces; no adapter may substitute live failure with simulation."""

from collections.abc import AsyncIterator
from typing import Protocol

from responseforge.contracts import (
    ActionCapability,
    ActionExecution,
    Alert,
    ApprovedAction,
    CollectionRequest,
    CollectionResult,
    EndpointRef,
    Evidence,
    Incident,
    VerificationResult,
)


class AlertSource(Protocol):
    def ingest(self) -> AsyncIterator[Alert]: ...


class EvidenceProvider(Protocol):
    async def list_evidence(self, incident: Incident) -> tuple[Evidence, ...]: ...

    async def collect(self, request: CollectionRequest) -> CollectionResult: ...


class ResponseProvider(Protocol):
    async def capabilities(self, endpoint: EndpointRef) -> tuple[ActionCapability, ...]: ...

    async def execute(self, action: ApprovedAction) -> ActionExecution: ...

    async def verify(self, execution: ActionExecution) -> VerificationResult: ...
