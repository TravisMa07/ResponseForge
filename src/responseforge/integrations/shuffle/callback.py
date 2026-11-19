"""Credential-safe application callback transport; no installed Shuffle app claim."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Literal

import httpx

from responseforge.contracts import Contract, PlaybookRun
from responseforge.integrations.shuffle.models import ShuffleConfig, ShuffleError, canonical_uuid
from responseforge.runtime import CallbackAcknowledgement, WorkflowCallback


def _now() -> datetime:
    return datetime.now(UTC)


def _nonce() -> str:
    return token_urlsafe(32)


@dataclass(frozen=True)
class CallbackConfig:
    base_url: str = field(repr=False)
    api_key: str = field(repr=False)
    workflow_ids: frozenset[str]
    timeout: float = 5.0
    max_response_bytes: int = 65536
    ca_file: str | Path | None = field(default=None, repr=False)
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        checked = ShuffleConfig(
            base_url=self.base_url,
            api_key=self.api_key,
            workflow_ids=self.workflow_ids,
            timeout=self.timeout,
            read_attempts=1,
            max_response_bytes=self.max_response_bytes,
            ca_file=self.ca_file,
            allow_loopback_http=self.allow_loopback_http,
        )
        object.__setattr__(self, "base_url", checked.base_url)
        object.__setattr__(self, "workflow_ids", checked.workflow_ids)


class CallbackReceipt(Contract):
    callback: WorkflowCallback
    delivery: Literal["accepted", "rejected", "uncertain"]


class CallbackTransport:
    def __init__(
        self,
        config: CallbackConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], datetime] = _now,
        nonce_factory: Callable[[], str] = _nonce,
    ) -> None:
        self.config = config
        self._transport = transport
        self._clock = clock
        self._nonce_factory = nonce_factory

    def _tls(self) -> bool | ssl.SSLContext:
        if self.config.ca_file is None:
            return True
        try:
            return ssl.create_default_context(cafile=str(self.config.ca_file))
        except (OSError, ssl.SSLError, ValueError):
            raise ShuffleError("invalid", "Invalid callback trusted CA configuration") from None

    def _prepared(self, item: WorkflowCallback) -> tuple[WorkflowCallback, str, str]:
        try:
            if (
                not isinstance(item, WorkflowCallback)
                or set(item.__dict__) - set(WorkflowCallback.model_fields)
                or item.__pydantic_extra__
            ):
                # Pydantic model_copy can place unknown keys in __dict__ even
                # under extra=forbid; model_dump would silently discard them.
                raise ValueError
            checked = WorkflowCallback.model_validate(item.model_dump(mode="json", warnings=False))
            canonical_uuid(checked.run_id)
            canonical_uuid(checked.workflow_id)
            if checked.workflow_id not in self.config.workflow_ids:
                raise ValueError
            sent_at = self._clock()
            if not isinstance(sent_at, datetime) or sent_at.utcoffset() != timedelta(0):
                raise ValueError
            nonce = self._nonce_factory()
            if (
                not isinstance(nonce, str)
                or not 1 <= len(nonce) <= 128
                or nonce != nonce.strip()
                or any(ord(c) < 32 or ord(c) >= 127 for c in nonce)
            ):
                raise ValueError
            return checked, sent_at.isoformat(), nonce
        except Exception:
            raise ShuffleError("invalid", "Invalid callback request configuration") from None

    @staticmethod
    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate JSON member")
            result[name] = value
        return result

    @staticmethod
    def _constant(value: str) -> Any:
        raise ValueError("Non-finite JSON is not permitted")

    async def _delivery(
        self, client: httpx.AsyncClient, item: WorkflowCallback
    ) -> Literal["accepted", "rejected", "uncertain"]:
        async with client.stream(
            "POST", "/v1/integrations/shuffle/callback", json=item.model_dump(mode="json")
        ) as response:
            if response.status_code in {401, 403, 409, 422}:
                return "rejected"
            if response.status_code != 200:
                return "uncertain"
            if response.headers.get("content-encoding", "identity").lower().strip() != "identity":
                return "uncertain"
            length = response.headers.get("content-length")
            if length is not None and (
                not length.isdecimal() or int(length) > self.config.max_response_bytes
            ):
                return "uncertain"
            raw = bytearray()
            if response.is_stream_consumed:
                # An injected transport may return already-buffered content. Its
                # allocation belongs to that transport, but the same cap applies.
                if len(response.content) > self.config.max_response_bytes:
                    return "uncertain"
                raw.extend(response.content)
            else:
                async for chunk in response.aiter_raw(
                    chunk_size=min(65536, self.config.max_response_bytes + 1)
                ):
                    if len(raw) + len(chunk) > self.config.max_response_bytes:
                        return "uncertain"
                    raw.extend(chunk)
            document: object = json.loads(
                raw.decode("utf-8"), object_pairs_hook=self._object, parse_constant=self._constant
            )
            if not isinstance(document, dict):
                return "uncertain"
            if "accepted" in document or "vendor_verified" in document:
                echoed: PlaybookRun | CallbackAcknowledgement = (
                    CallbackAcknowledgement.model_validate(document)
                )
            else:
                echoed = PlaybookRun.model_validate(document)
                if echoed.ended_at is None:
                    return "uncertain"
            for name in ("run_id", "incident_id", "workflow_id", "correlation_id", "status"):
                if getattr(echoed, name) != getattr(item, name):
                    return "uncertain"
            return "accepted"

    async def send(self, item: WorkflowCallback) -> CallbackReceipt:
        """Send once; a lost acknowledgement must be reconciled by the caller."""
        checked, sent_at, nonce = self._prepared(item)
        verify = self._tls()
        delivery: Literal["accepted", "rejected", "uncertain"] = "uncertain"
        try:
            async with asyncio.timeout(self.config.timeout):
                async with httpx.AsyncClient(
                    base_url=self.config.base_url,
                    headers={
                        "Authorization": "Bearer " + self.config.api_key,
                        "X-Request-Timestamp": sent_at,
                        "X-Request-Nonce": nonce,
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                    timeout=self.config.timeout,
                    verify=verify,
                    follow_redirects=False,
                    trust_env=False,
                    transport=self._transport,
                ) as client:
                    delivery = await self._delivery(client, checked)
        except Exception:
            # Neither vendor bodies nor request/transport exceptions can escape
            # into action results or logs, including an ambiguous acceptance.
            delivery = "uncertain"
        return CallbackReceipt(callback=checked, delivery=delivery)
