"""Source-derived Shuffle HTTP transport; mutating POSTs are never retried."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx

from responseforge.integrations.shuffle.models import (
    ShuffleArgument,
    ShuffleConfig,
    ShuffleError,
    StartReceipt,
    VendorExecution,
    WorkflowArtifact,
    canonical_uuid,
    workflow_artifact,
)


class _Transient(Exception):
    """Internal retry signal with no vendor/request data."""


def _constant(value: str) -> Any:
    raise ValueError("Non-finite JSON is not permitted")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _callback_status(result: dict[str, Any]) -> Literal["SUCCESS", "FAILURE"] | None:
    """Project one native receipt for the exact reviewed callback node, never its body."""
    graph = result.get("workflow")
    if not isinstance(graph, dict) or not isinstance(graph.get("actions"), list):
        return None
    nodes = [
        node
        for node in graph["actions"]
        if isinstance(node, dict)
        and node.get("app_name") == "responseforge_callback"
        and node.get("app_version") == "1.0.0"
        and node.get("name") == "callback"
    ]
    results = result.get("results")
    if len(nodes) != 1 or not isinstance(results, list):
        return None
    node = nodes[0]
    try:
        canonical_uuid(node["id"])
    except (KeyError, ValueError, TypeError):
        return None
    receipts = [
        item
        for item in results
        if isinstance(item, dict)
        and isinstance(item.get("action"), dict)
        and (
            item["action"].get("id") == node.get("id")
            or item["action"].get("app_name") == "responseforge_callback"
        )
    ]
    if len(receipts) != 1:
        return None
    receipt = receipts[0]
    if receipt["action"].get("app_id") not in (None, "", node.get("app_id")):
        return None
    if receipt.get("execution_id") != result.get("execution_id") or any(
        receipt["action"].get(key) != node.get(key)
        for key in ("id", "app_name", "app_version", "name")
    ):
        return None
    status = receipt.get("status")
    if status == "SUCCESS":
        return "SUCCESS"
    if status == "FAILURE":
        return "FAILURE"
    return None


class ShuffleTransport:
    """Bounded transport only; a successful workflow is not endpoint proof."""

    def __init__(
        self,
        config: ShuffleConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.config = config
        self._transport = transport
        self._sleep = sleep

    def _uuid(self, value: str) -> str:
        try:
            return canonical_uuid(value)
        except (ValueError, TypeError, AttributeError):
            raise ShuffleError("invalid", "Invalid Shuffle identity") from None

    def _workflow(self, value: str) -> str:
        value = self._uuid(value)
        if value not in self.config.workflow_ids:
            raise ShuffleError("invalid", "Shuffle workflow is not allowlisted")
        return value

    @staticmethod
    def _argument(value: ShuffleArgument, execution_id: str) -> ShuffleArgument:
        try:
            if not isinstance(value, ShuffleArgument):
                raise ValueError
            checked = ShuffleArgument.model_validate(value.model_dump(mode="json", warnings=False))
            if checked.run_id != execution_id:
                raise ValueError
            return checked
        except (ValueError, TypeError, AttributeError):
            raise ShuffleError("invalid", "Invalid Shuffle execution argument") from None

    def _tls(self) -> bool | ssl.SSLContext:
        if self.config.ca_file is None:
            return True
        try:
            return ssl.create_default_context(cafile=str(self.config.ca_file))
        except (OSError, ssl.SSLError, ValueError):
            raise ShuffleError("invalid", "Invalid Shuffle trusted CA configuration") from None

    @staticmethod
    def _json(document: dict[str, Any]) -> bytes:
        try:
            if not isinstance(document, dict):
                raise ValueError
            encoded = json.dumps(document, allow_nan=False, separators=(",", ":")).encode()
            if len(encoded) > 1048576:
                raise ValueError
            return encoded
        except (ValueError, TypeError, RecursionError):
            raise ShuffleError("invalid", "Invalid Shuffle request document") from None

    async def _once(
        self, method: str, path: str, encoded: bytes | None, *, mutation: bool
    ) -> dict[str, Any]:
        failure_kind: Literal["uncertain", "unavailable"] = (
            "uncertain" if mutation else "unavailable"
        )
        headers = {
            "Authorization": "Bearer " + self.config.api_key,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        if self.config.org_id is not None:
            headers["Org-Id"] = self.config.org_id
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=headers,
            timeout=self.config.timeout,
            verify=self._tls(),
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
        ) as client:
            async with client.stream(method, path, content=encoded) as response:
                if response.status_code >= 500:
                    raise _Transient
                if response.status_code != 200:
                    if 300 <= response.status_code < 500:
                        raise ShuffleError("rejected", "Shuffle request was rejected")
                    raise ShuffleError(failure_kind, "Shuffle response is unavailable")
                # Do not allow an unexpected compressed body to expand before the cap.
                if (
                    response.headers.get("content-encoding", "identity").lower().strip()
                    != "identity"
                ):
                    raise ShuffleError(failure_kind, "Shuffle response is invalid")
                length = response.headers.get("content-length")
                if length is not None and (
                    not length.isdecimal() or int(length) > self.config.max_response_bytes
                ):
                    raise ShuffleError(failure_kind, "Shuffle response exceeds permitted bounds")
                raw = bytearray()
                if response.is_stream_consumed:
                    # Injected transports may construct an already-buffered Response.
                    # Its allocation belongs to the transport, but still enforce the
                    # exact same parsing cap before copying or accepting its content.
                    if len(response.content) > self.config.max_response_bytes:
                        raise ShuffleError(
                            failure_kind, "Shuffle response exceeds permitted bounds"
                        )
                    raw.extend(response.content)
                else:
                    async for chunk in response.aiter_raw(
                        chunk_size=min(65536, self.config.max_response_bytes + 1)
                    ):
                        if len(raw) + len(chunk) > self.config.max_response_bytes:
                            raise ShuffleError(
                                failure_kind, "Shuffle response exceeds permitted bounds"
                            )
                        raw.extend(chunk)
                try:
                    result: object = json.loads(
                        raw.decode("utf-8"), parse_constant=_constant, object_pairs_hook=_object
                    )
                    if not isinstance(result, dict):
                        raise ValueError
                    if "success" in result and result["success"] is not True:
                        raise ValueError
                except (ValueError, TypeError, RecursionError):
                    raise ShuffleError(failure_kind, "Shuffle response is invalid") from None
                return result

    async def _request(
        self,
        method: str,
        path: str,
        document: dict[str, Any] | None = None,
        *,
        mutation: bool = False,
    ) -> dict[str, Any]:
        encoded = None if document is None else self._json(document)
        attempts = 1 if mutation else self.config.read_attempts
        for attempt in range(attempts):
            try:
                async with asyncio.timeout(self.config.timeout):
                    return await self._once(method, path, encoded, mutation=mutation)
            except ShuffleError:
                raise
            except (
                _Transient,
                TimeoutError,
                httpx.TimeoutException,
                httpx.NetworkError,
                httpx.ProtocolError,
            ):
                if not mutation and attempt + 1 < attempts:
                    await self._sleep(0.1 * 2**attempt)
                    continue
                kind: Literal["uncertain", "unavailable"] = (
                    "uncertain" if mutation else "unavailable"
                )
                raise ShuffleError(kind, "Shuffle operation outcome is unavailable") from None
            except Exception:
                kind = "uncertain" if mutation else "unavailable"
                raise ShuffleError(kind, "Shuffle operation outcome is unavailable") from None
        raise ShuffleError("unavailable", "Shuffle read attempts exhausted")

    async def get_workflow(self, workflow_id: str) -> WorkflowArtifact:
        workflow_id = self._workflow(workflow_id)
        result = await self._request("GET", "/api/v1/workflows/" + workflow_id)
        try:
            artifact = workflow_artifact(result)
            if artifact.workflow_id != workflow_id:
                raise ValueError
            return artifact
        except Exception:
            raise ShuffleError("unavailable", "Shuffle workflow response is invalid") from None

    async def create_workflow(self, document: dict[str, Any]) -> WorkflowArtifact:
        try:
            if not isinstance(document, dict):
                raise ValueError
            actions = document.get("actions")
            if (
                not isinstance(actions, list)
                or not actions
                or any(not isinstance(x, dict) for x in actions)
            ):
                raise ValueError
            if "id" in document:
                self._uuid(document["id"])
            self._json(document)
        except Exception:
            raise ShuffleError("invalid", "Invalid Shuffle workflow import document") from None
        result = await self._request("POST", "/api/v1/workflows", document, mutation=True)
        try:
            return workflow_artifact(result)
        except Exception:
            raise ShuffleError(
                "uncertain", "Shuffle workflow creation outcome is uncertain"
            ) from None

    async def start_execution(
        self, workflow_id: str, execution_id: str, argument: ShuffleArgument
    ) -> StartReceipt:
        workflow_id, execution_id = self._workflow(workflow_id), self._uuid(execution_id)
        argument = self._argument(argument, execution_id)
        result = await self._request(
            "POST",
            "/api/v1/workflows/" + workflow_id + "/execute",
            {
                "execution_id": execution_id,
                "execution_argument": argument.model_dump_json(),
                "execution_source": "responseforge",
            },
            mutation=True,
        )
        if result.get("success") is not True or result.get("execution_id") != execution_id:
            raise ShuffleError("uncertain", "Shuffle start receipt is invalid")
        return StartReceipt(workflow_id=workflow_id, execution_id=execution_id)

    async def get_execution(
        self, workflow_id: str, execution_id: str, expected_argument: ShuffleArgument
    ) -> VendorExecution:
        workflow_id, execution_id = self._workflow(workflow_id), self._uuid(execution_id)
        expected_argument = self._argument(expected_argument, execution_id)
        result = await self._request(
            "POST", "/api/v1/streams/results", {"execution_id": execution_id}
        )
        try:
            if (
                result.get("execution_id") != execution_id
                or result.get("workflow_id") != workflow_id
            ):
                raise ValueError
            if "workflow" in result and (
                not isinstance(result["workflow"], dict)
                or result["workflow"].get("id") != workflow_id
            ):
                raise ValueError
            if not isinstance(result.get("execution_argument"), str):
                raise ValueError
            decoded_argument = json.loads(
                result["execution_argument"], parse_constant=_constant, object_pairs_hook=_object
            )
            if not isinstance(decoded_argument, dict):
                raise ValueError
            argument = ShuffleArgument.model_validate(decoded_argument)
            if argument != expected_argument:
                raise ValueError
            runtime_workflow = result.get("workflow")
            runtime_hash = None
            if isinstance(runtime_workflow, dict) and "actions" in runtime_workflow:
                runtime_hash = workflow_artifact(runtime_workflow).sha256
            return VendorExecution(
                workflow_sha256=runtime_hash,
                callback_status=_callback_status(result),
                workflow_id=workflow_id,
                execution_id=execution_id,
                argument=argument,
                vendor_status=result["status"],
            )
        except Exception:
            raise ShuffleError("unavailable", "Shuffle execution response is invalid") from None
