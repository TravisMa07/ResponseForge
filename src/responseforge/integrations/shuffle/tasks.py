"""Native fixed-purpose Shuffle tasks for the authenticated playbook facade.

One app invocation performs one bound core step. Shuffle owns the graph and the
server remains the authority for evidence, human approval and response effects.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import ssl
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import TypeAdapter

from responseforge.contracts import Sha256
from responseforge.integrations.shuffle.callback import CallbackConfig
from responseforge.integrations.shuffle.graphs import dispatch_selected
from responseforge.integrations.shuffle.models import (
    ShuffleArgument,
    TaskResult,
    UUIDString,
    canonical_uuid,
    workflow_artifact,
)
from responseforge.playbooks.models import PlaybookPlan, PlaybookProgress, PlaybookStepRequest

_STEPS = frozenset({"prepare", "gate", "dispatch"})
_METADATA = ("id", "app_id", "app_name", "app_version", "name")
_LIMIT = 1048576


class _Rejected(Exception):
    """A fixed core operation was explicitly rejected; never retain its body."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Ambiguous task JSON")
        value[key] = item
    return value


def _constant(value: str) -> Any:
    raise ValueError("Invalid task JSON number")


def _json(raw: str | bytes, limit: int = _LIMIT) -> dict[str, Any]:
    if len(raw.encode() if isinstance(raw, str) else raw) > limit:
        raise ValueError("Task JSON bounds exceeded")
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    if not isinstance(value, dict):
        raise ValueError("Task JSON must be an object")
    return dict(value)


async def _post(
    client: httpx.AsyncClient, url: str, document: dict[str, Any], *, token: str | None = None
) -> dict[str, Any]:
    headers = {"Accept-Encoding": "identity"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    async with asyncio.timeout(15):
        async with client.stream("POST", url, json=document, headers=headers) as response:
            if 400 <= response.status_code < 500:
                raise _Rejected("Task operation rejected")
            if (
                response.status_code != 200
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("Task operation unavailable")
            raw = bytearray()
            if response.is_stream_consumed:
                raw.extend(response.content)
                if len(raw) > _LIMIT:
                    raise ValueError("Task response bounds exceeded")
            else:
                async for chunk in response.aiter_raw(chunk_size=65536):
                    if len(raw) + len(chunk) > _LIMIT:
                        raise ValueError("Task response bounds exceeded")
                    raw.extend(chunk)
            return _json(bytes(raw))


def _worker_origin(raw: str, configured_raw: str) -> str:
    parsed, configured = urlsplit(raw), urlsplit(configured_raw)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(ord(char) < 33 or ord(char) > 126 for char in raw)
    ):
        raise ValueError("Invalid task worker origin")
    trusted = parsed.hostname == configured.hostname and parsed.port == configured.port
    if not trusted and parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
            trusted = any(
                address in ipaddress.ip_network(network)
                for network in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
        except ValueError:
            pass
    if not trusted:
        raise ValueError("Task worker origin is not trusted")
    return raw.rstrip("/")


def _input(
    environ: Mapping[str, str], config_path: Path
) -> tuple[CallbackConfig, dict[str, str], dict[str, Any], str, str, str]:
    if config_path.is_symlink() or config_path.stat().st_size > 16384:
        raise ValueError
    private = _json(config_path.read_text(), 16384)
    if set(private) - {
        "base_url",
        "api_key",
        "workflow_ids",
        "ca_file",
        "shuffle_backend",
        "workflow_graphs",
    }:
        raise ValueError
    config = CallbackConfig(
        base_url=private["base_url"],
        api_key=private["api_key"],
        workflow_ids=frozenset(private["workflow_ids"]),
        ca_file=private.get("ca_file"),
    )
    graphs = TypeAdapter(dict[UUIDString, Sha256]).validate_python(private["workflow_graphs"])
    if not graphs or not set(graphs) <= config.workflow_ids:
        raise ValueError
    action = _json(environ["ACTION"], 65536)
    if (
        action.get("app_name") != "responseforge_tasks"
        or action.get("app_version") != "1.0.0"
        or action.get("name") not in _STEPS
        or action.get("parameters") not in (None, [])
    ):
        raise ValueError
    canonical_uuid(action["id"])
    canonical_uuid(action["app_id"])
    run_id = canonical_uuid(environ["EXECUTIONID"])
    authorization = environ["AUTHORIZATION"]
    if not 16 <= len(authorization) <= 4096 or any(
        ord(char) < 33 or ord(char) > 126 for char in authorization
    ):
        raise ValueError
    origin = _worker_origin(
        environ["BASE_URL"], private.get("shuffle_backend", "http://shuffle-backend:5001")
    )
    return config, graphs, action, run_id, authorization, origin


def _original(
    execution: dict[str, Any], action: dict[str, Any], run_id: str, config: CallbackConfig
) -> PlaybookStepRequest:
    workflow_id = canonical_uuid(execution["workflow_id"])
    if workflow_id not in config.workflow_ids or execution.get("execution_id") != run_id:
        raise ValueError
    graph = execution["workflow"]
    if not isinstance(graph, dict) or graph.get("id") != workflow_id:
        raise ValueError
    actions = graph.get("actions")
    if not isinstance(actions, list):
        raise ValueError
    nodes = [node for node in actions if isinstance(node, dict) and node.get("id") == action["id"]]
    if (
        len(nodes) != 1
        or any(nodes[0].get(field) != action.get(field) for field in _METADATA)
        or nodes[0].get("parameters") not in (None, [])
    ):
        raise ValueError
    argument = ShuffleArgument.model_validate(_json(execution["execution_argument"], 65536))
    if argument.run_id != run_id or argument.mode.value != "replay":
        raise ValueError
    if (
        argument.incident_id in {".", ".."}
        or len(argument.incident_id) > 256
        or any(ord(char) < 33 or ord(char) > 126 for char in argument.incident_id)
    ):
        raise ValueError
    return PlaybookStepRequest(**argument.model_dump(mode="json"), workflow_id=workflow_id)


def _gate_kind(execution: dict[str, Any]) -> Literal["process", "persistence", "containment"]:
    nodes = [
        node
        for node in execution["workflow"]["actions"]
        if isinstance(node, dict)
        and node.get("app_name") == "responseforge_tasks"
        and node.get("app_version") == "1.0.0"
        and node.get("name") == "gate"
    ]
    if len(nodes) != 1:
        raise ValueError
    receipts = [
        item
        for item in execution.get("results", [])
        if isinstance(item, dict)
        and isinstance(item.get("action"), dict)
        and item["action"].get("id") == nodes[0].get("id")
    ]
    if len(receipts) != 1:
        raise ValueError
    body = TaskResult.model_validate(_json(receipts[0]["result"]))
    if body.kind is None:
        raise ValueError
    return body.kind


def _core_result(
    step: str,
    value: dict[str, Any],
    request: PlaybookStepRequest,
    expected_kind: Literal["process", "persistence", "containment"] | None,
) -> TaskResult:
    result: PlaybookPlan | PlaybookProgress
    if step == "prepare":
        result = PlaybookPlan.model_validate(value)
        status = "prepared"
    else:
        result = PlaybookProgress.model_validate(value)
        status = result.status
        execution = result.execution
        if execution is not None and (
            execution.incident_id != request.incident_id
            or execution.proposal_id != result.proposal_id
            or execution.mode != request.mode
        ):
            raise ValueError
        if result.status == "completed" and (
            execution is None
            or execution.verification.status != "verified"
            or not execution.verification.simulated
            or execution.verification.verified_live
        ):
            raise ValueError
    if result.request != request or (expected_kind is not None and result.kind != expected_kind):
        raise ValueError
    return TaskResult.model_validate(
        {
            "delivery": "accepted",
            "run_id": request.run_id,
            "step": step,
            "status": status,
            "kind": result.kind,
        }
    )


async def execute_task(
    environ: Mapping[str, str],
    config_path: Path = Path("/run/responseforge/callback.json"),
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Execute one fixed authenticated step and publish only a safe native receipt."""
    try:
        config, graphs, action, run_id, authorization, origin = _input(environ, config_path)
        tls = ssl.create_default_context(cafile=str(config.ca_file) if config.ca_file else None)
    except Exception:
        raise ValueError("Invalid native task input") from None
    step = action["name"]
    result = TaskResult.model_validate(
        {
            "delivery": "uncertain",
            "run_id": run_id,
            "step": step,
            "status": "unavailable",
            "kind": None,
        }
    )
    known = False
    started = time.time_ns()
    async with httpx.AsyncClient(
        timeout=15, trust_env=False, follow_redirects=False, transport=transport
    ) as worker:
        try:
            execution = await _post(
                worker,
                origin + "/api/v1/streams/results",
                {"execution_id": run_id, "authorization": authorization},
            )
            request = _original(execution, action, run_id, config)
            known = True
            if workflow_artifact(execution["workflow"]).sha256 != graphs.get(request.workflow_id):
                raise ValueError
            expected_kind = None
            if step == "dispatch":
                selected = dispatch_selected(execution)
                expected_kind = _gate_kind(execution)
                if not selected:
                    result = TaskResult(
                        delivery="skipped",
                        run_id=run_id,
                        step="dispatch",
                        status="skipped",
                        kind=expected_kind,
                    )
            if result.delivery != "skipped":
                async with httpx.AsyncClient(
                    verify=tls,
                    timeout=15,
                    trust_env=False,
                    follow_redirects=False,
                    transport=transport,
                ) as core:
                    value = await _post(
                        core,
                        config.base_url
                        + "/v1/incidents/"
                        + quote(request.incident_id, safe="")
                        + "/playbooks/"
                        + step,
                        request.model_dump(mode="json"),
                        token=config.api_key,
                    )
                result = _core_result(step, value, request, expected_kind)
        except _Rejected:
            result = TaskResult.model_validate(
                result.model_dump(mode="json") | {"delivery": "rejected", "status": "unavailable"}
            )
        except Exception:
            pass
        vendor_result = "uncertain"
        if known:
            try:
                response = await _post(
                    worker,
                    origin + "/api/v1/streams",
                    {
                        "action": {key: action[key] for key in _METADATA} | {"label": step.title()},
                        "authorization": authorization,
                        "execution_id": run_id,
                        "result": result.model_dump_json(),
                        "started_at": started,
                        "completed_at": time.time_ns(),
                        "status": "SKIPPED"
                        if result.delivery == "skipped"
                        else "SUCCESS"
                        if result.delivery == "accepted"
                        else "FAILURE",
                    },
                )
                if response.get("success") is True:
                    vendor_result = "accepted"
            except Exception:
                pass
    return result.model_dump(mode="json") | {"vendor_result": vendor_result}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        result = asyncio.run(execute_task(os.environ))
    except Exception:
        print(json.dumps({"delivery": "rejected", "status": "unavailable"}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return (
        0
        if result["delivery"] in {"accepted", "skipped"} and result["vendor_result"] == "accepted"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
