"""Native Shuffle qualification app and the same internal case API in a container."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from responseforge.integrations.shuffle.callback import CallbackConfig, CallbackTransport
from responseforge.integrations.shuffle.models import ShuffleArgument, canonical_uuid
from responseforge.runtime import WorkflowCallback


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Ambiguous pilot JSON")
        result[name] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("Invalid pilot JSON number")


async def _post(
    client: httpx.AsyncClient, origin: str, path: str, document: dict[str, Any]
) -> dict[str, Any]:
    async with asyncio.timeout(15):
        async with client.stream("POST", origin + path, json=document) as response:
            if (
                response.status_code != 200
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("Pilot stream unavailable")
            data = bytearray()
            if response.is_stream_consumed:
                data.extend(response.content)
                if len(data) > 1048576:
                    raise ValueError("Pilot stream bounds exceeded")
            else:
                async for chunk in response.aiter_raw(chunk_size=65536):
                    if len(data) + len(chunk) > 1048576:
                        raise ValueError("Pilot stream bounds exceeded")
                    data.extend(chunk)
            value = json.loads(
                data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant
            )
            if not isinstance(value, dict):
                raise ValueError("Pilot stream invalid")
            return dict(value)


async def execute_app(
    environ: Mapping[str, str],
    config_path: Path = Path("/run/responseforge/callback.json"),
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Execute only the reviewed callback action, without a general-purpose SDK."""
    try:
        if config_path.is_symlink() or config_path.stat().st_size > 16384:
            raise ValueError
        private = json.loads(
            config_path.read_text(), object_pairs_hook=_object, parse_constant=_constant
        )
        if not isinstance(private, dict) or set(private) - {
            "base_url",
            "api_key",
            "workflow_ids",
            "ca_file",
            "shuffle_backend",
        }:
            raise ValueError
        config = CallbackConfig(
            base_url=private["base_url"],
            api_key=private["api_key"],
            workflow_ids=frozenset(private["workflow_ids"]),
            ca_file=private.get("ca_file"),
        )
        raw_action = environ["ACTION"]
        if len(raw_action.encode()) > 65536:
            raise ValueError
        action = json.loads(raw_action, object_pairs_hook=_object, parse_constant=_constant)
        if (
            not isinstance(action, dict)
            or action.get("app_name") != "responseforge_callback"
            or action.get("app_version") != "1.0.0"
            or action.get("name") != "callback"
        ):
            raise ValueError
        action_id = canonical_uuid(action["id"])
        app_id = canonical_uuid(action["app_id"])
        run_id = canonical_uuid(environ["EXECUTIONID"])
        authorization = environ["AUTHORIZATION"]
        if not 16 <= len(authorization) <= 4096 or any(
            ord(c) < 33 or ord(c) > 126 for c in authorization
        ):
            raise ValueError
        origin = environ["BASE_URL"]
        parsed = urlsplit(origin)
        # BASE_URL is injected only by the reviewed worker, never by a workflow
        # parameter. Its private HTTP endpoint shares the worker namespace.
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or any(ord(c) < 33 or ord(c) > 126 for c in origin)
        ):
            raise ValueError
        configured = urlsplit(private.get("shuffle_backend", "http://shuffle-backend:5001"))
        trusted_worker = parsed.hostname == configured.hostname and parsed.port == configured.port
        if not trusted_worker and parsed.scheme == "http":
            try:
                address = ipaddress.ip_address(parsed.hostname)
                trusted_worker = any(
                    address in ipaddress.ip_network(network)
                    for network in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
                )
            except ValueError:
                pass
        if not trusted_worker:
            raise ValueError
        parameters = action.get("parameters", [])
        if not isinstance(parameters, list):
            raise ValueError
        values: dict[str, Any] = {}
        for item in parameters:
            if (
                not isinstance(item, dict)
                or item.get("name") not in {"outcome", "delay_seconds"}
                or item["name"] in values
            ):
                raise ValueError
            values[item["name"]] = item.get("value")
        outcome = values.get("outcome", "succeeded")
        delay_raw = values.get("delay_seconds", "0")
        if outcome not in {"succeeded", "failed", "timeout"} or isinstance(delay_raw, bool):
            raise ValueError
        delay = float(delay_raw)
        if not 0 <= delay <= 60:
            raise ValueError
    except Exception:
        raise ValueError("Invalid pilot app input") from None

    safe: dict[str, Any] = {"delivery": "uncertain", "vendor_result": "uncertain", "run_id": run_id}
    started = time.time_ns()
    try:
        async with httpx.AsyncClient(
            timeout=15, trust_env=False, follow_redirects=False, transport=transport
        ) as client:
            execution = await _post(
                client,
                origin.rstrip("/"),
                "/api/v1/streams/results",
                {"execution_id": run_id, "authorization": authorization},
            )
            workflow_id = canonical_uuid(execution["workflow_id"])
            argument = ShuffleArgument.model_validate_json(execution["execution_argument"])
            if (
                execution["execution_id"] != run_id
                or argument.run_id != run_id
                or workflow_id not in config.workflow_ids
                or execution.get("workflow", {}).get("id") != workflow_id
                or argument.mode.value != "replay"
            ):
                raise ValueError("Pilot execution correlation rejected")
            if delay:
                await asyncio.sleep(delay)
            callback = WorkflowCallback(
                run_id=run_id,
                incident_id=argument.incident_id,
                workflow_id=workflow_id,
                correlation_id=argument.correlation_id,
                status=outcome,
            )
            # Stable across worker/app restarts. A lost acknowledgement cannot
            # silently turn the same action into a fresh-nonce callback attempt.
            nonce = hmac.new(
                config.api_key.encode(), (run_id + ":" + action_id).encode(), hashlib.sha256
            ).hexdigest()
            receipt = await CallbackTransport(
                config, transport=transport, nonce_factory=lambda: nonce
            ).send(callback)
            safe["delivery"] = receipt.delivery
            result = await _post(
                client,
                origin.rstrip("/"),
                "/api/v1/streams",
                {
                    "action": {
                        "id": action_id,
                        "app_id": app_id,
                        "app_name": "responseforge_callback",
                        "app_version": "1.0.0",
                        "name": "callback",
                    },
                    "authorization": authorization,
                    "execution_id": run_id,
                    "result": json.dumps(
                        {"delivery": receipt.delivery, "run_id": run_id, "outcome": outcome},
                        separators=(",", ":"),
                    ),
                    "started_at": started,
                    "completed_at": time.time_ns(),
                    "status": "SUCCESS"
                    if receipt.delivery == "accepted" and outcome == "succeeded"
                    else "FAILURE",
                },
            )
            if result.get("success") is True:
                safe["vendor_result"] = "accepted"
    except Exception:
        # Never serialize upstream execution secrets, raw bodies or exceptions.
        pass
    return safe


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "app"))
    args = parser.parse_args()
    if args.mode == "app":
        result = asyncio.run(execute_app(os.environ))
        # Only a safe summary can enter container output.
        print(json.dumps(result, separators=(",", ":")))
        return 0 if result.get("delivery") == "accepted" else 1
    if os.environ.get("RF_PILOT_CONTAINER") != "1":
        parser.exit(2, "Pilot server is restricted to the reviewed container topology.\n")
    import uvicorn

    from responseforge.__main__ import load_settings
    from responseforge.api import create_app

    try:
        settings = load_settings(Path("/run/responseforge/core.json"))
        app = create_app(settings)
    except Exception:
        parser.exit(2, "Invalid private pilot server configuration.\n")

    @app.middleware("http")
    async def qualification_fault(request: Any, call_next: Any) -> Any:
        payload: dict[str, Any] = {}
        if request.url.path == "/v1/integrations/shuffle/callback":
            try:
                raw = await request.body()
                parsed_payload = json.loads(raw) if len(raw) <= 16384 else None
                if isinstance(parsed_payload, dict):
                    payload = parsed_payload
            except Exception:
                pass
        response = await call_next(request)
        # Private, bounded fault injection only in this opt-in lab entrypoint.
        # Authentication/storage run first; delay simulates a lost callback ACK.
        if response.status_code == 200 and (
            request.url.path == "/v1/integrations/shuffle/callback"
            or request.url.path.endswith("/shuffle/start")
        ):
            try:
                fault_path = Path("/run/responseforge/fault.json")
                if fault_path.stat().st_size > 1024:
                    raise ValueError
                fault = json.loads(fault_path.read_text())
                key = (
                    "ack_delay_seconds"
                    if request.url.path == "/v1/integrations/shuffle/callback"
                    else "start_ack_delay_seconds"
                )
                delay = fault.get(key, 0)
                if (
                    isinstance(delay, (int, float))
                    and not isinstance(delay, bool)
                    and 0 < delay <= 15
                ):
                    from responseforge.runtime import Principal

                    incident_id = (
                        payload.get("incident_id")
                        if key == "ack_delay_seconds"
                        else request.url.path.split("/")[3]
                    )
                    service = app.state.service
                    actor = Principal(
                        actor_id="rf04-qualification",
                        roles=frozenset(),
                        endpoint_ids=frozenset(),
                        actions=frozenset(),
                        resources=frozenset(),
                    )
                    with service.store.transaction() as transaction:
                        service._audit(
                            transaction,
                            incident_id,
                            actor,
                            "qualification_callback_ack_delay"
                            if key == "ack_delay_seconds"
                            else "qualification_start_ack_delay",
                            "Bounded post-commit acknowledgement delay injected",
                        )
                    await asyncio.sleep(delay)
            except Exception:
                pass
        return response

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_certfile="/run/responseforge/pki/core.pem",
        ssl_keyfile="/run/responseforge/pki/core-key.pem",
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
