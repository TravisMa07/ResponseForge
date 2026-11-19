"""Opt-in genuine Shuffle transport qualification; never used by offline CI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import ssl
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from responseforge.integrations.shuffle.client import ShuffleTransport
from responseforge.integrations.shuffle.models import (
    ShuffleArgument,
    ShuffleConfig,
    canonical_uuid,
    workflow_artifact,
)
from responseforge.integrations.shuffle.operations import LABEL, PROJECT, DockerRuntime


def _save(path: Path, value: Any, *, readable: bool = False) -> None:
    if path.is_symlink():
        raise ValueError("Refusing private state symlink")
    if path.exists():
        path.chmod(0o600)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o444 if readable else 0o600)


async def _request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: Any = None,
    statuses: tuple[int, ...] = (200,),
) -> Any:
    headers = {} if token is None else {"Authorization": "Bearer " + token}
    response = await client.request(method, path, headers=headers, json=body)
    if response.status_code not in statuses or len(response.content) > 2 * 1048576:
        raise ValueError("Qualification API status/bounds rejected: " + str(response.status_code))
    return response.json()


async def _ready(
    client: httpx.AsyncClient, path: str, *, token: str | None = None, timeout: float = 180
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return await _request(client, "GET", path, token=token)
        except (httpx.HTTPError, ValueError):
            await asyncio.sleep(2)
    raise ValueError("Actual pilot readiness deadline expired")


def _roles(state: Path) -> dict[str, str]:
    core = json.loads((state / "core.json").read_text())
    return {role: token for token, actor in core["credentials"].items() for role in actor["roles"]}


def _environment(state: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in (state / "secrets.env").read_text().splitlines() if line
    )


def _scan_logs(runtime: DockerRuntime, secrets: list[str]) -> None:
    identities = runtime._raw(
        runtime._verified(mutate=False), ("ps", "-aq", "--filter", "label=" + LABEL + "=" + PROJECT)
    ).split()
    for identity in identities:
        text = runtime._raw(runtime._verified(mutate=False), ("logs", identity))
        if any(secret in text for secret in secrets if len(secret) >= 20):
            raise ValueError("Actual pilot log scan found a configured credential")


def _sentinel(
    runtime: DockerRuntime, journal: dict[str, Any], journal_path: Path, image: str
) -> dict[str, Any]:
    key = journal.get("sentinel_key") or str(uuid4())
    if "sentinel_id" not in journal:
        if journal.get("sentinel_reserved"):
            identities = runtime._raw(
                runtime._verified(mutate=False),
                ("ps", "-aq", "--filter", "label=responseforge.sentinel=" + key),
            ).split()
            if len(identities) != 1:
                raise ValueError(
                    "Sentinel creation acknowledgement uncertain; inspect original identity"
                )
            identity = identities[0]
        else:
            journal.update(sentinel_key=key, sentinel_reserved=True)
            _save(journal_path, journal)
            identity = runtime._raw(
                runtime._verified(mutate=True),
                (
                    "run",
                    "-d",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "64m",
                    "--cpus",
                    "0.1",
                    "--label",
                    "responseforge.sentinel=" + key,
                    "--label",
                    LABEL + "=unrelated-rf04-sentinel",
                    "--label",
                    "unrelated=shuffle",
                    "--entrypoint",
                    "python",
                    image,
                    "-c",
                    "import time; time.sleep(1800)",
                ),
            ).strip()
        if len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("Invalid qualification sentinel identity")
        journal["sentinel_id"] = identity
        _save(journal_path, journal)
    result = json.loads(
        runtime._raw(
            runtime._verified(mutate=False),
            ("inspect", "--format", "{{json .}}", journal["sentinel_id"]),
        )
    )
    if (
        result.get("Config", {}).get("Labels", {}).get("responseforge.sentinel") != key
        or result.get("Config", {}).get("Labels", {}).get(LABEL) != "unrelated-rf04-sentinel"
        or result.get("State", {}).get("Running") is not True
    ):
        raise ValueError("Qualification sentinel ownership/running state changed")
    return dict(result)


def _workflow(app_id: str, name: str, outcome: str, delay: str = "0") -> dict[str, Any]:
    action_id = str(uuid4())
    return {
        "name": name,
        "description": "Original non-disruptive RF-04 transport qualification",
        "start": action_id,
        "actions": [
            {
                "id": action_id,
                "app_id": app_id,
                "app_name": "responseforge_callback",
                "app_version": "1.0.0",
                "name": "callback",
                "label": "ResponseForge callback",
                "environment": "ResponseForge",
                "is_valid": True,
                "isStartNode": True,
                "position": {"x": 10, "y": 10},
                "large_image": "",
                "parameters": [
                    {
                        "name": key,
                        "value": value,
                        "variant": "STATIC_VALUE",
                        "description": "",
                        "example": "",
                        "configuration": False,
                    }
                    for key, value in (("outcome", outcome), ("delay_seconds", delay))
                ],
            }
        ],
        "branches": [],
        "triggers": [],
        "workflow_variables": [],
        "execution_variables": [],
        "configuration": {"exit_on_error": False, "skip_notifications": True},
    }


def _reviewed_workflow(
    value: dict[str, Any], template: dict[str, Any], *, exit_on_error: bool
) -> None:
    try:
        canonical_uuid(value["id"])
        wanted = template["actions"][0]
        actions = value["actions"]
        if not isinstance(actions, list) or len(actions) != 1:
            raise ValueError
        action = actions[0]
        if (
            value.get("name") != template["name"]
            or value.get("description") != template["description"]
            or value.get("start") != wanted["id"]
        ):
            raise ValueError
        if any(
            action.get(key) != wanted[key]
            for key in ("id", "app_id", "app_name", "app_version", "name", "label", "environment")
        ):
            raise ValueError
        if (
            action.get("authentication_id")
            or action.get("sub_action")
            or action.get("execution_delay")
            or action.get("generated")
            or value.get("public")
        ):
            raise ValueError
        expected = {parameter["name"]: parameter["value"] for parameter in wanted["parameters"]}
        parameters = action["parameters"]
        if (
            len(parameters) != len(expected)
            or {item["name"]: item["value"] for item in parameters} != expected
        ):
            raise ValueError
        if any(
            item.get("variant") != "STATIC_VALUE"
            or item.get("configuration")
            or item.get("action_field")
            or item.get("value_replace")
            for item in parameters
        ):
            raise ValueError
        if any(
            value.get(key) not in (None, [])
            for key in ("branches", "triggers", "workflow_variables", "execution_variables")
        ):
            raise ValueError
        if value["configuration"].get("exit_on_error") is not exit_on_error or value[
            "configuration"
        ].get("start_from_top"):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Imported workflow differs from reviewed qualification template") from None


def _qualified_results(results: dict[str, Any], workflows: dict[str, Any]) -> bool:
    expected = {
        "success": "finished",
        "failure": "failed",
        "timeout": "uncertain",
        "restart": "finished",
        "lost_start_ack": "finished",
    }
    if set(results) != set(expected) or set(workflows) != set(expected):
        return False
    for name, state in expected.items():
        item = results[name]
        if (
            not isinstance(item, dict)
            or item.get("delivery_state") != state
            or item.get("workflow_id") != workflows[name].get("workflow_id")
            or item.get("workflow_sha256") != workflows[name].get("sha256")
        ):
            return False
        if any(
            item.get(key) is not True
            for key in ("callback_audit", "duplicate_intake", "duplicate_start", "graph_verified")
        ):
            return False
        if (
            item.get("native_app_results") != 1
            or item.get("native_app_containers") != 1
            or item.get("native_status")
            != ("FAILURE" if name in {"failure", "timeout"} else "SUCCESS")
        ):
            return False
        if item.get("vendor_status") not in (
            {"FAILURE", "ABORTED"} if name in {"failure", "timeout"} else {"FINISHED", "SUCCESS"}
        ):
            return False
        if name == "timeout" and item.get("post_commit_callback_delay_proven") is not True:
            return False
        if name == "lost_start_ack" and (
            item.get("actual_start_ack_timeout") is not True
            or item.get("post_commit_start_delay_proven") is not True
        ):
            return False
    return True


async def qualify(state_dir: Path) -> dict[str, Any]:
    """Always clear lab-only delay faults after a checked qualification attempt."""
    DockerRuntime(state_dir)._verified(mutate=True)
    try:
        return await _qualify(state_dir)
    finally:
        _save(state_dir / "fault.json", {}, readable=True)


async def _qualify(state_dir: Path) -> dict[str, Any]:
    """Exercise actual vendor APIs and emit only redacted aggregate evidence."""
    runtime = DockerRuntime(state_dir)
    manifest = runtime._verified(mutate=True)
    tls = ssl.create_default_context(cafile=str(state_dir / "pki/ca.pem"))
    roles, env = _roles(state_dir), _environment(state_dir)
    journal_path = state_dir / "qualification-journal.json"
    journal: dict[str, Any] = (
        json.loads(journal_path.read_text())
        if journal_path.exists()
        else {"id": str(uuid4()), "workflows": {}, "runs": {}, "results": {}}
    )
    _save(journal_path, journal)
    build_proof = json.loads((state_dir / "build-inventory.json").read_text())
    binding = {
        "engine_id": manifest["engine_id"],
        "images": manifest["images"],
        "source_tree_sha256": build_proof["source_tree_sha256"],
    }
    if (
        build_proof["images"] != manifest["images"]
        or (journal.get("binding") is not None and journal["binding"] != binding)
        or (journal["results"] and journal.get("binding") is None)
    ):
        raise ValueError("Qualification journal belongs to different source/images/engine")
    journal["binding"] = binding
    _save(journal_path, journal)
    sentinel_before = _sentinel(runtime, journal, journal_path, manifest["images"]["core"])
    # Make the real sentinel older than the reviewed 2s housekeeping threshold
    # before a vendor startup/restart. The original broad cleanup would match it.
    age = (
        datetime.now(UTC).timestamp()
        - datetime.fromisoformat(sentinel_before["Created"].replace("Z", "+00:00")).timestamp()
    )
    await asyncio.sleep(max(0, 3 - age))
    started = time.monotonic()
    async with (
        httpx.AsyncClient(
            base_url="https://127.0.0.1:3443",
            verify=tls,
            timeout=20,
            follow_redirects=False,
            trust_env=False,
        ) as vendor,
        httpx.AsyncClient(
            base_url="https://127.0.0.1:8443",
            verify=tls,
            timeout=20,
            follow_redirects=False,
            trust_env=False,
        ) as core,
    ):
        info = await _ready(vendor, "/api/v1/getinfo", token=env["SHUFFLE_DEFAULT_APIKEY"])
        active = info.get("active_org", {})
        org_id = canonical_uuid(
            active.get("id") or info.get("active_org_id") or info.get("orgs", [{}])[0].get("id")
        )
        env["ORG"] = org_id
        (state_dir / "secrets.env").write_text(
            "".join(key + "=" + value + "\n" for key, value in env.items())
        )
        runtime.command("compose", "restart", "orborus", mutate=True)
        await _ready(core, "/healthz")
        apps = await _request(vendor, "GET", "/api/v1/apps", token=env["SHUFFLE_DEFAULT_APIKEY"])
        matches = [
            app
            for app in apps
            if app.get("name") == "responseforge_callback" and app.get("app_version") == "1.0.0"
        ]
        if not matches:
            if journal.get("app_creation_reserved"):
                raise ValueError(
                    "App creation acknowledgement uncertain; inspect original vendor state before retry"
                )
            journal["app_creation_reserved"] = True
            _save(journal_path, journal)
            await _request(
                vendor,
                "PUT",
                "/api/v1/apps",
                token=env["SHUFFLE_DEFAULT_APIKEY"],
                body={
                    "name": "responseforge_callback",
                    "description": "RF-04 private callback action",
                    "app_version": "1.0.0",
                    "contact_info": {"name": "ResponseForge"},
                    "reference_org": org_id,
                    "public": False,
                    "sharing": False,
                    "authentication": {"required": False},
                    "actions": [
                        {
                            "name": "callback",
                            "description": "Correlated callback",
                            "parameters": [
                                {
                                    "name": name,
                                    "description": "",
                                    "required": False,
                                    "schema": {"type": "string"},
                                }
                                for name in ("outcome", "delay_seconds")
                            ],
                        }
                    ],
                },
            )
            apps = await _request(
                vendor, "GET", "/api/v1/apps", token=env["SHUFFLE_DEFAULT_APIKEY"]
            )
            matches = [
                app
                for app in apps
                if app.get("name") == "responseforge_callback" and app.get("app_version") == "1.0.0"
            ]
        if len(matches) != 1:
            raise ValueError("Reviewed native callback app inventory is ambiguous")
        app_id = canonical_uuid(matches[0]["id"])
        for name, outcome, delay in (
            ("success", "succeeded", "0"),
            ("failure", "failed", "0"),
            ("timeout", "succeeded", "0"),
            ("restart", "succeeded", "5"),
            ("lost_start_ack", "succeeded", "0"),
        ):
            item = journal["workflows"].get(name)
            if item is None:
                template = _workflow(app_id, "RF04 " + name + " " + journal["id"], outcome, delay)
                journal["workflows"][name] = {"reserved": True, "template": template}
                _save(journal_path, journal)
                value = await _request(
                    vendor,
                    "POST",
                    "/api/v1/workflows",
                    token=env["SHUFFLE_DEFAULT_APIKEY"],
                    body=template,
                )
                workflow_id = canonical_uuid(value["id"])
                journal["workflows"][name]["workflow_id"] = workflow_id
                _save(journal_path, journal)
            elif "workflow_id" not in item:
                raise ValueError(
                    "Workflow creation acknowledgement uncertain; inspect original identity before retry"
                )
            workflow_id = journal["workflows"][name]["workflow_id"]
            value = await _request(
                vendor,
                "GET",
                "/api/v1/workflows/" + workflow_id,
                token=env["SHUFFLE_DEFAULT_APIKEY"],
            )
            if name in {"failure", "timeout"} and not value.get("configuration", {}).get(
                "exit_on_error"
            ):
                if journal["workflows"][name].get("sha256"):
                    raise ValueError("Previously reviewed qualification workflow changed")
                value["configuration"]["exit_on_error"] = True
                await _request(
                    vendor,
                    "PUT",
                    "/api/v1/workflows/" + workflow_id,
                    token=env["SHUFFLE_DEFAULT_APIKEY"],
                    body=value,
                )
                value = await _request(
                    vendor,
                    "GET",
                    "/api/v1/workflows/" + workflow_id,
                    token=env["SHUFFLE_DEFAULT_APIKEY"],
                )
            artifact = workflow_artifact(value)
            _reviewed_workflow(
                value,
                journal["workflows"][name]["template"],
                exit_on_error=name in {"failure", "timeout"},
            )
            if journal["workflows"][name].get("sha256") not in {None, artifact.sha256}:
                raise ValueError("Previously reviewed qualification workflow fingerprint changed")
            journal["workflows"][name]["sha256"] = artifact.sha256
            _save(state_dir / ("workflow-" + workflow_id + ".json"), value)
        _save(journal_path, journal)
        core_config = json.loads((state_dir / "core.json").read_text())
        core_config["shuffle"] = {
            "base_url": "https://shuffle-frontend",
            "api_key": env["SHUFFLE_DEFAULT_APIKEY"],
            "workflow_bindings": {
                item["workflow_id"]: {"version": "rf04-native-v1", "sha256": item["sha256"]}
                for item in journal["workflows"].values()
            },
            "ca_file": "/run/responseforge/pki/ca.pem",
            "org_id": org_id,
        }
        _save(state_dir / "core.json", core_config, readable=True)
        callback = json.loads((state_dir / "callback.json").read_text())
        callback["workflow_ids"] = list(core_config["shuffle"]["workflow_bindings"])
        _save(state_dir / "callback.json", callback, readable=True)
        runtime.seed()
        runtime.command("compose", "restart", "core", mutate=True)
        await _ready(core, "/healthz")
        transport = ShuffleTransport(
            ShuffleConfig(
                base_url="https://127.0.0.1:3443",
                api_key=env["SHUFFLE_DEFAULT_APIKEY"],
                workflow_ids=frozenset(callback["workflow_ids"]),
                ca_file=state_dir / "pki/ca.pem",
                org_id=org_id,
            )
        )

        for name in ("success", "failure", "timeout", "restart", "lost_start_ack"):
            if name in journal["results"]:
                if journal["results"][name].get("workflow_sha256") != journal["workflows"][name][
                    "sha256"
                ] or (
                    name == "lost_start_ack"
                    and journal["results"][name].get("actual_start_ack_timeout") is not True
                ):
                    raise ValueError(
                        "Incomplete or differently bound resumed qualification evidence"
                    )
                continue
            definition = journal["workflows"][name]
            workflow_id = definition["workflow_id"]
            if name not in journal["runs"]:
                now = datetime.now(UTC)
                # Original public synthetic contract example; no external corpus
                # or endpoint effect is represented by this transport-only alert.
                alert = {
                    "schema_version": "1.0",
                    "alert_id": "rf04-" + journal["id"] + "-" + name,
                    "mode": "replay",
                    "source": "synthetic",
                    "scenario_id": "rf04-transport-" + name,
                    "endpoint": {
                        "schema_version": "1.0",
                        "endpoint_id": "synthetic-host",
                        "hostname": "lab-example",
                        "agent_id": None,
                    },
                    "event_time": now.isoformat(),
                    "ingested_at": now.isoformat(),
                    "rule_id": "rf04-transport",
                    "severity": "low",
                    "provenance": {
                        "schema_version": "1.0",
                        "source": "synthetic",
                        "source_ref": "inline:RF-04-transport",
                        "sha256": hashlib.sha256(
                            b"RF-04 original transport qualification"
                        ).hexdigest(),
                        "original_event_ids": [name],
                    },
                }
                intake = await _request(
                    core,
                    "POST",
                    "/v1/alerts",
                    token=roles["source"],
                    body=alert,
                    statuses=(200, 201),
                )
                duplicate = await _request(
                    core,
                    "POST",
                    "/v1/alerts",
                    token=roles["source"],
                    body=alert,
                    statuses=(200, 201),
                )
                if (
                    duplicate["incident_id"] != intake["incident_id"]
                    or duplicate.get("duplicate") is not True
                ):
                    raise ValueError("Actual duplicate intake did not retain case identity")
                journal["runs"][name] = {
                    "incident_id": intake["incident_id"],
                    "correlation_id": intake["correlation_id"],
                    "run_id": str(uuid4()),
                }
                _save(journal_path, journal)
            run = journal["runs"][name]
            base = "/v1/incidents/" + run["incident_id"]
            if name == "timeout":
                _save(state_dir / "fault.json", {"ack_delay_seconds": 8}, readable=True)
            elif name == "lost_start_ack":
                _save(state_dir / "fault.json", {"start_ack_delay_seconds": 8}, readable=True)
            if not run.get("start_reserved"):
                run["start_reserved"] = True
                _save(journal_path, journal)
                if name == "lost_start_ack":
                    try:
                        await core.post(
                            base + "/shuffle/start",
                            headers={"Authorization": "Bearer " + roles["analyst"]},
                            json={"workflow_id": workflow_id, "run_id": run["run_id"]},
                            timeout=1,
                        )
                        raise ValueError("Real start acknowledgement timeout was not observed")
                    except httpx.TimeoutException:
                        run["actual_start_ack_timeout"] = True
                        _save(journal_path, journal)
                        marker_deadline = time.monotonic() + 30
                        marker_seen = False
                        while time.monotonic() < marker_deadline:
                            original_audit = await _request(
                                core, "GET", base + "/audit", token=roles["analyst"]
                            )
                            if any(
                                event["operation"] == "qualification_start_ack_delay"
                                for event in original_audit
                            ):
                                marker_seen = True
                                break
                            await asyncio.sleep(2)
                        if not marker_seen:
                            raise ValueError(
                                "Start timeout occurred without proven post-commit acknowledgement delay"
                            )
                        run["post_commit_start_delay_proven"] = True
                        _save(journal_path, journal)
                        _save(state_dir / "fault.json", {}, readable=True)
                else:
                    await _request(
                        core,
                        "POST",
                        base + "/shuffle/start",
                        token=roles["analyst"],
                        body={"workflow_id": workflow_id, "run_id": run["run_id"]},
                    )
            # A resumed/lost-response harness only repeats the coordinator call;
            # its durable reservation prevents another vendor launch.
            if name == "lost_start_ack" and (
                run.get("actual_start_ack_timeout") is not True
                or run.get("post_commit_start_delay_proven") is not True
            ):
                raise ValueError(
                    "Interrupted start fault has no proven actual acknowledgement timeout"
                )
            duplicate_start = await _request(
                core,
                "POST",
                base + "/shuffle/start",
                token=roles["analyst"],
                body={"workflow_id": workflow_id, "run_id": run["run_id"]},
            )
            if duplicate_start["argument"]["run_id"] != run["run_id"]:
                raise ValueError("Actual duplicate start identity changed")
            if name == "restart":
                runtime.command("compose", "restart", "core", mutate=True)
                await _ready(core, "/healthz")
            argument = ShuffleArgument(
                incident_id=run["incident_id"],
                run_id=run["run_id"],
                correlation_id=run["correlation_id"],
                mode="replay",
            )
            deadline = time.monotonic() + 180
            observation = None
            while time.monotonic() < deadline:
                try:
                    observation = await transport.get_execution(
                        workflow_id, run["run_id"], argument
                    )
                    if observation.vendor_status in {"FINISHED", "SUCCESS", "FAILURE", "ABORTED"}:
                        break
                except Exception:
                    pass
                await asyncio.sleep(2)
            if observation is None or observation.vendor_status not in {
                "FINISHED",
                "SUCCESS",
                "FAILURE",
                "ABORTED",
            }:
                raise ValueError("Genuine workflow completion deadline expired")
            if observation.workflow_sha256 != definition["sha256"]:
                raise ValueError("Actual executed graph differs from reviewed stored workflow")
            raw_execution = await _request(
                vendor,
                "POST",
                "/api/v1/streams/results",
                token=env["SHUFFLE_DEFAULT_APIKEY"],
                body={"execution_id": run["run_id"]},
            )
            native_results = [
                item
                for item in raw_execution.get("results", [])
                if item.get("action", {}).get("app_name") == "responseforge_callback"
            ]
            if len(native_results) != 1:
                raise ValueError("Actual workflow did not produce exactly one reviewed app result")
            native_result = json.loads(native_results[0].get("result", "{}"))
            if name == "timeout" and native_result.get("delivery") != "uncertain":
                raise ValueError("Real callback acknowledgement timeout was not observed")
            if name != "timeout" and (
                native_result.get("delivery") != "accepted"
                or native_result.get("outcome") != ("failed" if name == "failure" else "succeeded")
                or native_results[0].get("status")
                != ("FAILURE" if name == "failure" else "SUCCESS")
            ):
                raise ValueError("Actual native app outcome differs from the scenario")
            containers = runtime._raw(
                runtime._verified(mutate=False),
                (
                    "ps",
                    "-aq",
                    "--filter",
                    "label=" + LABEL + "=" + PROJECT,
                    "--filter",
                    "label=responseforge.execution=" + run["run_id"],
                ),
            ).split()
            app_instances = 0
            for identity in containers:
                image_id = runtime._raw(
                    runtime._verified(mutate=False), ("inspect", "--format", "{{.Image}}", identity)
                ).strip()
                if image_id == manifest["images"]["app"]:
                    app_instances += 1
            if app_instances != 1:
                raise ValueError("Duplicate start produced unexpected native app container count")
            _save(state_dir / "fault.json", {}, readable=True)
            delivery = await _request(
                core,
                "POST",
                base + "/shuffle/reconcile",
                token=roles["analyst"],
                body={"run_id": run["run_id"]},
            )
            expected = (
                "failed" if name == "failure" else "uncertain" if name == "timeout" else "finished"
            )
            if delivery["state"] != expected:
                raise ValueError(
                    "Actual vendor/node reconciliation differs from scenario expectation"
                )
            audit = await _request(core, "GET", base + "/audit", token=roles["analyst"])
            if not any(item["operation"] == "workflow_callback" for item in audit):
                raise ValueError("Actual workflow has no authenticated core node audit")
            if name == "timeout" and not any(
                item["operation"] == "qualification_callback_ack_delay" for item in audit
            ):
                raise ValueError(
                    "Callback timeout did not follow a proven post-commit acknowledgement delay"
                )
            # Exercise actual HTTP authentication and replay rejection, not mocks.
            body = {
                "run_id": run["run_id"],
                "incident_id": run["incident_id"],
                "workflow_id": workflow_id,
                "correlation_id": run["correlation_id"],
                "status": "succeeded",
            }
            stamp = datetime.now(UTC).isoformat()
            headers = {
                "Authorization": "Bearer " + roles["workflow"],
                "X-Request-Timestamp": stamp,
                "X-Request-Nonce": "qualification-" + run["run_id"],
            }
            forged = await core.post(
                "/v1/integrations/shuffle/callback",
                json=body | {"correlation_id": "forged"},
                headers=headers,
            )
            if forged.status_code not in {403, 409}:
                raise ValueError("Actual forged callback not rejected")
            wrong = await core.post(
                "/v1/integrations/shuffle/callback",
                json=body,
                headers=headers | {"Authorization": "Bearer not-a-real-credential"},
            )
            if wrong.status_code != 401:
                raise ValueError("Actual unauthenticated callback not rejected")
            if name in {"success", "restart", "lost_start_ack"}:
                accepted = await core.post(
                    "/v1/integrations/shuffle/callback", json=body, headers=headers
                )
                repeated = await core.post(
                    "/v1/integrations/shuffle/callback", json=body, headers=headers
                )
                if accepted.status_code != 200 or repeated.status_code != 409:
                    raise ValueError("Actual callback nonce replay not enforced")
                expired = await core.post(
                    "/v1/integrations/shuffle/callback",
                    json=body,
                    headers=headers
                    | {
                        "X-Request-Nonce": str(uuid4()),
                        "X-Request-Timestamp": (
                            datetime.now(UTC) - timedelta(seconds=301)
                        ).isoformat(),
                    },
                )
                if expired.status_code != 409:
                    raise ValueError("Actual stale callback not rejected")
            for format_name in ("json", "html"):
                response = await core.get(
                    base + "/report",
                    params={"format": format_name},
                    headers={"Authorization": "Bearer " + roles["analyst"]},
                )
                if response.status_code != 200 or any(
                    secret in response.text
                    for secret in list(roles.values()) + list(env.values())
                    if len(secret) >= 20
                ):
                    raise ValueError("Actual report export failed or disclosed a credential")
            journal["results"][name] = {
                "workflow_id": workflow_id,
                "workflow_sha256": definition["sha256"],
                "run_id": run["run_id"],
                "incident_id": run["incident_id"],
                "vendor_status": observation.vendor_status,
                "delivery_state": delivery["state"],
                "callback_audit": True,
                "duplicate_intake": True,
                "duplicate_start": True,
                "graph_verified": True,
                "native_app_results": len(native_results),
                "native_app_containers": app_instances,
                "native_status": native_results[0].get("status"),
                "actual_start_ack_timeout": run.get("actual_start_ack_timeout", False),
                "post_commit_start_delay_proven": run.get("post_commit_start_delay_proven", False),
                "post_commit_callback_delay_proven": name == "timeout"
                and any(item["operation"] == "qualification_callback_ack_delay" for item in audit),
            }
            _save(journal_path, journal)
        # Vendor restart must preserve the original persisted execution and graph.
        runtime.command("compose", "restart", "backend", mutate=True)
        await _ready(vendor, "/api/v1/getinfo", token=env["SHUFFLE_DEFAULT_APIKEY"])
        runtime.command("compose", "restart", "orborus", mutate=True)
        positive = journal["runs"]["success"]
        definition = journal["workflows"]["success"]
        original = ShuffleArgument(
            incident_id=positive["incident_id"],
            run_id=positive["run_id"],
            correlation_id=positive["correlation_id"],
            mode="replay",
        )
        after_restart = await transport.get_execution(
            definition["workflow_id"], positive["run_id"], original
        )
        if after_restart.workflow_sha256 != definition[
            "sha256"
        ] or after_restart.vendor_status not in {"FINISHED", "SUCCESS"}:
            raise ValueError("Vendor restart did not preserve original execution")
        # Same sentinel was present through the workload and vendor restarts.
        sentinel_key = journal["sentinel_key"]
        sentinel = journal["sentinel_id"]
        before = json.loads(
            runtime._raw(
                runtime._verified(mutate=False), ("inspect", "--format", "{{json .}}", sentinel)
            )
        )
        if (
            before["Id"] != sentinel_before["Id"]
            or before["State"]["StartedAt"] != sentinel_before["State"]["StartedAt"]
            or before["State"]["Running"] is not True
        ):
            raise ValueError("Unrelated sentinel changed during vendor startup/execution/restart")
        all_secrets = list(roles.values()) + list(env.values())
        for observed_run in journal["runs"].values():
            observed = await _request(
                vendor,
                "POST",
                "/api/v1/streams/results",
                token=env["SHUFFLE_DEFAULT_APIKEY"],
                body={"execution_id": observed_run["run_id"]},
            )
            if isinstance(observed.get("authorization"), str):
                all_secrets.append(observed["authorization"])
        _scan_logs(runtime, all_secrets)
        resource_ids = runtime._raw(
            runtime._verified(mutate=False),
            ("ps", "-q", "--filter", "label=" + LABEL + "=" + PROJECT),
        ).split()
        resource_text = runtime._raw(
            runtime._verified(mutate=False),
            ("stats", "--no-stream", "--format", "{{json .}}", *resource_ids),
        )
        resource_snapshot = [
            {key: item.get(key) for key in ("Name", "CPUPerc", "MemUsage", "PIDs")}
            for item in (json.loads(line) for line in resource_text.splitlines() if line)
        ]
        runtime.down()
        after = json.loads(
            runtime._raw(
                runtime._verified(mutate=False), ("inspect", "--format", "{{json .}}", sentinel)
            )
        )
        if (
            before["Id"] != after["Id"]
            or before["State"]["StartedAt"] != after["State"]["StartedAt"]
            or after["State"]["Running"] is not True
        ):
            raise ValueError("Unrelated sentinel changed during scoped teardown")
        runtime.up()
        await _ready(core, "/healthz")
        await _ready(vendor, "/api/v1/getinfo", token=env["SHUFFLE_DEFAULT_APIKEY"])
        persisted = await _request(
            core, "GET", "/v1/incidents/" + positive["incident_id"], token=roles["analyst"]
        )
        if persisted["incident_id"] != positive["incident_id"]:
            raise ValueError("Case state did not survive down/up")
        after_down_up = await transport.get_execution(
            definition["workflow_id"], positive["run_id"], original
        )
        if after_down_up.workflow_sha256 != definition[
            "sha256"
        ] or after_down_up.vendor_status not in {"FINISHED", "SUCCESS"}:
            raise ValueError("Vendor execution did not survive full down/up")
        labels = json.loads(
            runtime._raw(
                runtime._verified(mutate=False),
                ("inspect", "--format", "{{json .Config.Labels}}", sentinel),
            )
        )
        if (
            labels.get("responseforge.sentinel") != sentinel_key
            or labels.get(LABEL) != "unrelated-rf04-sentinel"
        ):
            raise ValueError("Sentinel ownership changed; refusing cleanup")
        runtime._raw(runtime._verified(mutate=True), ("rm", "-f", sentinel))
        # Logs remain private. This scan is part of actual qualification, not a
        # blanket claim about arbitrary upstream apps or future workflows.
        _scan_logs(runtime, all_secrets)
        if not _qualified_results(journal["results"], journal["workflows"]):
            raise ValueError("Required runtime case evidence is incomplete or inconsistent")
        summary = {
            "runtime_qualified": True,
            "mode": "replay",
            "verified_live": False,
            "endpoint_effect": "none",
            "runs": journal["results"],
            "elapsed_seconds_current_invocation": round(time.monotonic() - started, 3),
            "images": manifest["images"],
            "platform": manifest["architecture"],
            "vendor_restart": True,
            "persistence_down_up": True,
            "unrelated_sentinel_preserved": True,
            "configured_secret_log_scan": True,
            "binding": {
                "images": binding["images"],
                "source_tree_sha256": binding["source_tree_sha256"],
                "engine_id_sha256": hashlib.sha256(binding["engine_id"].encode()).hexdigest(),
            },
            "resource_observation": {
                "kind": "post-scenario snapshot, not peak or benchmark",
                "containers": resource_snapshot,
            },
            "qualification_housekeeping_age_seconds": 2,
            "domain_workflows_qualified": 0,
            "expected_uncertain_fault_runs": 1,
        }
        _save(state_dir / "qualification-summary.json", summary)
        return summary
