"""Explicit genuine three-domain Shuffle qualification; never an offline substitute."""

from __future__ import annotations

import asyncio
import json
import math
import ssl
import statistics
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from responseforge.integrations.shuffle.client import ShuffleTransport
from responseforge.integrations.shuffle.graphs import build_workflow, validate_workflow
from responseforge.integrations.shuffle.models import (
    DeliveryRecord,
    ShuffleArgument,
    ShuffleConfig,
    TaskResult,
    canonical_uuid,
    workflow_artifact,
)
from responseforge.integrations.shuffle.operations import LABEL, PROJECT, DockerRuntime
from responseforge.integrations.shuffle.playbook_bootstrap import bind_workflows
from responseforge.integrations.shuffle.qualification import (
    _environment,
    _ready,
    _request,
    _roles,
    _save,
    _scan_logs,
    _sentinel,
)
from responseforge.playbooks.models import PlaybookPlan
from responseforge.replay import load_replay, logical_receipt, make_alerts
from responseforge.replay_driver import _revision

# Qualification scenarios are fixed requirements, never inferred from observed output.
_EXPECTED = {
    "process-awaiting": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "process-approved": ("process", "ready", "SUCCESS", 1, "finished"),
    "process-duplicate": ("process", "completed", "SKIPPED", 1, "finished"),
    "denied-awaiting": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "denied-final": ("process", "denied", "SKIPPED", 0, "finished"),
    "expired-awaiting": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "expired-final": ("process", "expired", "SKIPPED", 0, "finished"),
    "incomplete": ("process", "no_action", "SKIPPED", 0, "finished"),
    "persistence": ("persistence", "no_action", "SKIPPED", 0, "finished"),
    "containment-awaiting": ("containment", "awaiting_approval", "SKIPPED", 0, "finished"),
    "containment-approved": ("containment", "ready", "SUCCESS", 1, "finished"),
    "callback-loss": ("process", "awaiting_approval", "SKIPPED", 0, "uncertain"),
    "restart": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "task-failure": ("process", "unavailable", "unavailable", 0, "uncertain"),
}
_LABELS = set(_EXPECTED)


class _CorePacer:
    """Bound lab host traffic without weakening core limits or retrying mutations."""

    def __init__(self) -> None:
        self.last_at: float | None = None
        self.waited_seconds = 0.0
        self.lock = asyncio.Lock()

    async def __call__(self, request: httpx.Request) -> None:
        async with self.lock:
            now = time.monotonic()
            wait = 0.0 if self.last_at is None else max(0.0, 1.1 - (now - self.last_at))
            if wait:
                await asyncio.sleep(wait)
                self.waited_seconds += wait
            self.last_at = time.monotonic()


def _distribution(values: list[float]) -> dict[str, Any]:
    if not values or any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("Measured timestamp samples are incomplete or invalid")
    return {
        "run_count": len(values),
        "median_seconds": statistics.median(values),
        "p95_seconds": sorted(values)[math.ceil(0.95 * len(values)) - 1],
        "failures": 0,
        "estimator": "nearest-rank p95; synthetic lab sample",
    }


def _valid_record(name: str, item: Any) -> bool:
    if name not in _EXPECTED or not isinstance(item, dict):
        return False
    kind, gate, native, effects, state = _EXPECTED[name]
    statuses = {"FINISHED", "SUCCESS"}
    if name in {"callback-loss", "task-failure"}:
        statuses |= {"FAILURE", "ABORTED"}
    return (
        item.get("kind") == kind
        and item.get("gate_status") == gate
        and item.get("dispatch_native") == native
        and type(item.get("effect_count")) is int
        and item["effect_count"] == effects
        and item.get("delivery_state") == state
        and item.get("vendor_status") in statuses
        and all(
            item.get(field) is True
            for field in ("duplicate_start", "graph_verified", "audit_verified")
        )
        and item.get("callback_fault_proven") is (name == "callback-loss")
        and item.get("task_failure_proven") is (name == "task-failure")
        and item.get("core_restart_proven") is (name == "restart")
    )


def _valid_proof(runs: dict[str, Any]) -> bool:
    return set(runs) == _LABELS and all(_valid_record(name, item) for name, item in runs.items())


class _Lab:
    def __init__(self, state: Path, vendor: httpx.AsyncClient, core: httpx.AsyncClient) -> None:
        self.state, self.vendor, self.core = state, vendor, core
        self.runtime = DockerRuntime(state)
        self.manifest = self.runtime._verified(mutate=True)
        self.env, self.roles = _environment(state), _roles(state)
        self.path = state / "domain-journal.json"
        self.journal: dict[str, Any] = (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {
                "id": str(uuid4()),
                "workflows": {},
                "runs": {},
                "results": {},
                "decisions": {},
                "cases": {},
            }
        )
        proof = json.loads((state / "build-inventory.json").read_text())
        self.binding = {
            "images": self.manifest["images"],
            "engine_id": self.manifest["engine_id"],
            "source_tree_sha256": proof["source_tree_sha256"],
            "source_sha256": self.manifest.get("playbook_source_sha256"),
        }
        if (
            self.manifest.get("playbooks_enabled") is not True
            or proof["images"] != self.manifest["images"]
            or self.journal.get("binding") not in (None, self.binding)
        ):
            raise ValueError("Domain journal belongs to different source/images/engine")
        self.journal["binding"] = self.binding
        self.save()
        self.transport: ShuffleTransport
        self.alerts: dict[str, Any] = {}
        self.workflows: dict[str, dict[str, Any]] = {}

    def save(self) -> None:
        _save(self.path, self.journal)

    async def app(self, name: str, org: str) -> str:
        apps = await _request(
            self.vendor, "GET", "/api/v1/apps", token=self.env["SHUFFLE_DEFAULT_APIKEY"]
        )
        matches = [
            item for item in apps if item.get("name") == name and item.get("app_version") == "1.0.0"
        ]
        if not matches:
            key = "app-reserved-" + name
            if self.journal.get(key):
                raise ValueError(
                    "App creation acknowledgement uncertain; inspect original vendor identity"
                )
            self.journal[key] = True
            self.save()
            steps = (
                ("callback",)
                if name == "responseforge_callback"
                else ("prepare", "gate", "dispatch")
            )
            await _request(
                self.vendor,
                "PUT",
                "/api/v1/apps",
                token=self.env["SHUFFLE_DEFAULT_APIKEY"],
                body={
                    "name": name,
                    "app_version": "1.0.0",
                    "description": "Original RF05 native fixed actions",
                    "contact_info": {"name": "ResponseForge"},
                    "reference_org": org,
                    "public": False,
                    "sharing": False,
                    "authentication": {"required": False},
                    "actions": [
                        {
                            "name": step,
                            "description": "Bound " + step,
                            "parameters": [
                                {
                                    "name": key,
                                    "description": "",
                                    "required": False,
                                    "schema": {"type": "string"},
                                }
                                for key in (
                                    ("outcome", "delay_seconds") if step == "callback" else ()
                                )
                            ],
                        }
                        for step in steps
                    ],
                },
            )
            apps = await _request(
                self.vendor, "GET", "/api/v1/apps", token=self.env["SHUFFLE_DEFAULT_APIKEY"]
            )
            matches = [
                item
                for item in apps
                if item.get("name") == name and item.get("app_version") == "1.0.0"
            ]
        if len(matches) != 1:
            raise ValueError("Native app registration is ambiguous")
        return canonical_uuid(matches[0]["id"])

    async def bootstrap(self) -> None:
        info = await _ready(
            self.vendor, "/api/v1/getinfo", token=self.env["SHUFFLE_DEFAULT_APIKEY"]
        )
        org = canonical_uuid(info["active_org"]["id"])
        self.env["ORG"] = org
        (self.state / "secrets.env").write_text(
            "".join(key + "=" + value + "\n" for key, value in self.env.items())
        )
        self.runtime.up()  # Compose applies the reviewed env-file change without resetting state.
        await _ready(self.vendor, "/api/v1/getinfo", token=self.env["SHUFFLE_DEFAULT_APIKEY"])
        task_app, callback_app = (
            await self.app("responseforge_tasks", org),
            await self.app("responseforge_callback", org),
        )
        for kind in ("process", "persistence", "containment"):
            item = self.journal["workflows"].get(kind)
            if item is None:
                value = build_workflow(kind, task_app, callback_app)
                value["name"] += " " + self.journal["id"]
                self.journal["workflows"][kind] = {"reserved": True}
                self.save()
                response = await _request(
                    self.vendor,
                    "POST",
                    "/api/v1/workflows",
                    token=self.env["SHUFFLE_DEFAULT_APIKEY"],
                    body=value,
                )
                identity = canonical_uuid(response["id"])
                self.journal["workflows"][kind]["workflow_id"] = identity
                self.save()
            elif "workflow_id" not in item:
                raise ValueError(
                    "Workflow import acknowledgement uncertain; inspect original identity"
                )
            identity = self.journal["workflows"][kind]["workflow_id"]
            value = await _request(
                self.vendor,
                "GET",
                "/api/v1/workflows/" + identity,
                token=self.env["SHUFFLE_DEFAULT_APIKEY"],
            )
            if not value.get("configuration", {}).get("exit_on_error") or not value.get(
                "configuration", {}
            ).get("skip_notifications"):
                if self.journal["workflows"][kind].get("sha256"):
                    raise ValueError("Previously reviewed workflow configuration changed")
                value.setdefault("configuration", {}).update(
                    exit_on_error=True, skip_notifications=True
                )
                await _request(
                    self.vendor,
                    "PUT",
                    "/api/v1/workflows/" + identity,
                    token=self.env["SHUFFLE_DEFAULT_APIKEY"],
                    body=value,
                )
                value = await _request(
                    self.vendor,
                    "GET",
                    "/api/v1/workflows/" + identity,
                    token=self.env["SHUFFLE_DEFAULT_APIKEY"],
                )
            validate_workflow(value, kind, task_app, callback_app)
            artifact = workflow_artifact(value)
            if self.journal["workflows"][kind].get("sha256") not in {None, artifact.sha256}:
                raise ValueError("Stored domain graph fingerprint changed")
            self.journal["workflows"][kind]["sha256"] = artifact.sha256
            self.workflows[kind] = value
            _save(self.state / ("domain-workflow-" + kind + ".json"), value)
        self.save()
        bind_workflows(
            self.state,
            self.workflows,
            task_app_id=task_app,
            callback_app_id=callback_app,
            org_id=org,
            qualification_id=self.journal["id"],
        )
        self.runtime.seed()
        self.runtime.command("compose", "restart", "core", mutate=True)
        await _ready(self.core, "/healthz")
        self.roles = _roles(self.state)
        config = json.loads((self.state / "core.json").read_text())
        self.roles["approver"] = next(
            token
            for token, actor in config["credentials"].items()
            if actor["actor_id"] == "rf05-qualification-human"
        )
        batch = load_replay(self.state / "replay.jsonl", source_id=config["playbooks"]["source_id"])
        self.alerts = {
            alert.scenario_id.removeprefix("rf05-"): alert
            for alert in make_alerts(batch, ingested_at=logical_receipt(batch))
        }
        self.transport = ShuffleTransport(
            ShuffleConfig(
                base_url="https://127.0.0.1:3443",
                api_key=self.env["SHUFFLE_DEFAULT_APIKEY"],
                workflow_ids=frozenset(item["id"] for item in self.workflows.values()),
                org_id=org,
                ca_file=str(self.state / "pki/ca.pem"),
                timeout=15,
            )
        )

    def snapshot(self, profile: str) -> dict[str, Any]:
        endpoint = self.alerts[profile].endpoint.model_dump(mode="json")
        code = (
            "import json; from pathlib import Path; from responseforge.contracts import EndpointRef; "
            "from responseforge.integrations.mock_edr import MockResponseProvider; "
            "c=json.loads(Path('/run/responseforge/core.json').read_text()); "
            "p=MockResponseProvider(c['playbooks']['mock_path']); "
            "print(json.dumps(p.snapshot(EndpointRef.model_validate(" + repr(endpoint) + "))))"
        )
        return dict(
            json.loads(
                self.runtime._raw(
                    self.runtime._verified(mutate=False),
                    ("exec", PROJECT + "-core", "python", "-c", code),
                )
            )
        )

    async def audit(self, incident: str) -> list[dict[str, Any]]:
        return list(
            await _request(
                self.core,
                "GET",
                "/v1/incidents/" + incident + "/audit",
                token=self.roles["analyst"],
            )
        )

    async def run(
        self,
        label: str,
        profile: str,
        kind: str,
        gate_status: str,
        effects: int,
        *,
        callback_fault: bool = False,
        task_fault: bool = False,
        restart: bool = False,
    ) -> dict[str, Any]:
        scenario = _EXPECTED.get(label)
        if (
            scenario is None
            or scenario[:4]
            != (
                kind,
                gate_status,
                "unavailable"
                if task_fault
                else ("SUCCESS" if gate_status in {"ready", "uncertain"} else "SKIPPED"),
                effects,
            )
            or (callback_fault, task_fault, restart)
            != (label == "callback-loss", label == "task-failure", label == "restart")
        ):
            raise ValueError("Invocation differs from frozen domain scenario")
        if label in self.journal["results"]:
            return await self.cached(label, profile, kind)
        alert = self.alerts[profile]
        intake = await _request(
            self.core,
            "POST",
            "/v1/alerts",
            token=self.roles["source"],
            body=alert.model_dump(mode="json"),
            statuses=(200, 201),
        )
        duplicate = await _request(
            self.core,
            "POST",
            "/v1/alerts",
            token=self.roles["source"],
            body=alert.model_dump(mode="json"),
            statuses=(200, 201),
        )
        if intake["incident_id"] != duplicate["incident_id"] or duplicate["duplicate"] is not True:
            raise ValueError("Actual domain duplicate intake changed case identity")
        self.journal["cases"][profile] = intake
        self.save()
        incident, workflow = intake["incident_id"], self.workflows[kind]
        item = self.journal["runs"].get(label)
        if item is None:
            item = {
                "run_id": str(uuid4()),
                "incident_id": incident,
                "correlation_id": intake["correlation_id"],
                "workflow_id": workflow["id"],
                "reserved": True,
            }
            self.journal["runs"][label] = item
            self.save()
        if item["incident_id"] != incident or item["workflow_id"] != workflow["id"]:
            raise ValueError("Original domain run identity changed")
        if callback_fault:
            _save(self.state / "fault.json", {"ack_delay_seconds": 8}, readable=True)
        if task_fault:
            _save(self.state / "fault.json", {"task_fail_after_prepare": True}, readable=True)
        base = "/v1/incidents/" + incident
        start = await _request(
            self.core,
            "POST",
            base + "/shuffle/start",
            token=self.roles["analyst"],
            body={"workflow_id": workflow["id"], "run_id": item["run_id"]},
        )
        repeated = await _request(
            self.core,
            "POST",
            base + "/shuffle/start",
            token=self.roles["analyst"],
            body={"workflow_id": workflow["id"], "run_id": item["run_id"]},
        )
        if (
            start["argument"]["run_id"] != repeated["argument"]["run_id"]
            or repeated["argument"]["run_id"] != item["run_id"]
        ):
            raise ValueError("Actual duplicate domain start changed original run")
        argument = ShuffleArgument(
            incident_id=incident,
            run_id=item["run_id"],
            correlation_id=item["correlation_id"],
            mode="replay",
        )
        deadline = time.monotonic() + 180
        observed = None
        while time.monotonic() < deadline:
            try:
                observed = await self.transport.get_execution(
                    workflow["id"], item["run_id"], argument
                )
                if observed.vendor_status in {"FINISHED", "SUCCESS", "FAILURE", "ABORTED"}:
                    break
            except Exception:
                pass
            await asyncio.sleep(1)
        if observed is None or observed.vendor_status not in {
            "FINISHED",
            "SUCCESS",
            "FAILURE",
            "ABORTED",
        }:
            raise ValueError("Genuine domain completion deadline expired: " + label)
        if observed.workflow_sha256 != self.journal["workflows"][kind]["sha256"]:
            raise ValueError("Actual executed domain graph differs from reviewed source")
        raw = await _request(
            self.vendor,
            "POST",
            "/api/v1/streams/results",
            token=self.env["SHUFFLE_DEFAULT_APIKEY"],
            body={"execution_id": item["run_id"]},
        )
        _save(self.state / ("domain-execution-" + item["run_id"] + ".json"), raw)
        tasks = {
            name: [
                value
                for value in raw.get("results", [])
                if value.get("action", {}).get("app_name") == "responseforge_tasks"
                and value["action"].get("name") == name
            ]
            for name in ("prepare", "gate", "dispatch")
        }
        if len(tasks["prepare"]) != 1:
            raise ValueError("Actual workflow lacks unique prepare result")
        audit = await self.audit(incident)
        if not any(
            value["operation"] == "playbook_prepared" and item["run_id"] in value["detail"]
            for value in audit
        ):
            raise ValueError("Native prepare has no bound core audit")
        if task_fault:
            task = tasks["prepare"][0]
            body = TaskResult.model_validate_json(task["result"])
            if (
                task["status"] != "FAILURE"
                or body.delivery != "uncertain"
                or not any(value["operation"] == "qualification_prepare_failure" for value in audit)
            ):
                raise ValueError("Actual post-commit task failure was not proven")
            gate_native, dispatch_native = "unavailable", "unavailable"
        else:
            if any(len(values) != 1 for values in tasks.values()):
                raise ValueError("Actual domain task results missing or duplicated")
            prepare = TaskResult.model_validate_json(tasks["prepare"][0]["result"])
            gate = TaskResult.model_validate_json(tasks["gate"][0]["result"])
            dispatch = TaskResult.model_validate_json(tasks["dispatch"][0]["result"])
            if (
                prepare.status != "prepared"
                or gate.status != gate_status
                or gate.kind != kind
                or tasks["prepare"][0]["status"] != "SUCCESS"
                or tasks["gate"][0]["status"] != "SUCCESS"
            ):
                raise ValueError("Genuine native prepare/gate differs from expectation: " + label)
            selected = gate_status in {"ready", "uncertain"}
            if (
                tasks["dispatch"][0]["status"] != ("SUCCESS" if selected else "SKIPPED")
                or dispatch.delivery != ("accepted" if selected else "skipped")
                or (selected and dispatch.status != "completed")
            ):
                raise ValueError("Actual native branch/response differs from expectation: " + label)
            gate_native, dispatch_native = gate.status, tasks["dispatch"][0]["status"]
        # Recover durable original receipts after native completion. Restarting
        # inside an unacknowledged mutating task correctly fails closed instead.
        if restart and not item.get("core_restart_proven"):
            before = self.runtime._raw(
                self.runtime._verified(mutate=False),
                ("inspect", "--format", "{{.State.StartedAt}}", PROJECT + "-core"),
            )
            self.runtime.command("compose", "restart", "core", mutate=True)
            await _ready(self.core, "/healthz")
            after = self.runtime._raw(
                self.runtime._verified(mutate=False),
                ("inspect", "--format", "{{.State.StartedAt}}", PROJECT + "-core"),
            )
            if before == after:
                raise ValueError("Actual core restart was not observed")
            item["core_restart_proven"] = True
            self.save()
        _save(self.state / "fault.json", {}, readable=True)
        delivery = await _request(
            self.core,
            "POST",
            base + "/shuffle/reconcile",
            token=self.roles["analyst"],
            body={"run_id": item["run_id"]},
        )
        expected = "uncertain" if callback_fault or task_fault else "finished"
        if delivery["state"] != expected:
            raise ValueError("Actual domain reconciliation differs: " + label)
        if not task_fault and not any(value["operation"] == "workflow_callback" for value in audit):
            raise ValueError("Actual native final callback has no authenticated core audit")
        callback_proven = callback_fault and any(
            value["operation"] == "qualification_callback_ack_delay" for value in audit
        )
        if callback_fault and not callback_proven:
            raise ValueError("Callback ACK fault had no post-commit proof")
        snapshot = self.snapshot(profile)
        if snapshot["effect_count"] != effects or (
            profile == "containment" and snapshot["isolated"] != (effects == 1)
        ):
            raise ValueError("Actual durable simulated effects differ: " + label)
        # Query the already-native-created immutable plan; do not synthesize one.
        plan = PlaybookPlan.model_validate(
            await _request(
                self.core,
                "POST",
                base + "/playbooks/prepare",
                token=self.roles["workflow"],
                body={**argument.model_dump(mode="json"), "workflow_id": workflow["id"]},
            )
        )
        if profile in {"persistence", "incomplete"} and (
            plan.proposal_id is not None or plan.assessment.disposition != "escalate"
        ):
            raise ValueError("Unsupported or incomplete evidence manufactured an action")
        if (
            profile == "persistence"
            and "does not support disable_persistence" not in plan.assessment.rationale
        ):
            raise ValueError("Persistence did not report actual unsupported capability")
        for format_name in ("json", "html"):
            response = await self.core.get(
                base + "/report",
                params={"format": format_name},
                headers={"Authorization": "Bearer " + self.roles["analyst"]},
            )
            if response.status_code != 200 or any(
                secret in response.text for secret in self.secret_values() if len(secret) >= 20
            ):
                raise ValueError("Domain export failed or disclosed a credential")
        record = {
            "run_id": item["run_id"],
            "incident_id": incident,
            "workflow_id": workflow["id"],
            "kind": kind,
            "vendor_status": observed.vendor_status,
            "delivery_state": delivery["state"],
            "gate_status": gate_native,
            "dispatch_native": dispatch_native,
            "effect_count": snapshot["effect_count"],
            "graph_verified": True,
            "audit_verified": True,
            "duplicate_start": True,
            "callback_fault_proven": bool(callback_proven),
            "task_failure_proven": task_fault,
            "core_restart_proven": item.get("core_restart_proven", False),
            "proposal_id": plan.proposal_id,
        }
        self.journal["results"][label] = record
        self.save()
        return record

    async def cached(self, label: str, profile: str, kind: str) -> dict[str, Any]:
        """Re-observe the original execution; never replay a cached mutation."""
        record = self.journal["results"][label]
        item = self.journal["runs"].get(label, {})
        case = self.journal["cases"].get(profile, {})
        workflow = self.workflows[kind]
        if (
            not _valid_record(label, record)
            or any(
                record.get(key) != item.get(key) for key in ("run_id", "incident_id", "workflow_id")
            )
            or record.get("incident_id") != case.get("incident_id")
            or record.get("workflow_id") != workflow["id"]
        ):
            raise ValueError("Cached domain result differs from original scenario identity")
        argument = ShuffleArgument(
            incident_id=item["incident_id"],
            run_id=item["run_id"],
            correlation_id=case["correlation_id"],
            mode="replay",
        )
        observed = await self.transport.get_execution(workflow["id"], item["run_id"], argument)
        callback = (
            None
            if label == "task-failure"
            else ("FAILURE" if label == "callback-loss" else "SUCCESS")
        )
        if (
            observed.vendor_status != record["vendor_status"]
            or observed.workflow_sha256 != self.journal["workflows"][kind]["sha256"]
            or observed.callback_status != callback
        ):
            raise ValueError("Cached native completion is no longer proven by original execution")
        delivery = await _request(
            self.core,
            "POST",
            "/v1/incidents/" + item["incident_id"] + "/shuffle/reconcile",
            token=self.roles["analyst"],
            body={"run_id": item["run_id"]},
        )
        audit = await self.audit(item["incident_id"])
        durable = DeliveryRecord.model_validate(delivery)
        required_audit = {"playbook_prepared"}
        if label != "task-failure":
            required_audit.add("workflow_callback")
        if label == "callback-loss":
            required_audit.add("qualification_callback_ack_delay")
        if label == "task-failure":
            required_audit.add("qualification_prepare_failure")
        if (
            durable.state != record["delivery_state"]
            or durable.argument != argument
            or durable.workflow_id != workflow["id"]
            or durable.workflow_sha256 != observed.workflow_sha256
            or durable.callback_status != callback
            or not required_audit.issubset({value["operation"] for value in audit})
            or not any(
                value["operation"] == "playbook_prepared" and item["run_id"] in value["detail"]
                for value in audit
            )
        ):
            raise ValueError("Cached domain core delivery/audit changed")
        # Historical zero effects can precede an approved run on the same case.
        # Current durable effects are verified separately against final snapshots.
        return dict(record)

    def secret_values(self) -> list[str]:
        config = json.loads((self.state / "core.json").read_text())
        return list(config["credentials"]) + list(self.env.values())

    async def decide(self, label: str, decision: str, *, expire: bool = False) -> None:
        result = self.journal["results"][label]
        proposal = result["proposal_id"]
        view = await _request(
            self.core, "GET", "/v1/actions/" + proposal, token=self.roles["analyst"]
        )
        existing = view["approval"]
        key = label + ":" + decision
        if existing is not None:
            if (
                existing["decision"] != decision
                or existing["approver_id"] != "rf05-qualification-human"
            ):
                raise ValueError("Existing immutable synthetic human decision differs")
        else:
            if key in self.journal["decisions"]:
                raise ValueError(
                    "Human fixture acknowledgement uncertain; inspect original decision"
                )
            expires = (datetime.now(UTC) + timedelta(seconds=2 if expire else 600)).isoformat()
            self.journal["decisions"][key] = {"reserved": True, "expires_at": expires}
            self.save()
            existing = await _request(
                self.core,
                "POST",
                "/v1/actions/" + proposal + ("/approve" if decision == "approved" else "/reject"),
                token=self.roles["approver"],
                body={"expires_at": expires},
            )
        if expire:
            wait = (
                datetime.fromisoformat(existing["expires_at"].replace("Z", "+00:00"))
                - datetime.now(UTC)
            ).total_seconds()
            if wait > 3:
                raise ValueError("Expiry fixture is not short and bounded")
            await asyncio.sleep(max(0, wait) + 0.2)

    async def denied_execute(self, label: str) -> None:
        result = self.journal["results"][label]
        response = await self.core.post(
            "/v1/actions/" + result["proposal_id"] + "/execute",
            headers={"Authorization": "Bearer " + self.roles["executor"]},
            json={"provider": "mock-edr"},
        )
        if response.status_code not in {403, 409}:
            raise ValueError("Actual denied/expired approval dispatched")
        if (
            self.snapshot("denied" if label.startswith("denied") else "expired")["effect_count"]
            != 0
        ):
            raise ValueError("Denied/expired approval changed simulated endpoint")


async def qualify_playbooks(state_dir: Path) -> dict[str, Any]:
    runtime = DockerRuntime(state_dir)
    runtime._verified(mutate=True)
    try:
        return await _qualify_playbooks(state_dir)
    finally:
        _save(state_dir / "fault.json", {}, readable=True)


async def _qualify_playbooks(state: Path) -> dict[str, Any]:
    tls = ssl.create_default_context(cafile=str(state / "pki/ca.pem"))
    started = time.monotonic()
    pacer = _CorePacer()
    async with (
        httpx.AsyncClient(
            base_url="https://127.0.0.1:3443", verify=tls, timeout=20, trust_env=False
        ) as vendor,
        httpx.AsyncClient(
            base_url="https://127.0.0.1:8443",
            verify=tls,
            timeout=20,
            trust_env=False,
            event_hooks={"request": [pacer]},
        ) as core,
    ):
        lab = _Lab(state, vendor, core)
        sentinel_before = _sentinel(
            lab.runtime, lab.journal, lab.path, lab.manifest["images"]["core"]
        )
        age = (
            datetime.now(UTC).timestamp()
            - datetime.fromisoformat(sentinel_before["Created"].replace("Z", "+00:00")).timestamp()
        )
        await asyncio.sleep(max(0, 3 - age))
        await lab.bootstrap()
        await lab.run("process-awaiting", "process", "process", "awaiting_approval", 0)
        await lab.decide("process-awaiting", "approved")
        await lab.run("process-approved", "process", "process", "ready", 1)
        await lab.run("process-duplicate", "process", "process", "completed", 1)
        await lab.run("denied-awaiting", "denied", "process", "awaiting_approval", 0)
        await lab.decide("denied-awaiting", "rejected")
        await lab.run("denied-final", "denied", "process", "denied", 0)
        await lab.denied_execute("denied-final")
        await lab.run("expired-awaiting", "expired", "process", "awaiting_approval", 0)
        await lab.decide("expired-awaiting", "approved", expire=True)
        await lab.run("expired-final", "expired", "process", "expired", 0)
        await lab.denied_execute("expired-final")
        await lab.run("incomplete", "incomplete", "process", "no_action", 0)
        await lab.run("persistence", "persistence", "persistence", "no_action", 0)
        await lab.run("containment-awaiting", "containment", "containment", "awaiting_approval", 0)
        await lab.decide("containment-awaiting", "approved")
        await lab.run("containment-approved", "containment", "containment", "ready", 1)
        await lab.run(
            "callback-loss", "callback-loss", "process", "awaiting_approval", 0, callback_fault=True
        )
        await lab.run("restart", "restart", "process", "awaiting_approval", 0, restart=True)
        await lab.run("task-failure", "task-failure", "process", "unavailable", 0, task_fault=True)
        if not _valid_proof(lab.journal["results"]):
            raise ValueError("Domain acceptance proof is incomplete")
        if len(lab.journal["cases"]) != 9:
            raise ValueError("Nine independently scoped original cases are required")
        # Actual timestamp metrics, once per case; approval/automation wait remains distinct.
        readiness = []
        for case in lab.journal["cases"].values():
            metrics = await _request(
                core,
                "GET",
                "/v1/incidents/" + case["incident_id"] + "/metrics",
                token=lab.roles["analyst"],
            )
            accepted = next(item for item in metrics if item["kind"] == "alert_accepted")
            ready = next(item for item in metrics if item["kind"] == "case_ready")
            readiness.append(
                (
                    datetime.fromisoformat(ready["occurred_at"])
                    - datetime.fromisoformat(accepted["occurred_at"])
                ).total_seconds()
            )
        actions = []
        for name in ("process-approved", "containment-approved"):
            record = lab.journal["results"][name]
            view = await _request(
                core, "GET", "/v1/actions/" + record["proposal_id"], token=lab.roles["analyst"]
            )
            execution, approval = view["execution"], view["approval"]
            if (
                execution["verification"]["status"] != "verified"
                or execution["verification"]["verified_live"] is not False
            ):
                raise ValueError("Actual response effect verification is missing or mislabeled")
            actions.append(
                {
                    "approval_to_dispatch_seconds": (
                        datetime.fromisoformat(execution["requested_at"])
                        - datetime.fromisoformat(approval["decided_at"])
                    ).total_seconds(),
                    "dispatch_to_verified_seconds": (
                        datetime.fromisoformat(execution["verification"]["checked_at"])
                        - datetime.fromisoformat(execution["requested_at"])
                    ).total_seconds(),
                }
            )
        all_secrets = lab.secret_values()
        for item in lab.journal["runs"].values():
            raw = await _request(
                vendor,
                "POST",
                "/api/v1/streams/results",
                token=lab.env["SHUFFLE_DEFAULT_APIKEY"],
                body={"execution_id": item["run_id"]},
            )
            if isinstance(raw.get("authorization"), str):
                all_secrets.append(raw["authorization"])
        _scan_logs(lab.runtime, all_secrets)
        snapshots = {profile: lab.snapshot(profile) for profile in lab.alerts}
        lab.runtime.command("compose", "restart", "backend", mutate=True)
        await _ready(vendor, "/api/v1/getinfo", token=lab.env["SHUFFLE_DEFAULT_APIKEY"])
        lab.runtime.command("compose", "restart", "orborus", mutate=True)

        # Foreign sentinel must be the same live container, not a reconstructed substitute.
        def sentinel() -> dict[str, Any]:
            return dict(
                json.loads(
                    lab.runtime._raw(
                        lab.runtime._verified(mutate=False),
                        ("inspect", "--format", "{{json .}}", lab.journal["sentinel_id"]),
                    )
                )
            )

        before_down = sentinel()
        if (
            before_down["State"]["StartedAt"] != sentinel_before["State"]["StartedAt"]
            or not before_down["State"]["Running"]
        ):
            raise ValueError("Foreign sentinel changed during domain execution/restart")
        lab.runtime.down()
        after_down = sentinel()
        if (
            after_down["Id"] != before_down["Id"]
            or after_down["State"]["StartedAt"] != before_down["State"]["StartedAt"]
            or not after_down["State"]["Running"]
        ):
            raise ValueError("Foreign sentinel changed during domain teardown")
        lab.runtime.up()
        await _ready(core, "/healthz")
        await _ready(vendor, "/api/v1/getinfo", token=lab.env["SHUFFLE_DEFAULT_APIKEY"])
        for name in ("process-approved", "persistence", "containment-approved", "callback-loss"):
            item = lab.journal["runs"][name]
            argument = ShuffleArgument(
                incident_id=item["incident_id"],
                run_id=item["run_id"],
                correlation_id=item["correlation_id"],
                mode="replay",
            )
            observed = await lab.transport.get_execution(
                item["workflow_id"], item["run_id"], argument
            )
            kind = lab.journal["results"][name]["kind"]
            if observed.workflow_sha256 != lab.journal["workflows"][kind][
                "sha256"
            ] or observed.vendor_status not in {"FINISHED", "SUCCESS", "FAILURE", "ABORTED"}:
                raise ValueError("Original domain execution did not persist")
            await _request(
                core, "GET", "/v1/incidents/" + item["incident_id"], token=lab.roles["analyst"]
            )
        if snapshots != {profile: lab.snapshot(profile) for profile in lab.alerts}:
            raise ValueError("Simulated receipts/state changed during down/up")
        lost = lab.journal["runs"]["callback-loss"]
        persisted_loss = await _request(
            core,
            "POST",
            "/v1/incidents/" + lost["incident_id"] + "/shuffle/reconcile",
            token=lab.roles["analyst"],
            body={"run_id": lost["run_id"]},
        )
        if persisted_loss["state"] != "uncertain":
            raise ValueError("Lost callback acknowledgement became false success after restart")
        labels = sentinel()["Config"]["Labels"]
        if (
            labels.get("responseforge.sentinel") != lab.journal["sentinel_key"]
            or labels.get(LABEL) != "unrelated-rf04-sentinel"
        ):
            raise ValueError("Foreign sentinel ownership differs; refusing cleanup")
        lab.runtime._raw(
            lab.runtime._verified(mutate=True), ("rm", "-f", lab.journal["sentinel_id"])
        )
        _scan_logs(lab.runtime, all_secrets)
        summary = {
            "runtime_qualified": True,
            "domain_workflows_qualified": 3,
            "mode": "replay",
            "verified_live": False,
            "effects_simulated": True,
            "endpoint_effect": "none",
            "revision": _revision(),
            "source_tree_sha256": lab.binding["source_tree_sha256"],
            "source_sha256": lab.binding["source_sha256"],
            "images": lab.manifest["images"],
            "platform": lab.manifest["architecture"],
            "run_count": len(lab.journal["results"]),
            "case_count": 9,
            "runs": lab.journal["results"],
            "snapshots": snapshots,
            "readiness": _distribution(readiness),
            "action_timings": actions,
            "core_vendor_restart": True,
            "persistence_down_up": True,
            "unrelated_sentinel_preserved": True,
            "configured_execution_secret_scans": True,
            "negative_dispatch_attempts": 2,
            "host_request_pacing_seconds": round(pacer.waited_seconds, 3),
            "expected_uncertain_fault_runs": 2,
            "elapsed_seconds_current_invocation": round(time.monotonic() - started, 3),
            "limitations": "Original synthetic data; 9 case samples; latency includes harness pacing; simulated effects only; no analyst-time/throughput/live claim",
        }
        _save(state / "domain-summary.json", summary)
        return summary
