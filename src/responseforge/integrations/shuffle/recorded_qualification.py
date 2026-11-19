"""Genuine source-bound native recorded replay qualification, never offline CI."""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from responseforge.contracts import Evidence, Mode
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
from responseforge.integrations.shuffle.native_session import NativeSession
from responseforge.integrations.shuffle.operations import LABEL, PROJECT, DockerRuntime
from responseforge.integrations.shuffle.playbook_qualification import (
    _CorePacer,
    _distribution,
)
from responseforge.integrations.shuffle.qualification import (
    _environment,
    _ready,
    _request,
    _roles,
    _save,
    _scan_logs,
    _sentinel,
)
from responseforge.integrations.shuffle.recorded_bootstrap import (
    bind_recorded_workflows,
    recorded_bundle_fingerprint,
)
from responseforge.integrations.shuffle.recorded_evidence import (
    EXPECTED,
    _valid_proof,
    _valid_record,
    validate_summary,
)
from responseforge.playbooks.assessment import assess
from responseforge.playbooks.models import PlaybookPlan, PlaybookStepRequest
from responseforge.recorded_contracts import RecordedConfig, recorded_provider_name
from responseforge.replay import logical_receipt, make_alerts, replay_provenance
from responseforge.replay.registry import load_recorded_sources
from responseforge.replay_contracts import digest
from responseforge.replay_driver import _revision


def _check_native_phase(label: str, raw: dict[str, Any], run_id: str) -> None:
    """Check this phase's receipts, in addition to transport graph/origin proof."""
    try:
        _, kind, gate, native, _, _, _ = EXPECTED[label]
        tasks = {
            step: [
                value
                for value in raw["results"]
                if value.get("action", {}).get("app_name") == "responseforge_tasks"
                and value["action"].get("name") == step
            ]
            for step in ("prepare", "gate", "dispatch")
        }
        if len(tasks["prepare"]) != 1:
            raise ValueError

        def result(step: str) -> TaskResult:
            value = tasks[step][0]["result"]
            parsed = (
                TaskResult.model_validate_json(value)
                if isinstance(value, str)
                else TaskResult.model_validate(value)
            )
            if parsed.run_id != run_id or parsed.step != step:
                raise ValueError
            return parsed

        prepared = result("prepare")
        if label == "task-failure":
            if (
                tasks["prepare"][0]["status"] != "FAILURE"
                or prepared.delivery != "uncertain"
                or prepared.status != "unavailable"
                or tasks["gate"]
                or tasks["dispatch"]
            ):
                raise ValueError
            return
        if any(len(values) != 1 for values in tasks.values()):
            raise ValueError
        gated, dispatched = result("gate"), result("dispatch")
        if (
            prepared.kind != kind
            or gated.kind != kind
            or dispatched.kind != kind
            or prepared.status != "prepared"
            or prepared.delivery != "accepted"
            or gated.status != gate
            or gated.delivery != "accepted"
            or tasks["prepare"][0]["status"] != "SUCCESS"
            or tasks["gate"][0]["status"] != "SUCCESS"
            or tasks["dispatch"][0]["status"] != native
            or dispatched.delivery != ("accepted" if native == "SUCCESS" else "skipped")
            or dispatched.status != ("completed" if native == "SUCCESS" else "skipped")
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise ValueError("Original native phase proof differs from frozen recorded case") from None


class RecordedLab(NativeSession):
    # These helpers only register the fixed native app and read authenticated
    # audit/secrets. RF05's run/cached scenario oracle is deliberately not reused.

    def __init__(self, state: Path, vendor: httpx.AsyncClient, core: httpx.AsyncClient) -> None:
        self.state, self.vendor, self.core = state, vendor, core
        self.runtime = DockerRuntime(state)
        self.manifest = self.runtime._verified(mutate=True)
        self.env, self.roles = _environment(state), _roles(state)
        self.config = RecordedConfig.model_validate_json(
            (state / "recorded/cases.json").read_text()
        )
        host = self.config.model_copy(update={"bundle_root": str(state / "recorded")})
        batches = load_recorded_sources(host, mode=Mode.REPLAY)
        self.cases = {case.profile: case for case in self.config.cases}
        self.batches = {
            case.profile: batch for case, batch in zip(self.config.cases, batches, strict=True)
        }
        self.alerts = {
            profile: make_alerts(batch, ingested_at=logical_receipt(batch))[0]
            for profile, batch in self.batches.items()
        }
        self.path = state / "recorded-journal.json"
        self.journal: dict[str, Any] = (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {
                "id": self.config.qualification_id,
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
            "recorded_source_sha256": recorded_bundle_fingerprint(state / "recorded"),
            "cases": [case.model_dump(mode="json") for case in self.config.cases],
        }
        if (
            self.manifest.get("recorded_enabled") is not True
            or proof["images"] != self.manifest["images"]
            or self.manifest.get("recorded_source_sha256") != self.binding["recorded_source_sha256"]
            or self.journal.get("id") != self.config.qualification_id
            or self.journal.get("binding") not in (None, self.binding)
        ):
            raise ValueError("Recorded journal belongs to a different source/build/scope")
        self.journal["binding"] = self.binding
        self.save()
        self.workflows: dict[str, dict[str, Any]] = {}
        self.transport: ShuffleTransport

    def save(self) -> None:
        _save(self.path, self.journal)

    async def bootstrap(self) -> None:
        info = await _ready(
            self.vendor, "/api/v1/getinfo", token=self.env["SHUFFLE_DEFAULT_APIKEY"]
        )
        org = canonical_uuid(info["active_org"]["id"])
        if self.env.get("ORG") not in (None, "", org):
            raise ValueError("Existing vendor organization changed")
        self.env["ORG"] = org
        (self.state / "secrets.env").write_text(
            "".join(key + "=" + value + "\n" for key, value in self.env.items())
        )
        self.runtime.up()
        await _ready(self.vendor, "/api/v1/getinfo", token=self.env["SHUFFLE_DEFAULT_APIKEY"])
        task_app, callback_app = (
            await self.app("responseforge_tasks", org),
            await self.app("responseforge_callback", org),
        )
        for kind in ("process", "persistence", "containment"):
            item = self.journal["workflows"].get(kind)
            if item is None:
                document = build_workflow(kind, task_app, callback_app)
                document["name"] += " recorded " + self.journal["id"]
                self.journal["workflows"][kind] = {"reserved": True}
                self.save()
                response = await _request(
                    self.vendor,
                    "POST",
                    "/api/v1/workflows",
                    token=self.env["SHUFFLE_DEFAULT_APIKEY"],
                    body=document,
                )
                identity = canonical_uuid(response["id"])
                self.journal["workflows"][kind] = {"id": identity}
                self.save()
            else:
                if not item.get("id"):
                    raise ValueError("Recorded graph creation acknowledgement uncertain")
                identity = canonical_uuid(item["id"])
            value = await _request(
                self.vendor,
                "GET",
                "/api/v1/workflows/" + identity,
                token=self.env["SHUFFLE_DEFAULT_APIKEY"],
            )
            configuration = value.get("configuration", {})
            if (
                configuration.get("exit_on_error") is not True
                or configuration.get("skip_notifications") is not True
            ):
                if self.journal["workflows"][kind].get("sha256"):
                    raise ValueError("Previously bound graph configuration changed")
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
            if self.journal["workflows"][kind].get("sha256") not in (None, artifact.sha256):
                raise ValueError("Recorded graph fingerprint changed")
            self.journal["workflows"][kind]["sha256"] = artifact.sha256
            self.workflows[kind] = value
            _save(self.state / ("recorded-workflow-" + kind + ".json"), value)
        self.save()
        bind_recorded_workflows(
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
            if actor["actor_id"] == "rf06-qualification-human"
        )
        self.transport = ShuffleTransport(
            ShuffleConfig(
                base_url="https://127.0.0.1:3443",
                api_key=self.env["SHUFFLE_DEFAULT_APIKEY"],
                workflow_ids=frozenset(value["id"] for value in self.workflows.values()),
                org_id=org,
                ca_file=str(self.state / "pki/ca.pem"),
                timeout=15,
            )
        )

    def receipts(self) -> dict[str, int]:
        code = (
            "import json,sqlite3;from pathlib import Path;"
            "c=json.loads(Path('/run/responseforge/core.json').read_text());"
            "p=Path(c['recorded']['mock_path']);"
            "d=sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True);"
            "print(json.dumps(dict(d.execute('SELECT proposal_id,changed FROM receipts').fetchall())))"
        )
        value = json.loads(
            self.runtime._raw(
                self.runtime._verified(mutate=False),
                ("exec", PROJECT + "-core", "python", "-c", code),
            )
        )
        if not isinstance(value, dict) or any(
            type(count) is not int or count not in (0, 1) for count in value.values()
        ):
            raise ValueError("Recorded mock receipts are invalid")
        return dict(value)

    async def source_plan(self, profile: str, item: dict[str, Any]) -> PlaybookPlan:
        kind = item["kind"]
        argument = ShuffleArgument(
            incident_id=item["incident_id"],
            run_id=item["run_id"],
            correlation_id=item["correlation_id"],
            mode="replay",
        )
        plan = PlaybookPlan.model_validate(
            await _request(
                self.core,
                "POST",
                "/v1/incidents/" + item["incident_id"] + "/playbooks/inspect",
                token=self.roles["workflow"],
                body={**argument.model_dump(mode="json"), "workflow_id": item["workflow_id"]},
            )
        )
        batch, alert = self.batches[profile], self.alerts[profile]
        expected = assess(kind, batch, alert)
        if (
            plan.assessment != expected
            or plan.source_sha256 != batch.sha256
            or plan.kind != kind
            or plan.provider != recorded_provider_name(self.config)
            or plan.provider_version != "1.0"
            or plan.request
            != PlaybookStepRequest.model_validate(
                {**argument.model_dump(mode="json"), "workflow_id": item["workflow_id"]}
            )
        ):
            raise ValueError("Native source plan differs from reviewed original evidence")
        evidence = await _request(
            self.core,
            "GET",
            "/v1/incidents/" + item["incident_id"] + "/evidence",
            token=self.roles["analyst"],
        )
        available = [value for value in evidence if value["availability"] == "available"]
        expected_refs = tuple(
            sorted(
                "evidence-"
                + digest(
                    [
                        batch.source_id,
                        batch.sha256,
                        item["incident_id"],
                        event.scenario_id,
                        event.endpoint.model_dump(mode="json"),
                        event.event_id,
                    ]
                )
                for event in batch.events
            )
        )
        if plan.evidence_refs != expected_refs:
            raise ValueError("Recorded plan references differ from original selected source")
        if len(available) != len(batch.events) or {
            value["evidence_id"] for value in available
        } != set(plan.evidence_refs):
            raise ValueError("Recorded evidence set differs from selected source")
        for value in available:
            event = batch.events[0]
            typed = Evidence.model_validate(value)
            if (
                typed.incident_id != item["incident_id"]
                or typed.mode != Mode.REPLAY
                or typed.endpoint != alert.endpoint
                or typed.classification != "sensitive"
                or typed.collected_at > plan.created_at
            ):
                raise ValueError("Recorded evidence scope or chronology differs")
            if (
                value["provenance"]
                != replay_provenance(batch, (event.event_id,)).model_dump(mode="json")
                or datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
                != event.observed_at
            ):
                raise ValueError("Original recorded proof/time changed")
        if profile in {"powershell", "lsass", "task", "note", "dns"} and len(plan.known_gaps) < 2:
            raise ValueError("Actual incomplete source evidence was concealed")
        return plan

    async def exports(self, incident: str) -> None:
        for format_name in ("json", "html"):
            response = await self.core.get(
                "/v1/incidents/" + incident + "/report",
                params={"format": format_name},
                headers={"Authorization": "Bearer " + self.roles["analyst"]},
            )
            if response.status_code != 200 or any(
                secret in response.text for secret in self.secret_values() if len(secret) >= 20
            ):
                raise ValueError("Recorded report export failed or disclosed credentials")
            if format_name == "json":
                value = response.json()
                if (
                    value.get("source_selection") != "explicit_subset"
                    or value.get("source_transformation") != "windows-events-v1"
                    or value.get("verified_live") is not False
                    or value.get("mode") != "replay"
                    or value.get("simulated") is not True
                ):
                    raise ValueError("Recorded source/simulation report labels changed")
            (self.state / ("recorded-report-" + incident + "." + format_name)).write_text(
                response.text
            )

    async def run(self, label: str) -> dict[str, Any]:
        profile, kind, gate_status, native, effects, delta, delivery_state = EXPECTED[label]
        if label in self.journal["results"]:
            return await self.cached(label)
        alert, workflow = self.alerts[profile], self.workflows[kind]
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
            raise ValueError("Recorded duplicate intake changed identity")
        if self.journal["cases"].get(profile) not in (None, intake):
            # Duplicate disposition is allowed to differ on recovery; identity is not.
            old = self.journal["cases"][profile]
            if any(old[key] != intake[key] for key in ("incident_id", "correlation_id")):
                raise ValueError("Original recorded case changed")
        self.journal["cases"][profile] = intake
        item = self.journal["runs"].get(label)
        if item is None:
            item = {
                "run_id": str(uuid4()),
                "incident_id": intake["incident_id"],
                "correlation_id": intake["correlation_id"],
                "workflow_id": workflow["id"],
                "kind": kind,
                "profile": profile,
                "baseline_receipts": self.receipts(),
            }
            self.journal["runs"][label] = item
            self.save()
        if any(
            item[key] != value
            for key, value in (
                ("incident_id", intake["incident_id"]),
                ("correlation_id", intake["correlation_id"]),
                ("workflow_id", workflow["id"]),
                ("kind", kind),
                ("profile", profile),
            )
        ):
            raise ValueError("Original recorded run changed")
        callback_fault, task_fault = label == "callback-loss", label == "task-failure"
        if callback_fault:
            _save(self.state / "fault.json", {"ack_delay_seconds": 8}, readable=True)
        if task_fault:
            _save(self.state / "fault.json", {"task_fail_after_prepare": True}, readable=True)
        base = "/v1/incidents/" + item["incident_id"]
        body = {"workflow_id": workflow["id"], "run_id": item["run_id"]}
        started = await _request(
            self.core, "POST", base + "/shuffle/start", token=self.roles["analyst"], body=body
        )
        repeated = await _request(
            self.core, "POST", base + "/shuffle/start", token=self.roles["analyst"], body=body
        )
        if (
            started["argument"]["run_id"] != item["run_id"]
            or repeated["argument"] != started["argument"]
        ):
            raise ValueError("Recorded duplicate start changed delivery")
        argument = ShuffleArgument(
            incident_id=item["incident_id"],
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
        if (
            observed is None
            or observed.vendor_status not in {"FINISHED", "SUCCESS", "FAILURE", "ABORTED"}
            or observed.workflow_sha256 != self.journal["workflows"][kind]["sha256"]
        ):
            raise ValueError("Genuine recorded native execution missing/changed: " + label)
        raw = await _request(
            self.vendor,
            "POST",
            "/api/v1/streams/results",
            token=self.env["SHUFFLE_DEFAULT_APIKEY"],
            body={"execution_id": item["run_id"]},
        )
        _save(self.state / ("recorded-execution-" + item["run_id"] + ".json"), raw)
        _check_native_phase(label, raw, item["run_id"])
        tasks = {
            name: [
                value
                for value in raw.get("results", [])
                if value.get("action", {}).get("app_name") == "responseforge_tasks"
                and value["action"].get("name") == name
            ]
            for name in ("prepare", "gate", "dispatch")
        }
        audit = await self.audit(item["incident_id"])
        if len(tasks["prepare"]) != 1 or not any(
            value["operation"] == "playbook_prepared" and item["run_id"] in value["detail"]
            for value in audit
        ):
            raise ValueError("Genuine native Prepare did not create bound source readiness")
        if task_fault:
            prepare = TaskResult.model_validate_json(tasks["prepare"][0]["result"])
            if (
                tasks["prepare"][0]["status"] != "FAILURE"
                or prepare.delivery != "uncertain"
                or not any(value["operation"] == "qualification_prepare_failure" for value in audit)
            ):
                raise ValueError("Recorded post-commit task failure unproven")
        else:
            if any(len(values) != 1 for values in tasks.values()):
                raise ValueError("Recorded native tasks missing/duplicated")
            prepare, gate, dispatch = (
                TaskResult.model_validate_json(tasks[name][0]["result"])
                for name in ("prepare", "gate", "dispatch")
            )
            if (
                prepare.status != "prepared"
                or gate.status != gate_status
                or gate.kind != kind
                or tasks["prepare"][0]["status"] != "SUCCESS"
                or tasks["gate"][0]["status"] != "SUCCESS"
                or tasks["dispatch"][0]["status"] != native
            ):
                raise ValueError("Actual recorded native branch differs: " + label)
            if (
                native == "SUCCESS"
                and (dispatch.delivery != "accepted" or dispatch.status != "completed")
            ) or (native == "SKIPPED" and dispatch.delivery != "skipped"):
                raise ValueError("Recorded native dispatch effect proof differs")
        if label == "dns-awaiting" and not item.get("core_restart_proven"):
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
                raise ValueError("Recorded core restart not observed")
            item["core_restart_proven"] = True
            self.save()
        _save(self.state / "fault.json", {}, readable=True)
        delivery = DeliveryRecord.model_validate(
            await _request(
                self.core,
                "POST",
                base + "/shuffle/reconcile",
                token=self.roles["analyst"],
                body={"run_id": item["run_id"]},
            )
        )
        callback_status = None if task_fault else ("FAILURE" if callback_fault else "SUCCESS")
        if (
            delivery.state != delivery_state
            or delivery.argument != argument
            or delivery.workflow_sha256 != observed.workflow_sha256
            or observed.callback_status != callback_status
        ):
            raise ValueError("Recorded native/core delivery agreement missing")
        if not task_fault and not any(value["operation"] == "workflow_callback" for value in audit):
            raise ValueError("Recorded authenticated callback audit missing")
        callback_proven = callback_fault and any(
            value["operation"] == "qualification_callback_ack_delay" for value in audit
        )
        if callback_fault and not callback_proven:
            raise ValueError("Recorded callback fault phase unproven")
        # Query only after genuine native Prepare result and bound audit above.
        plan = await self.source_plan(profile, item)
        receipts = self.receipts()
        case_effects = 0 if plan.proposal_id is None else receipts.get(plan.proposal_id, 0)
        baseline = item["baseline_receipts"]
        effect_delta = sum(receipts.values()) - sum(baseline.values())
        if case_effects != effects or effect_delta != delta:
            raise ValueError("Actual recorded case receipt/effect delta differs: " + label)
        if effects:
            view = await _request(
                self.core,
                "GET",
                "/v1/actions/" + str(plan.proposal_id),
                token=self.roles["analyst"],
            )
            verification = view["execution"]["verification"]
            if (
                verification["status"] != "verified"
                or verification["simulated"] is not True
                or verification["verified_live"] is not False
            ):
                raise ValueError("Recorded effect lacks verified simulation proof")
        await self.exports(item["incident_id"])
        case = self.cases[profile]
        result = {
            "profile": profile,
            "kind": kind,
            "run_id": item["run_id"],
            "incident_id": item["incident_id"],
            "workflow_id": item["workflow_id"],
            "vendor_status": observed.vendor_status,
            "delivery_state": delivery.state,
            "gate_status": gate_status,
            "dispatch_native": native,
            "effect_count": case_effects,
            "effect_delta": effect_delta,
            "graph_verified": True,
            "audit_verified": True,
            "source_verified": True,
            "duplicate_start": True,
            "callback_fault_proven": bool(callback_proven),
            "task_failure_proven": task_fault,
            "core_restart_proven": item.get("core_restart_proven", False),
            "proposal_id": plan.proposal_id,
            "plan_disposition": plan.assessment.disposition,
            "artifact_id": case.artifact.artifact_id,
            "source_sha256": case.artifact.sha256,
        }
        if not _valid_record(label, result):
            raise ValueError("Recorded phase differs from frozen oracle")
        self.journal["results"][label] = result
        self.save()
        print(
            json.dumps({"phase": label, "delivery": delivery.state, "case_effects": case_effects}),
            flush=True,
        )
        return result

    async def cached(self, label: str) -> dict[str, Any]:
        profile, kind, _, _, _, _, _ = EXPECTED[label]
        result, item = self.journal["results"][label], self.journal["runs"].get(label, {})
        case = self.journal["cases"].get(profile, {})
        if (
            not _valid_record(label, result)
            or any(
                result.get(key) != item.get(key) for key in ("run_id", "incident_id", "workflow_id")
            )
            or case.get("incident_id") != item.get("incident_id")
            or case.get("correlation_id") != item.get("correlation_id")
            or item.get("profile") != profile
            or item.get("kind") != kind
            or item.get("workflow_id") != self.workflows[kind]["id"]
        ):
            raise ValueError("Cached recorded scenario identity changed")
        argument = ShuffleArgument(
            incident_id=item["incident_id"],
            run_id=item["run_id"],
            correlation_id=item["correlation_id"],
            mode="replay",
        )
        observed = await self.transport.get_execution(item["workflow_id"], item["run_id"], argument)
        raw = await _request(
            self.vendor,
            "POST",
            "/api/v1/streams/results",
            token=self.env["SHUFFLE_DEFAULT_APIKEY"],
            body={"execution_id": item["run_id"]},
        )
        _check_native_phase(label, raw, item["run_id"])
        callback = (
            None
            if label == "task-failure"
            else ("FAILURE" if label == "callback-loss" else "SUCCESS")
        )
        delivery = DeliveryRecord.model_validate(
            await _request(
                self.core,
                "POST",
                "/v1/incidents/" + item["incident_id"] + "/shuffle/reconcile",
                token=self.roles["analyst"],
                body={"run_id": item["run_id"]},
            )
        )
        audit = await self.audit(item["incident_id"])
        required = {"playbook_prepared"} | (
            set() if label == "task-failure" else {"workflow_callback"}
        )
        if label == "callback-loss":
            required.add("qualification_callback_ack_delay")
        if label == "task-failure":
            required.add("qualification_prepare_failure")
        if (
            observed.workflow_sha256 != self.journal["workflows"][kind]["sha256"]
            or observed.vendor_status != result["vendor_status"]
            or observed.callback_status != callback
            or delivery.argument != argument
            or delivery.workflow_id != item["workflow_id"]
            or delivery.workflow_sha256 != observed.workflow_sha256
            or delivery.state != result["delivery_state"]
            or delivery.callback_status != callback
            or not required <= {value["operation"] for value in audit}
            or not any(
                value["operation"] == "playbook_prepared" and item["run_id"] in value["detail"]
                for value in audit
            )
        ):
            raise ValueError("Cached recorded native/core/source proof no longer agrees")
        plan = await self.source_plan(profile, item)
        if (
            plan.proposal_id != result["proposal_id"]
            or self.cases[profile].artifact.sha256 != result["source_sha256"]
        ):
            raise ValueError("Cached recorded plan/source changed")
        return dict(result)

    async def decide(self, label: str, decision: str, *, expire: bool = False) -> None:
        proposal = self.journal["results"][label]["proposal_id"]
        view = await _request(
            self.core, "GET", "/v1/actions/" + proposal, token=self.roles["analyst"]
        )
        existing, key = view["approval"], label + ":" + decision
        if existing is not None:
            if (
                existing["decision"] != decision
                or existing["approver_id"] != "rf06-qualification-human"
            ):
                raise ValueError("Original recorded human decision changed")
        else:
            if key in self.journal["decisions"]:
                raise ValueError("Recorded human acknowledgement uncertain")
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
                raise ValueError("Recorded expiry fixture is not bounded")
            await asyncio.sleep(max(0, wait) + 0.2)

    async def denied_execute(self, label: str) -> None:
        before = self.receipts()
        response = await self.core.post(
            "/v1/actions/" + self.journal["results"][label]["proposal_id"] + "/execute",
            headers={"Authorization": "Bearer " + self.roles["executor"]},
            json={"provider": self.journal["recorded_provider"]},
        )
        if response.status_code not in {403, 409} or self.receipts() != before:
            raise ValueError("Forbidden recorded execute changed durable state")

    def legacy_receipts(self) -> dict[str, int]:
        code = (
            "import json,sqlite3;from pathlib import Path;"
            "c=json.loads(Path('/run/responseforge/core.json').read_text());"
            "d=sqlite3.connect('file:'+c['playbooks']['mock_path']+'?mode=ro',uri=True);"
            "print(json.dumps(dict(d.execute('SELECT proposal_id,changed FROM receipts').fetchall())))"
        )
        return dict(
            json.loads(
                self.runtime._raw(
                    self.runtime._verified(mutate=False),
                    ("exec", PROJECT + "-core", "python", "-c", code),
                )
            )
        )


async def qualify_recorded(state: Path) -> dict[str, Any]:
    DockerRuntime(state)._verified(mutate=True)
    try:
        return await _qualify_recorded(state)
    finally:
        _save(state / "fault.json", {}, readable=True)


async def _qualify_recorded(state: Path) -> dict[str, Any]:
    tls = ssl.create_default_context(cafile=str(state / "pki/ca.pem"))
    pacer, started = _CorePacer(), time.monotonic()
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
        lab = RecordedLab(state, vendor, core)
        before = _sentinel(lab.runtime, lab.journal, lab.path, lab.manifest["images"]["core"])
        age = (
            datetime.now(UTC).timestamp()
            - datetime.fromisoformat(before["Created"].replace("Z", "+00:00")).timestamp()
        )
        await asyncio.sleep(max(0, 3 - age))
        if "legacy_receipts_before" not in lab.journal:
            lab.journal["legacy_receipts_before"] = lab.legacy_receipts()
            lab.save()
        await lab.bootstrap()
        from responseforge.recorded_contracts import recorded_provider_name

        lab.journal["recorded_provider"] = recorded_provider_name(lab.config)
        lab.save()
        for label in (
            "powershell-negative",
            "lsass-negative",
            "task-negative",
            "note-negative",
            "dns-negative",
            "lsass",
            "task",
        ):
            await lab.run(label)
        await lab.run("denied-awaiting")
        await lab.decide("denied-awaiting", "rejected")
        await lab.run("denied-final")
        await lab.denied_execute("denied-final")
        await lab.run("expired-awaiting")
        await lab.decide("expired-awaiting", "approved", expire=True)
        await lab.run("expired-final")
        await lab.denied_execute("expired-final")
        await lab.run("callback-loss")
        await lab.run("task-failure")
        await lab.run("powershell-awaiting")
        await lab.decide("powershell-awaiting", "approved")
        await lab.run("powershell-approved")
        await lab.run("powershell-duplicate")
        await lab.run("note-awaiting")
        await lab.decide("note-awaiting", "approved")
        await lab.run("note-approved")
        await lab.run("dns-awaiting")
        await lab.decide("dns-awaiting", "approved")
        await lab.run("dns-approved")
        if not _valid_proof(lab.journal["results"]) or len(lab.journal["cases"]) != 14:
            raise ValueError("Recorded case/phase proof incomplete")
        samples = []
        for case in lab.journal["cases"].values():
            metrics = await _request(
                core,
                "GET",
                "/v1/incidents/" + case["incident_id"] + "/metrics",
                token=lab.roles["analyst"],
            )
            accepted, ready = (
                [value for value in metrics if value["kind"] == kind]
                for kind in ("alert_accepted", "case_ready")
            )
            if (
                len(accepted) != 1
                or len(ready) != 1
                or accepted[0]["correlation_id"] != ready[0]["correlation_id"]
            ):
                raise ValueError("Recorded readiness events missing/duplicated")
            samples.append(
                (
                    datetime.fromisoformat(ready[0]["occurred_at"].replace("Z", "+00:00"))
                    - datetime.fromisoformat(accepted[0]["occurred_at"].replace("Z", "+00:00"))
                ).total_seconds()
            )
        action_timings = []
        proposals = set()
        for label in ("powershell-approved", "note-approved", "dns-approved"):
            result = lab.journal["results"][label]
            proposals.add(result["proposal_id"])
            view = await _request(
                core, "GET", "/v1/actions/" + result["proposal_id"], token=lab.roles["analyst"]
            )
            action, approval = view["execution"], view["approval"]
            if (
                approval["approver_id"] != "rf06-qualification-human"
                or action["verification"]["status"] != "verified"
                or action["verification"]["simulated"] is not True
                or action["verification"]["verified_live"] is not False
            ):
                raise ValueError("Recorded action authority/effect proof missing")
            action_timings.append(
                {
                    "scenario": label,
                    "approval_to_dispatch_seconds": (
                        datetime.fromisoformat(action["requested_at"].replace("Z", "+00:00"))
                        - datetime.fromisoformat(approval["decided_at"].replace("Z", "+00:00"))
                    ).total_seconds(),
                    "dispatch_to_verified_seconds": (
                        datetime.fromisoformat(
                            action["verification"]["checked_at"].replace("Z", "+00:00")
                        )
                        - datetime.fromisoformat(action["requested_at"].replace("Z", "+00:00"))
                    ).total_seconds(),
                }
            )
        receipts = lab.receipts()
        if set(receipts) != proposals or list(receipts.values()) != [1] * 3:
            raise ValueError("Recorded unique durable effect receipts differ")
        secrets = lab.secret_values()
        for item in lab.journal["runs"].values():
            raw = await _request(
                vendor,
                "POST",
                "/api/v1/streams/results",
                token=lab.env["SHUFFLE_DEFAULT_APIKEY"],
                body={"execution_id": item["run_id"]},
            )
            if isinstance(raw.get("authorization"), str):
                secrets.append(raw["authorization"])
        for report in state.glob("recorded-report-*"):
            text = report.read_text()
            if any(secret in text for secret in secrets if len(secret) >= 20):
                raise ValueError("Recorded report disclosed a configured or execution credential")
        _scan_logs(lab.runtime, secrets)
        lab.runtime.command("compose", "restart", "backend", mutate=True)
        await _ready(vendor, "/api/v1/getinfo", token=lab.env["SHUFFLE_DEFAULT_APIKEY"])
        lab.runtime.command("compose", "restart", "orborus", mutate=True)

        def sentinel() -> dict[str, Any]:
            return dict(
                json.loads(
                    lab.runtime._raw(
                        lab.runtime._verified(mutate=False),
                        ("inspect", "--format", "{{json .}}", lab.journal["sentinel_id"]),
                    )
                )
            )

        for value in (sentinel(),):
            if (
                value["Id"] != before["Id"]
                or value["State"]["StartedAt"] != before["State"]["StartedAt"]
                or not value["State"]["Running"]
            ):
                raise ValueError("Recorded sentinel changed during execution")
        lab.runtime.down()
        value = sentinel()
        if (
            value["Id"] != before["Id"]
            or value["State"]["StartedAt"] != before["State"]["StartedAt"]
            or not value["State"]["Running"]
        ):
            raise ValueError("Recorded sentinel changed across teardown")
        lab.runtime.up()
        await _ready(core, "/healthz")
        await _ready(vendor, "/api/v1/getinfo", token=lab.env["SHUFFLE_DEFAULT_APIKEY"])
        if (
            lab.receipts() != receipts
            or lab.legacy_receipts() != lab.journal["legacy_receipts_before"]
        ):
            raise ValueError("Original or recorded receipts changed across down/up")
        for label in EXPECTED:
            await lab.cached(label)
        if recorded_bundle_fingerprint(state / "recorded") != lab.binding["recorded_source_sha256"]:
            raise ValueError("Recorded source snapshots changed during runtime")
        value = sentinel()
        if (
            value["Config"]["Labels"].get("responseforge.sentinel") != lab.journal["sentinel_key"]
            or value["Config"]["Labels"].get(LABEL) != "unrelated-rf04-sentinel"
        ):
            raise ValueError("Recorded sentinel ownership changed")
        lab.runtime._raw(
            lab.runtime._verified(mutate=True), ("rm", "-f", lab.journal["sentinel_id"])
        )
        _scan_logs(lab.runtime, secrets)
        readiness = _distribution(samples)
        readiness.update(
            samples_seconds=samples,
            estimator="nearest-rank p95; recorded replay lab with synthetic human decisions",
        )
        summary = {
            "runtime_qualified": True,
            "domain_workflows": 3,
            "recorded_sources": 5,
            "recorded_scenarios": 5,
            "mode": "replay",
            "verified_live": False,
            "effects_simulated": True,
            "endpoint_effect": "none",
            "revision": _revision(),
            "source_tree_sha256": lab.binding["source_tree_sha256"],
            "recorded_source_sha256": lab.binding["recorded_source_sha256"],
            "images": lab.manifest["images"],
            "platform": lab.manifest["architecture"],
            "run_count": 20,
            "case_count": 14,
            "runs": lab.journal["results"],
            "readiness": readiness,
            "action_timings": action_timings,
            "unique_simulated_effects": 3,
            "negative_dispatch_attempts": 2,
            "duplicate_effects": 0,
            "forbidden_effects": 0,
            "expected_uncertain_fault_runs": 2,
            "core_restart": True,
            "vendor_restart": True,
            "persistence_down_up": True,
            "unrelated_sentinel_preserved": True,
            "configured_execution_secret_scans": True,
            "legacy_receipts_preserved": True,
            "host_request_pacing_seconds": pacer.waited_seconds,
            "elapsed_seconds_current_invocation": time.monotonic() - started,
            "limitations": "Five recorded observation scenarios, source-selected negatives and actual missing evidence; simulated effects and synthetic human decisions; timings include host pacing; no live effect, detector accuracy, analyst savings or throughput claim",
        }
        summary["recovery"] = {
            key: summary[key]
            for key in (
                "core_restart",
                "vendor_restart",
                "persistence_down_up",
                "unrelated_sentinel_preserved",
                "configured_execution_secret_scans",
            )
        }
        validate_summary(summary)
        _save(state / "recorded-summary.json", summary)
        return summary
