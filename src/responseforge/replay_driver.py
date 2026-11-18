"""Offline HTTP replay runner; simulated approval requires explicit operator choice."""

import platform
import re
import secrets
import sqlite3
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx

from responseforge.api import create_app
from responseforge.contracts import ActionProposal, ActionType, EndpointRef, Incident, Mode
from responseforge.integrations.mock_edr import MockResponseProvider
from responseforge.investigation import ReplayEvidenceProvider
from responseforge.replay import ReplayError, ReplaySource, logical_receipt
from responseforge.replay_contracts import ReplayBatch, ReplayRunSummary, digest
from responseforge.runtime import Principal, Settings


def _revision() -> str:
    """Attribute observations to repository revision when available; never fake one."""
    from responseforge import __version__

    root = Path(__file__).resolve().parents[2]
    if (root / "src/responseforge/replay_driver.py").resolve() != Path(__file__).resolve():
        return "package-" + __version__ + "-source-revision-unavailable"
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
        changed = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40}", head):
            return head + ("-dirty" if changed else "")
    except (OSError, subprocess.SubprocessError):
        pass
    return "package-" + __version__ + "-source-revision-unavailable"


def _pid(value: str | None) -> str | None:
    return (
        value
        if value is not None
        and re.fullmatch(r"[1-9][0-9]{0,9}", value)
        and int(value) <= 2147483647
        else None
    )


async def run_replay(
    batch: ReplayBatch,
    *,
    database_path: str | Path,
    mock_path: str | Path,
    output_dir: str | Path,
    decision: Literal["none", "approve", "reject"] = "none",
    speed: float = 0,
    clock: Callable[[], datetime] | None = None,
) -> ReplayRunSummary:
    batch = ReplayBatch.model_validate(batch.model_dump(mode="json", warnings=False))
    if decision not in {"none", "approve", "reject"}:
        raise ReplayError("Unknown replay operator decision")
    if Path(database_path).resolve() == Path(mock_path).resolve():
        raise ReplayError("Core and simulated state require distinct database paths")
    now = clock or (lambda: datetime.now(UTC))
    source = ReplaySource(batch, ingested_at=logical_receipt(batch), speed=speed)
    endpoints: dict[str, EndpointRef] = {}
    processes: dict[str, set[str]] = {}
    for event in batch.events:
        previous = endpoints.get(event.endpoint.endpoint_id)
        if previous is not None and previous != event.endpoint:
            raise ReplayError("Conflicting canonical endpoint identities in replay")
        endpoints[event.endpoint.endpoint_id] = event.endpoint
        processes.setdefault(event.endpoint.endpoint_id, set())
        process = _pid(event.fields.get("process_id")) if event.artifact == "process" else None
        if process is not None:
            processes[event.endpoint.endpoint_id].add(process)
    provider = MockResponseProvider(mock_path, clock=now)
    for identity, endpoint in endpoints.items():
        provider.seed_endpoint(endpoint, processes=tuple(sorted(processes[identity])))
    resources = {
        key: frozenset("process:" + x for x in values) for key, values in processes.items()
    }
    all_resources = frozenset(x for values in resources.values() for x in values)
    credentials: dict[str, Principal] = {}
    tokens = {}
    for role in ("source", "analyst", "approver", "executor"):
        token = secrets.token_urlsafe(32)
        tokens[role] = token
        credentials[token] = Principal(
            actor_id="offline-replay-" + role,
            roles=frozenset({role}),
            endpoint_ids=frozenset(endpoints),
            actions=frozenset({ActionType.TERMINATE_PROCESS}),
            resources=all_resources,
            sources=frozenset({"replay-fixture"}) if role == "source" else frozenset(),
            human=role == "approver",
        )
    settings = Settings(
        database_path=database_path,
        mode=Mode.REPLAY,
        endpoints=tuple(endpoints.values()),
        credentials=credentials,
        resource_allowlist=resources,
        providers={provider.name: provider},
        provider_versions={provider.name: provider.version},
        evidence_provider=ReplayEvidenceProvider(batch, clock=now),
        replay_batch=batch,
        revision=_revision(),
        environment="offline-synthetic-replay:"
        + platform.system()
        + "-"
        + platform.machine()
        + ":Python"
        + platform.python_version()
        + ":SQLite"
        + sqlite3.sqlite_version,
    )
    app = create_app(settings, clock=now)
    incidents: list[str] = []
    report_paths: list[str] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://offline.local"
    ) as client:

        async def request(method: str, path: str, role: str = "analyst", value: Any = None) -> Any:
            response = await client.request(
                method, path, headers={"Authorization": "Bearer " + tokens[role]}, json=value
            )
            if response.status_code >= 400:
                raise ReplayError(
                    "Offline replay API operation rejected (status "
                    + str(response.status_code)
                    + ")"
                )
            return response.json()

        async for alert in source.ingest():
            accepted = await request("POST", "/v1/alerts", "source", alert.model_dump(mode="json"))
            incident_id = accepted["incident_id"]
            incidents.append(incident_id)
            base = "/v1/incidents/" + incident_id
            incident = Incident.model_validate(await request("GET", base))
            if incident.status == "RECEIVED":
                await request("POST", base + "/transition", value={"status": "TRIAGING"})
                incident = Incident.model_validate(await request("GET", base))
            if incident.status == "TRIAGING":
                await request("POST", base + "/transition", value={"status": "INVESTIGATING"})
            try:
                start, end = (
                    alert.event_time - timedelta(minutes=5),
                    alert.event_time + timedelta(minutes=5),
                )
            except OverflowError:
                raise ReplayError("Replay evidence window exceeds timestamp range") from None
            gathered = []
            gaps: list[str] = []
            for artifact in ("process", "network", "file", "persistence"):
                result = await request(
                    "POST",
                    base + "/collect",
                    value={
                        "incident_id": incident_id,
                        "mode": "replay",
                        "scenario_id": alert.scenario_id,
                        "endpoint": alert.endpoint.model_dump(mode="json"),
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                        "artifact": artifact,
                    },
                )
                gathered.extend(result["evidence"])
                gaps.extend(result["gaps"])
            observed = [
                e
                for e in batch.events
                if e.scenario_id == alert.scenario_id
                and e.endpoint == alert.endpoint
                and start <= e.observed_at <= end
            ]
            candidates = [
                e
                for e in observed
                if e.artifact == "process"
                and e.observed_at == alert.event_time
                and e.fields.get("image", "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
                == "powershell.exe"
                and "-encodedcommand" in e.fields.get("command_line", "").casefold()
                and "-windowstyle hidden" in e.fields.get("command_line", "").casefold()
            ]
            target = next(
                (
                    e
                    for e in candidates
                    if _pid(e.fields.get("process_id")) is not None
                    and e.fields.get("process_guid", "").strip()
                ),
                None,
            )
            recorded_guids = {
                e.fields.get("process_guid") for e in observed if e.artifact == "process"
            }
            for event in candidates:
                parent = event.fields.get("parent_process_guid") or event.fields.get("parent_guid")
                if parent and parent not in recorded_guids:
                    gaps.append("Parent process not recorded")
            actionable = alert.rule_id == "RF-REPLAY-ENCODED-PS" and target is not None
            no_action_reason = None if actionable else "No supported action from recorded evidence"
            proposal = None
            if actionable and target is not None:
                resource = "process:" + str(_pid(target.fields.get("process_id")))
                proposal_id = "proposal-" + digest(
                    [alert.alert_id, incident_id, "terminate_process", resource]
                )
                old = await client.get(
                    "/v1/actions/" + proposal_id,
                    headers={"Authorization": "Bearer " + tokens["analyst"]},
                )
                if old.status_code == 200:
                    proposal = ActionProposal.model_validate(old.json()["proposal"])
                elif old.status_code == 404:
                    proposal = ActionProposal(
                        proposal_id=proposal_id,
                        incident_id=incident_id,
                        mode=Mode.REPLAY,
                        target={"endpoint": alert.endpoint, "resource": resource},
                        action=ActionType.TERMINATE_PROCESS,
                        rationale="Observed synthetic hidden encoded PowerShell process",
                        risk="disruptive",
                        created_at=now(),
                        expires_at=now() + timedelta(minutes=30),
                        idempotency_key=proposal_id,
                    )
                    await request(
                        "POST", base + "/actions/propose", value=proposal.model_dump(mode="json")
                    )
                else:
                    raise ReplayError("Offline action lookup rejected")
            elif candidates:
                gaps.append("Target process identity not recorded")
            audit = await request("GET", base + "/audit")
            await request(
                "POST",
                base + "/ready",
                value={
                    "evidence_refs": [
                        e["evidence_id"] for e in gathered if e["availability"] == "available"
                    ],
                    "known_gaps": sorted(set(gaps)),
                    "proposal_ids": [proposal.proposal_id] if proposal else [],
                    "no_action_reason": no_action_reason,
                    "audit_event_id": audit[0]["event_id"],
                },
            )
            if proposal is not None and decision != "none":
                action_path = "/v1/actions/" + proposal.proposal_id
                view = await request("GET", action_path)
                approval = view["approval"]
                expected = "approved" if decision == "approve" else "rejected"
                if approval is None:
                    approval = await request(
                        "POST",
                        action_path + "/" + decision,
                        "approver",
                        {"expires_at": proposal.expires_at.isoformat()},
                    )
                if approval["decision"] != expected:
                    raise ReplayError("Existing immutable operator decision conflicts")
                if decision == "approve":
                    execution = view["execution"]
                    operation = (
                        "/reconcile"
                        if execution is not None
                        and execution["verification"]["status"] != "verified"
                        else "/execute"
                    )
                    await request(
                        "POST", action_path + operation, "executor", {"provider": provider.name}
                    )
                else:
                    state = await request("GET", base)
                    if state["status"] == "AWAITING_APPROVAL":
                        await request("POST", base + "/transition", value={"status": "RESOLVED"})
            elif proposal is None:
                state = await request("GET", base)
                if state["status"] == "INVESTIGATING":
                    await request("POST", base + "/transition", value={"status": "RESOLVED"})
            # Obtain the export through the same authenticated API as external callers.
            report = await request("GET", base + "/report")
            from responseforge.reports import write_report

            paths = write_report(report, output_dir)
            report_paths.extend(str(path) for path in paths)
    return ReplayRunSummary(
        incident_ids=tuple(incidents),
        report_paths=tuple(report_paths),
        quarantine=batch.quarantine,
        duplicates=batch.duplicates,
    )
