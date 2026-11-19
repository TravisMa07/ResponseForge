"""Pure recommendations from registered, tightly scoped recorded observations.

These are transparent fixture rules, not general ransomware/C2 detection or live
collection. Recorded commands and persistence names remain inert source data.
"""

import re
from datetime import timedelta

from responseforge.contracts import ActionType, Alert, Mode
from responseforge.playbooks.models import Assessment, PlaybookKind
from responseforge.replay import ReplayError, make_alerts
from responseforge.replay_contracts import RecordedEvent, ReplayBatch, digest

_REPUTATION_GAP = "Offline reputation enrichment unavailable"


def _canonical(value: str | None) -> bool:
    return value is not None and bool(value) and value == value.strip()


def _pid(value: str | None) -> str | None:
    if value is None or re.fullmatch(r"[1-9][0-9]{0,9}", value) is None:
        return None
    return value if int(value) <= 2147483647 else None


def _suspicious(event: RecordedEvent) -> bool:
    image = event.fields.get("image", "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
    command = event.fields.get("command_line", "").casefold()
    return (
        event.artifact == "process"
        and image == "powershell.exe"
        and "-encodedcommand" in command
        and "-windowstyle hidden" in command
    )


def _context(batch: ReplayBatch, alert: Alert) -> tuple[RecordedEvent, ...]:
    if alert.mode != Mode.REPLAY:
        raise ReplayError("Recorded assessment cannot satisfy live mode")
    expected = next(
        (
            item
            for item in make_alerts(batch, ingested_at=alert.ingested_at)
            if item.alert_id == alert.alert_id
        ),
        None,
    )
    if expected is None or expected != alert:
        raise ReplayError("Assessment alert differs from registered source")
    try:
        start, end = (
            alert.event_time - timedelta(minutes=5),
            alert.event_time + timedelta(minutes=5),
        )
    except OverflowError:
        raise ReplayError("Assessment evidence window exceeds timestamp range") from None
    return tuple(
        sorted(
            (
                event
                for event in batch.events
                if event.endpoint == alert.endpoint
                and event.scenario_id == alert.scenario_id
                and start <= event.observed_at <= end
            ),
            key=lambda event: (event.observed_at, event.event_id),
        )
    )


def _result(
    kind: PlaybookKind,
    disposition: str,
    rationale: str,
    events: tuple[RecordedEvent, ...] = (),
    gaps: tuple[str, ...] = (),
    *,
    action: ActionType | None = None,
    resource: str | None = None,
) -> Assessment:
    return Assessment.model_validate(
        {
            "kind": kind,
            "disposition": disposition,
            "rationale": rationale,
            "event_ids": sorted({event.event_id for event in events}),
            "known_gaps": sorted(set(gaps) | {_REPUTATION_GAP}),
            "action": action,
            "resource": resource,
        }
    )


def _process(events: tuple[RecordedEvent, ...], alert: Alert) -> Assessment:
    candidates = tuple(
        event for event in events if event.observed_at == alert.event_time and _suspicious(event)
    )
    target = next(
        (
            event
            for event in candidates
            if _pid(event.fields.get("process_id")) is not None
            and _canonical(event.fields.get("process_guid"))
        ),
        None,
    )
    if target is None:
        if candidates:
            return _result(
                "process",
                "escalate",
                "Suspicious process lacks a canonical target",
                candidates,
                ("Target process identity not recorded",),
            )
        return _result("process", "no_action", "No supported process action from recorded evidence")
    guids = {event.fields.get("process_guid") for event in events if event.artifact == "process"}
    parent = target.fields.get("parent_process_guid") or target.fields.get("parent_guid")
    gaps = (
        ()
        if parent and parent in guids and parent != target.fields["process_guid"]
        else ("Parent process not recorded",)
    )
    return _result(
        "process",
        "propose",
        "Recorded hidden encoded PowerShell process",
        (target,),
        gaps,
        action=ActionType.TERMINATE_PROCESS,
        resource="process:" + str(_pid(target.fields.get("process_id"))),
    )


def _persistence(events: tuple[RecordedEvent, ...]) -> Assessment:
    records = tuple(event for event in events if event.artifact == "persistence")
    if not records:
        return _result(
            "persistence",
            "no_action",
            "No recorded persistence indicator",
            gaps=("Persistence events not recorded",),
        )
    processes = {
        event.fields.get("process_guid"): event
        for event in events
        if event.artifact == "process" and _canonical(event.fields.get("process_guid"))
    }
    for event in records:
        field = "task_name" if _canonical(event.fields.get("task_name")) else "service_name"
        identifier = event.fields.get(field)
        guid = event.fields.get("process_guid")
        if (
            _canonical(identifier)
            and _canonical(event.fields.get("account"))
            and _canonical(guid)
            and guid in processes
        ):
            mechanism = "task" if field == "task_name" else "service"
            return _result(
                "persistence",
                "propose",
                "Recorded persistence actor and process association",
                (event, processes[guid]),
                action=ActionType.DISABLE_PERSISTENCE,
                resource="persistence:" + digest([mechanism, identifier]),
            )
    return _result(
        "persistence",
        "escalate",
        "Persistence evidence lacks a complete recorded association",
        records,
        ("Persistence identifier, actor or process association not recorded",),
    )


def _containment(events: tuple[RecordedEvent, ...], alert: Alert) -> Assessment:
    processes = {
        event.fields.get("process_guid"): event
        for event in events
        if event.artifact == "process" and _canonical(event.fields.get("process_guid"))
    }
    indicators: list[RecordedEvent] = []
    for event in events:
        if event.artifact not in {"network", "file"}:
            continue
        guid = event.fields.get("process_guid")
        process = processes.get(guid)
        if event.artifact == "file":
            if event.fields.get("operation") != "shadow_copy_delete":
                continue
            indicators.append(event)
            qualifies = process is not None
        else:
            if event.fields.get("direction", "").casefold() != "outbound":
                continue
            if not (
                _canonical(event.fields.get("destination_ip"))
                or _canonical(event.fields.get("destination_domain"))
            ):
                continue
            indicators.append(event)
            qualifies = process is not None and _suspicious(process)
        if qualifies and process is not None:
            return _result(
                "containment",
                "propose",
                "Replay host isolation interrupts connectivity; rollback requires unisolate_host",
                (process, event),
                action=ActionType.ISOLATE_HOST,
                resource="host:" + alert.endpoint.endpoint_id,
            )
    if indicators:
        return _result(
            "containment",
            "escalate",
            "Recorded indicators lack a qualified process association",
            tuple(indicators),
            ("Qualified network or file process association not recorded",),
        )
    return _result(
        "containment",
        "no_action",
        "No supported containment indicator from recorded evidence",
        gaps=("Correlated containment artifacts not recorded",),
    )


def assess(kind: PlaybookKind, batch: ReplayBatch, alert: Alert) -> Assessment:
    """Return a bounded recommendation without provider I/O or endpoint effects."""
    try:
        if kind not in ("process", "persistence", "containment"):
            raise ReplayError("Unknown playbook kind")
        batch = ReplayBatch.model_validate(batch.model_dump(mode="json", warnings=False))
        alert = Alert.model_validate(alert.model_dump(mode="json", warnings=False))
        events = _context(batch, alert)
        if batch.origin is not None and batch.origin.transformation == "windows-events-v1":
            from responseforge.playbooks.recorded import assess_recorded

            result = assess_recorded(kind, events, alert)
            if batch.origin.selected_event_ids is not None:
                result = result.model_copy(update={"known_gaps": tuple(sorted(
                    set(result.known_gaps) | {
                        "Explicit recorded source subset; omitted source events were not assessed"
                    }
                ))})
            return result
        if kind == "process":
            return _process(events, alert)
        if kind == "persistence":
            return _persistence(events)
        return _containment(events, alert)
    except ReplayError:
        raise
    except (ValueError, TypeError, AttributeError, KeyError):
        raise ReplayError("Invalid recorded assessment contract") from None
