"""Narrow recorded-observation rules; source commands and payloads stay inert.

These predicates identify curated observations, not general malware behavior or
successful payload execution. Only the trusted Windows replay integration selects
this policy; original synthetic fixture rules remain independent.
"""

import re
from datetime import timedelta
from typing import Literal
from uuid import UUID

from responseforge.contracts import ActionType, Alert, Mode
from responseforge.playbooks.models import Assessment, PlaybookKind
from responseforge.replay_contracts import RecordedEvent

Signal = Literal["powershell", "lsass_access", "task_creation", "ransom_note", "process_dns"]
_REPUTATION_GAP = "Offline reputation enrichment unavailable"
_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CATEGORIES = {
    "process_create": ("process", "1"),
    "process_access": ("process", "10"),
    "task_create": ("persistence", "4698"),
    "file_create": ("file", "11"),
    "dns_query": ("network", "22"),
}


def _canonical(value: str | None) -> bool:
    return value is not None and bool(value) and value == value.strip()


def _basename(value: str | None) -> str:
    if not _canonical(value):
        return ""
    assert value is not None
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _tokens(command: str) -> list[str] | None:
    """Read a deliberately small inert launcher-token subset, never a shell."""
    if not command or any(character in command for character in "\r\n\x00"):
        return None
    tokens: list[str] = []
    offset = 0
    while offset < len(command):
        if command[offset] in " \t":
            offset += 1
            continue
        if command[offset] in {"\"", "'"}:
            quote = command[offset]
            end = command.find(quote, offset + 1)
            if end < 0 or (end + 1 < len(command) and command[end + 1] not in " \t"):
                return None
            token = command[offset + 1 : end]
            # Embedded/mixed quoting and escape interpretation are outside this
            # frozen subset. No unescaping can manufacture a launcher option.
            if "\"" in token or "'" in token:
                return None
            tokens.append(token)
            offset = end + 1
        else:
            end = offset
            while end < len(command) and command[end] not in " \t":
                if command[end] in {"\"", "'"}:
                    return None
                end += 1
            tokens.append(command[offset:end])
            offset = end
    return tokens


def _hidden_encoded(command: str | None) -> bool:
    if command is None:
        return False
    tokens = _tokens(command)
    if not tokens or _basename(tokens[0]) != "powershell.exe":
        return False
    no_argument = {"-nop", "-noprofile", "-noni", "-noninteractive", "-nologo"}
    switches: set[str] = set()
    encoded = False
    hidden = False
    offset = 1
    while offset < len(tokens):
        switch = tokens[offset].casefold()
        if switch in no_argument:
            key = "profile" if switch in {"-nop", "-noprofile"} else (
                "interactive" if switch in {"-noni", "-noninteractive"} else "logo"
            )
            if key in switches:
                return False
            switches.add(key)
            offset += 1
            continue
        argument_key = {
            "-enc": "encoded", "-encodedcommand": "encoded",
            "-windowstyle": "window", "-ep": "policy", "-executionpolicy": "policy",
        }.get(switch)
        if argument_key is None or argument_key in switches or offset + 1 >= len(tokens):
            return False
        operand = tokens[offset + 1]
        if not operand or operand.startswith("-"):
            return False
        switches.add(argument_key)
        if argument_key == "encoded":
            encoded = True
        elif argument_key == "window":
            hidden = operand.casefold() == "hidden"
        offset += 2
    return encoded and hidden


def _signal(event: RecordedEvent) -> Signal | None:
    fields = event.fields
    kind = fields.get("event_kind", "")
    if _CATEGORIES.get(kind) != (event.artifact, fields.get("windows_event_id")):
        return None
    if kind == "process_create":
        if _basename(fields.get("image")) == "powershell.exe" and _hidden_encoded(
            fields.get("command_line")
        ):
            return "powershell"
    elif kind == "process_access":
        access = fields.get("granted_access", "")
        if (
            _basename(fields.get("target_image")) == "lsass.exe"
            and _basename(fields.get("source_image")) in {"mimikatz.exe", "xordump.exe"}
            and re.fullmatch(r"0[xX][0-9a-fA-F]+", access) is not None
            and int(access, 16) & 0x10
        ):
            return "lsass_access"
    elif kind == "task_create":
        if _basename(fields.get("configured_command")) == "powershell.exe":
            return "task_creation"
    elif kind == "file_create":
        if (
            _basename(fields.get("target_filename")) == "getyoufiles.txt"
            and _basename(fields.get("image")) == "powershell.exe"
        ):
            return "ransom_note"
    elif kind == "dns_query":
        image = _basename(fields.get("image"))
        query = fields.get("query_name", "").casefold()
        if (image, query) in {
            ("wscript.exe", "pastebin.com"), ("powershell.exe", "cdn.discordapp.com")
        }:
            return "process_dns"
    return None


def recorded_signal(event: RecordedEvent) -> Signal | None:
    """Match only the frozen field predicates, never labels or executable data."""
    try:
        event = RecordedEvent.model_validate(event.model_dump(mode="json", warnings=False))
        return _signal(event)
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None


def _guid(guid: str | None) -> str | None:
    if guid is None:
        return None
    if guid.startswith("{") and guid.endswith("}"):
        guid = guid[1:-1]
    if _GUID.fullmatch(guid) is None:
        return None
    value = UUID(guid)
    return str(value) if value.int else None


def _identity(event: RecordedEvent) -> tuple[str, str] | None:
    pid = event.fields.get("process_id", "")
    guid = _guid(event.fields.get("process_guid"))
    if (
        re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None
        or int(pid) > 2147483647
        or guid is None
    ):
        return None
    return guid, pid


def _result(
    kind: PlaybookKind,
    disposition: Literal["propose", "escalate", "no_action"],
    rationale: str,
    events: tuple[RecordedEvent, ...] = (),
    gaps: tuple[str, ...] = (),
    *,
    action: ActionType | None = None,
    resource: str | None = None,
) -> Assessment:
    return Assessment(
        kind=kind,
        disposition=disposition,
        rationale=rationale,
        event_ids=tuple(sorted({event.event_id for event in events})),
        known_gaps=tuple(sorted(set(gaps) | {_REPUTATION_GAP})),
        action=action,
        resource=resource,
    )


def _target(
    kind: PlaybookKind, candidates: tuple[RecordedEvent, ...], *, gaps: tuple[str, ...]
) -> Assessment | None:
    identities = tuple(_identity(event) for event in candidates)
    if any(identity is None for identity in identities):
        return _result(
            kind, "escalate", "Recorded indicator lacks a canonical direct process identity",
            candidates, gaps + ("Canonical direct process GUID or PID not recorded",),
        )
    if len(set(identities)) != 1:
        return _result(
            kind, "escalate", "Recorded indicator has ambiguous direct process identities",
            candidates, gaps + ("Direct process identity is ambiguous",),
        )
    return None


def _process(
    events: tuple[RecordedEvent, ...], context: tuple[RecordedEvent, ...]
) -> Assessment:
    candidates = tuple(event for event in events if _signal(event) == "powershell")
    if candidates:
        refusal = _target("process", candidates, gaps=())
        if refusal is not None:
            return refusal
        target = candidates[0]
        identity = _identity(target)
        assert identity is not None
        parent = _guid(target.fields.get("parent_process_guid"))
        parent_recorded = any(
            event.artifact == "process"
            and event.fields.get("event_kind") == "process_create"
            and event.fields.get("windows_event_id") == "1"
            and parent is not None
            and _guid(event.fields.get("process_guid")) == parent
            and parent != identity[0]
            and event.observed_at <= target.observed_at
            for event in context
        )
        return _result(
            "process", "propose", "Recorded hidden encoded PowerShell process creation",
            candidates, () if parent_recorded else ("Parent process creation not recorded",),
            action=ActionType.TERMINATE_PROCESS, resource="process:" + identity[1],
        )
    access = tuple(event for event in events if _signal(event) == "lsass_access")
    if access:
        return _result(
            "process", "escalate", "Recorded process access targeting LSASS; credential theft unproven",
            access, (
                "Source and target process creation and lineage not recorded",
                "Read memory contents and credential theft not recorded",
            ),
        )
    return _result("process", "no_action", "No supported recorded process indicator at alert time")


def _persistence(events: tuple[RecordedEvent, ...]) -> Assessment:
    candidates = tuple(event for event in events if _signal(event) == "task_creation")
    if not candidates:
        return _result(
            "persistence", "no_action", "No supported recorded task indicator at alert time"
        )
    gaps = ["Task execution not recorded", "Task process association not recorded"]
    if any(not _canonical(event.fields.get("task_name")) for event in candidates):
        gaps.append("Task name not recorded")
    if any(not _canonical(event.fields.get("account")) for event in candidates):
        gaps.append("Task creator account not recorded")
    return _result(
        "persistence", "escalate",
        "Recorded scheduled task configured for PowerShell; execution not recorded",
        candidates, tuple(gaps),
    )


def _containment(events: tuple[RecordedEvent, ...], alert: Alert) -> Assessment:
    candidates = tuple(
        event for event in events if _signal(event) in {"ransom_note", "process_dns"}
    )
    if not candidates:
        return _result(
            "containment", "no_action", "No supported recorded containment indicator at alert time"
        )
    gaps: list[str] = ["Process creation and lineage not recorded by the indicator"]
    if any(_signal(event) == "ransom_note" for event in candidates):
        gaps.extend(("File contents not recorded", "Encryption and shadow-copy effects not recorded"))
    if any(_signal(event) == "process_dns" for event in candidates):
        gaps.extend((
            "DNS query only; network session not recorded",
            "Download and C2 activity not proven by DNS",
        ))
    refusal = _target("containment", candidates, gaps=tuple(gaps))
    if refusal is not None:
        return refusal
    return _result(
        "containment", "propose",
        "Recorded file or DNS indicator; replay isolation interrupts connectivity; rollback requires unisolate_host",
        candidates, tuple(gaps), action=ActionType.ISOLATE_HOST,
        resource="host:" + alert.endpoint.endpoint_id,
    )


def assess_recorded(
    kind: PlaybookKind, events: tuple[RecordedEvent, ...], alert: Alert
) -> Assessment:
    """Recommend only from exact recorded scope and the original alert anchor.

    The integration validates original source-alert binding before calling this
    function. This additional detached scope check cannot authorize live effects.
    """
    try:
        if kind not in {"process", "persistence", "containment"}:
            raise ValueError("Unknown recorded playbook kind")
        alert = Alert.model_validate(alert.model_dump(mode="json", warnings=False))
        if alert.mode != Mode.REPLAY:
            raise ValueError("Recorded policy cannot satisfy live mode")
        if not isinstance(events, tuple) or len(events) > 1000:
            raise ValueError("Invalid recorded event collection")
        detached = tuple(
            RecordedEvent.model_validate(event.model_dump(mode="json", warnings=False))
            for event in events
        )
        start = alert.event_time - timedelta(minutes=5)
        end = alert.event_time + timedelta(minutes=5)
        context = tuple(
            event for event in detached
            if event.endpoint == alert.endpoint
            and event.scenario_id == alert.scenario_id
            and start <= event.observed_at <= end
        )
        anchor = tuple(event for event in context if event.observed_at == alert.event_time)
        if kind == "process":
            return _process(anchor, context)
        if kind == "persistence":
            return _persistence(anchor)
        return _containment(anchor, alert)
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise ValueError("Invalid recorded assessment contract") from None
