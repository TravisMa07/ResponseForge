"""Bounded recorded Windows projections; event meanings never imply missing effects."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from xml.etree.ElementTree import Element, ParseError, fromstring

from pydantic import TypeAdapter

from responseforge.contracts import EndpointRef, Id, UtcDateTime
from responseforge.dataset_contracts import DatasetArtifact
from responseforge.replay import ReplayError
from responseforge.replay.sysmon import (
    _MAPPING,
    _NAMESPACE,
    _TIMESTAMP,
    _UTC_TIME,
    _local,
    _parse,
    _signature,
    _text,
)
from responseforge.replay_contracts import QuarantineItem, RecordedEvent, ReplayBatch, ReplayOrigin

_SYSMON = "Microsoft-Windows-Sysmon"
_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_SECURITY = "Microsoft-Windows-Security-Auditing"
_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_DECLARATION = re.compile(
    r'''\A<\?xml\s+version=(?P<q>["'])1\.0(?P=q)'''
    r'''(?:\s+encoding=(?P<e>["'])(?i:UTF-16|UTF-8)(?P=e))?\s*\?>''',
)
_MAPPINGS: dict[str, dict[str, str]] = {
    "1": _MAPPING,
    "10": {
        "SourceImage": "source_image",
        "SourceProcessId": "source_process_id",
        "SourceProcessGUID": "source_process_guid",
        "TargetImage": "target_image",
        "TargetProcessId": "target_process_id",
        "TargetProcessGUID": "target_process_guid",
        "GrantedAccess": "granted_access",
        "SourceUser": "source_account",
        "TargetUser": "target_account",
    },
    "11": {
        "Image": "image", "ProcessId": "process_id", "ProcessGuid": "process_guid",
        "TargetFilename": "target_filename", "User": "account",
        "CreationUtcTime": "creation_utc_time",
    },
    "22": {
        "Image": "image", "ProcessId": "process_id", "ProcessGuid": "process_guid",
        "QueryName": "query_name", "QueryStatus": "query_status", "QueryResults": "query_results",
        "User": "account",
    },
    "4698": {
        "TaskName": "task_name", "SubjectUserName": "account",
        "SubjectDomainName": "account_domain", "SubjectUserSid": "account_sid",
        "SubjectLogonId": "actor_logon_id",
    },
}
_KINDS = {
    "1": ("process", "process_create"),
    "10": ("process", "process_access"),
    "11": ("file", "file_create"),
    "22": ("network", "dns_query"),
    "4698": ("persistence", "task_create"),
}


def _utc_time(value: str) -> None:
    """UTC-named Sysmon fields may be explicitly unzoned; SystemTime may not."""
    if _UTC_TIME.fullmatch(value) is not None:
        datetime.fromisoformat(value).replace(tzinfo=UTC)
    elif _TIMESTAMP.fullmatch(value) is not None:
        TypeAdapter(UtcDateTime).validate_python(value)
    else:
        raise ValueError("Invalid recorded UTC time")


def _structure(element: Element) -> tuple[str, dict[str, Element], dict[str, str]]:
    namespace = "{" + _NAMESPACE + "}" if element.tag.startswith("{") else ""
    if element.tag != namespace + "Event":
        raise ValueError("Invalid event namespace")
    if any(node.tag != namespace + _local(node.tag) for node in element.iter()):
        raise ValueError("Invalid event namespace")
    if [child.tag for child in element] != [namespace + "System", namespace + "EventData"]:
        raise ValueError("Invalid event structure")
    system, event_data = list(element)
    for container in (element, system, event_data):
        if container.text and container.text.strip():
            raise ValueError("Mixed structural text")
        if any(child.tail and child.tail.strip() for child in container):
            raise ValueError("Mixed structural text")
    system_fields: dict[str, Element] = {}
    for child in system:
        key = _local(child.tag)
        if key in system_fields:
            raise ValueError("Ambiguous system field")
        system_fields[key] = child
    data: dict[str, str] = {}
    for child in event_data:
        if child.tag != namespace + "Data" or len(child):
            raise ValueError("Invalid event data")
        key = child.attrib["Name"]
        if not key or key in data:
            raise ValueError("Ambiguous event data")
        data[key] = child.text or ""
    return namespace, system_fields, data


def _scalar(node: Element, *, nonempty: bool) -> str:
    if len(node):
        raise ValueError("Nested task action scalar")
    value = node.text or ""
    if nonempty and not value.strip():
        raise ValueError("Missing configured command")
    return value


def _task_fields(content: str) -> dict[str, str]:
    if not content or len(content) > 4096:
        raise ValueError("Invalid task content bound")
    text = content.lstrip()
    declaration = _DECLARATION.match(text)
    if declaration is not None:
        text = text[declaration.end():]
    if "<?" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("Unsupported task declarations")
    try:
        root = fromstring(text)
    except (ParseError, ValueError, RecursionError):
        raise ValueError("Invalid task XML") from None
    namespace = "{" + _TASK_NAMESPACE + "}" if root.tag.startswith("{") else ""
    if root.tag != namespace + "Task":
        raise ValueError("Invalid task namespace or root")
    pending = [(root, 1)]
    task_count = 0
    actions: list[Element] = []
    while pending:
        node, depth = pending.pop()
        if depth > 16 or node.tag != namespace + _local(node.tag):
            raise ValueError("Invalid task depth or namespace")
        if _local(node.tag) == "Task":
            task_count += 1
        if _local(node.tag) == "Actions":
            actions.append(node)
        pending.extend((child, depth + 1) for child in node)
    if task_count != 1 or len(actions) != 1 or actions[0] not in list(root):
        raise ValueError("Ambiguous task actions")
    action = actions[0]
    if action.text and action.text.strip():
        raise ValueError("Mixed task action text")
    if len(action) != 1 or action[0].tag != namespace + "Exec":
        raise ValueError("Unsupported or ambiguous task action")
    execution = action[0]
    for container in (root, execution):
        if container.text and container.text.strip():
            raise ValueError("Mixed task structural text")
        if any(child.tail and child.tail.strip() for child in container):
            raise ValueError("Mixed task structural text")
    if execution.tail and execution.tail.strip():
        raise ValueError("Mixed task action text")
    commands = [child for child in execution if child.tag == namespace + "Command"]
    arguments = [child for child in execution if child.tag == namespace + "Arguments"]
    if len(commands) != 1 or len(arguments) > 1 or len(execution) != len(commands) + len(arguments):
        raise ValueError("Ambiguous configured task command")
    fields = {"configured_command": _scalar(commands[0], nonempty=True)}
    if arguments:
        fields["configured_arguments"] = _scalar(arguments[0], nonempty=False)
    return fields


def _event(element: Element, scenario_id: str) -> RecordedEvent:
    _, system, data = _structure(element)
    provider = system["Provider"]
    timestamp = system["TimeCreated"]
    for metadata in (provider, timestamp):
        if len(metadata) or (metadata.text and metadata.text.strip()):
            raise ValueError("Invalid system metadata")
    name = provider.attrib["Name"]
    channel = _text(system["Channel"])
    event_id = _text(system["EventID"])
    if not (
        (name == _SYSMON and channel == _CHANNEL and event_id in {"1", "10", "11", "22"})
        or (name == _SECURITY and channel == "Security" and event_id == "4698")
    ):
        raise ValueError("Unsupported provider, channel or event")
    record_id = _text(system["EventRecordID"])
    if re.fullmatch(r"[1-9][0-9]{0,19}", record_id) is None:
        raise ValueError("Invalid record identity")
    computer = _text(system["Computer"])
    if not computer:
        raise ValueError("Missing computer")
    original_time = timestamp.attrib["SystemTime"]
    if _TIMESTAMP.fullmatch(original_time) is None:
        raise ValueError("Invalid event timestamp")
    observed_at = TypeAdapter(UtcDateTime).validate_python(original_time)
    category, kind = _KINDS[event_id]
    fields = {
        "event_kind": kind,
        "windows_event_id": event_id,
        "original_record_id": record_id,
        "original_system_time": original_time,
        "channel": channel,
        "provider": name,
    }
    for source, target in _MAPPINGS[event_id].items():
        if source in data:
            fields[target] = data[source]
    if name == _SYSMON and "UtcTime" in data:
        _utc_time(data["UtcTime"])
        fields["original_utc_time"] = data["UtcTime"]
    if event_id == "11" and "CreationUtcTime" in data:
        _utc_time(data["CreationUtcTime"])
    if event_id == "4698" and "TaskContent" in data:
        fields.update(_task_fields(data["TaskContent"]))
    return RecordedEvent.model_validate({
        "event_id": channel + ":" + record_id,
        "scenario_id": scenario_id,
        "endpoint": EndpointRef(endpoint_id=computer, hostname=computer),
        "observed_at": observed_at,
        "artifact": category,
        "fields": fields,
    })


def normalize_windows(raw: bytes, *, artifact: DatasetArtifact, scenario_id: str) -> ReplayBatch:
    """Project supported event facts after binding exact retained source bytes."""
    try:
        artifact = DatasetArtifact.model_validate(artifact.model_dump(mode="json", warnings=False))
        scenario_id = TypeAdapter(Id).validate_python(scenario_id)
        if (
            artifact.format != "windows-event-xml"
            or not isinstance(raw, bytes)
            or len(raw) > 1024 * 1024
            or len(raw) != artifact.size_bytes
            or hashlib.sha256(raw).hexdigest() != artifact.sha256
        ):
            raise ReplayError("Windows source integrity mismatch")
        records, locations = _parse(raw)
        events: list[RecordedEvent] = []
        issues: list[QuarantineItem] = []
        seen: dict[tuple[str, str, str], tuple[object, ...]] = {}
        duplicates = 0
        for element in records:
            line = locations[id(element)][0]
            try:
                event = _event(element, scenario_id)
            except (ValueError, TypeError, KeyError, OverflowError):
                issues.append(QuarantineItem(line=line, code="invalid_schema"))
                continue
            identity = (scenario_id, event.endpoint.endpoint_id, event.event_id)
            signature = _signature(element)
            if identity in seen:
                if seen[identity] == signature:
                    duplicates += 1
                else:
                    issues.append(QuarantineItem(line=line, code="duplicate_conflict"))
                continue
            seen[identity] = signature
            events.append(event)
        events.sort(key=lambda event: (event.observed_at, event.endpoint.endpoint_id, event.event_id))
        return ReplayBatch(
            source_id=artifact.artifact_id, sha256=artifact.sha256,
            origin=ReplayOrigin(source_ref=artifact.source_url, transformation="windows-events-v1"),
            events=tuple(events), quarantine=tuple(issues), duplicates=duplicates,
        )
    except ReplayError:
        raise
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
        raise ReplayError("Invalid Windows normalization contract") from None
