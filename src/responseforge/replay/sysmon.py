"""Bounded Sysmon Event 1 projection; original source bytes remain authoritative."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers.expat import ExpatError, ParserCreate

from pydantic import TypeAdapter

from responseforge.contracts import EndpointRef, Id, UtcDateTime
from responseforge.dataset_contracts import DatasetArtifact
from responseforge.replay import ReplayError
from responseforge.replay_contracts import QuarantineItem, RecordedEvent, ReplayBatch, ReplayOrigin

_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_MAPPING = {
    "Image": "image",
    "CommandLine": "command_line",
    "ProcessId": "process_id",
    "ProcessGuid": "process_guid",
    "ParentProcessId": "parent_process_id",
    "ParentProcessGuid": "parent_process_guid",
    "ParentImage": "parent_image",
    "ParentCommandLine": "parent_command_line",
    "User": "account",
    "Hashes": "hashes",
}
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?")


def _name(value: str) -> str:
    return "{" + value if "}" in value else value


def _local(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _parse(raw: bytes) -> tuple[list[Element], dict[int, tuple[int, int]]]:
    """Parse one bounded envelope, collecting physical event starts and sizes."""
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper() or b"<?" in raw:
        raise ReplayError("Unsupported XML declarations")
    try:
        raw.decode("utf-8")
    except UnicodeError:
        raise ReplayError("XML source must be UTF-8") from None
    wrapped = b"<RFRoot>\n" + raw + b"\n</RFRoot>"
    parser = ParserCreate(encoding="utf-8", namespace_separator="}")
    builder = TreeBuilder()
    depth = 0
    count = 0
    starts: dict[int, tuple[int, int]] = {}
    locations: dict[int, tuple[int, int]] = {}
    stack: list[Element] = []

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal depth, count
        depth += 1
        if depth > 16:
            raise ReplayError("XML source exceeds depth limit")
        element = builder.start(_name(name), {_name(k): v for k, v in attributes.items()})
        stack.append(element)
        if _local(element.tag) == "Event":
            count += 1
            if count > 1000:
                raise ReplayError("XML source exceeds record limit")
            starts[id(element)] = (parser.CurrentLineNumber - 1, parser.CurrentByteIndex)

    def end(name: str) -> None:
        nonlocal depth
        element = stack.pop()
        builder.end(_name(name))
        if id(element) in starts:
            line, offset = starts[id(element)]
            close = wrapped.find(b">", parser.CurrentByteIndex)
            size = (close + 1 if close >= 0 else len(wrapped)) - offset
            if size > 16 * 1024:
                raise ReplayError("XML event exceeds byte limit")
            locations[id(element)] = (line, size)
        depth -= 1

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(wrapped, True)
        root = builder.close()
    except (ExpatError, ValueError, RecursionError):
        raise ReplayError("Invalid XML source structure") from None
    if root.text and root.text.strip():
        raise ReplayError("Invalid XML source structure")
    children = list(root)
    if any(child.tail and child.tail.strip() for child in children):
        raise ReplayError("Invalid XML source structure")
    if len(children) == 1 and _local(children[0].tag) == "Events":
        envelope = children[0]
        if envelope.tag not in {"Events", "{" + _NAMESPACE + "}Events"}:
            raise ReplayError("Invalid XML source namespace")
        if envelope.text and envelope.text.strip():
            raise ReplayError("Invalid XML source structure")
        children = list(envelope)
    if any(_local(child.tag) != "Event" for child in children):
        raise ReplayError("Invalid XML source structure")
    if any(child.tail and child.tail.strip() for child in children):
        raise ReplayError("Invalid XML source structure")
    return children, locations


def _text(element: Element) -> str:
    if len(element) or element.text is None or element.text != element.text.strip():
        raise ValueError("Invalid scalar")
    return element.text


def _event(element: Element, scenario_id: str) -> RecordedEvent:
    namespace = "{" + _NAMESPACE + "}" if element.tag.startswith("{") else ""
    if element.tag != namespace + "Event":
        raise ValueError("Invalid event namespace")
    for node in element.iter():
        if node.tag != namespace + _local(node.tag):
            raise ValueError("Invalid event namespace")
    if [child.tag for child in element] != [namespace + "System", namespace + "EventData"]:
        raise ValueError("Invalid event schema")
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
    provider = system_fields["Provider"]
    timestamp = system_fields["TimeCreated"]
    if (
        len(provider) or len(timestamp)
        or (provider.text and provider.text.strip())
        or (timestamp.text and timestamp.text.strip())
    ):
        raise ValueError("Invalid system metadata")
    if provider.attrib.get("Name") != "Microsoft-Windows-Sysmon":
        raise ValueError("Unsupported provider")
    if _text(system_fields["EventID"]) != "1":
        raise ValueError("Unsupported event")
    record_id = _text(system_fields["EventRecordID"])
    if re.fullmatch(r"[1-9][0-9]{0,19}", record_id) is None:
        raise ValueError("Invalid record identity")
    channel = _text(system_fields["Channel"])
    if channel != _CHANNEL:
        raise ValueError("Unsupported channel")
    computer = _text(system_fields["Computer"])
    if not computer:
        raise ValueError("Missing computer")
    original_time = timestamp.attrib["SystemTime"]
    if _TIMESTAMP.fullmatch(original_time) is None:
        raise ValueError("Invalid event timestamp")
    observed_at = TypeAdapter(UtcDateTime).validate_python(original_time)
    fields = {
        "sysmon_event_id": "1",
        "original_record_id": record_id,
        "original_system_time": original_time,
        "channel": channel,
        "provider": "Microsoft-Windows-Sysmon",
    }
    data: dict[str, str] = {}
    for child in event_data:
        if child.tag != namespace + "Data" or len(child):
            raise ValueError("Invalid event data")
        key = child.attrib["Name"]
        if not key or key in data:
            raise ValueError("Ambiguous event data")
        data[key] = child.text or ""
    for key, target in _MAPPING.items():
        if key in data:
            fields[target] = data[key]
    if "UtcTime" in data:
        original_utc = data["UtcTime"]
        if _UTC_TIME.fullmatch(original_utc) is not None:
            datetime.fromisoformat(original_utc).replace(tzinfo=UTC)
        elif _TIMESTAMP.fullmatch(original_utc) is not None:
            TypeAdapter(UtcDateTime).validate_python(original_utc)
        else:
            raise ValueError("Invalid process timestamp")
        fields["original_utc_time"] = original_utc
    return RecordedEvent(
        event_id=record_id,
        scenario_id=scenario_id,
        endpoint=EndpointRef(endpoint_id=computer, hostname=computer),
        observed_at=observed_at,
        artifact="process",
        fields=fields,
    )


def _signature(element: Element) -> tuple[object, ...]:
    """Bind duplicate comparison to full parsed content, including unmapped fields."""
    return (
        element.tag,
        tuple(sorted(element.attrib.items())),
        element.text if not len(element) else (element.text or "").strip(),
        element.tail if element.tail and element.tail.strip() else None,
        tuple(_signature(child) for child in element),
    )


def normalize_sysmon(raw: bytes, *, artifact: DatasetArtifact, scenario_id: str) -> ReplayBatch:
    try:
        artifact = DatasetArtifact.model_validate(artifact.model_dump(mode="json", warnings=False))
        scenario_id = TypeAdapter(Id).validate_python(scenario_id)
        if (
            artifact.format != "sysmon-xml"
            or not isinstance(raw, bytes)
            or len(raw) > 1024 * 1024
            or len(raw) != artifact.size_bytes
            or hashlib.sha256(raw).hexdigest() != artifact.sha256
        ):
            raise ReplayError("XML source integrity mismatch")
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
            source_id=artifact.artifact_id,
            sha256=artifact.sha256,
            origin=ReplayOrigin(source_ref=artifact.source_url),
            events=tuple(events),
            quarantine=tuple(issues),
            duplicates=duplicates,
        )
    except ReplayError:
        raise
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
        raise ReplayError("Invalid XML normalization contract") from None
