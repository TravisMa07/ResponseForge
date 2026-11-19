"""Independently authored Windows XML and recorded observations."""

from datetime import UTC, datetime
from xml.sax.saxutils import escape

from responseforge.contracts import Alert, EndpointRef, Provenance
from responseforge.replay_contracts import RecordedEvent, ReplayBatch, ReplayOrigin
from tests.rf06a.helpers import artifact as base_artifact

NOW = datetime(2025, 1, 1, 12, tzinfo=UTC)
STAMP = "2025-01-01T12:00:00.123456700Z"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
GUID = "11111111-1111-4111-8111-111111111111"
OTHER_GUID = "22222222-2222-4222-8222-222222222222"
HOST = EndpointRef(endpoint_id="rf05-host", hostname="original-synthetic-host")
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def task_xml(command="powershell.exe", arguments="Get-Process", **changes):
    return (
        '<?xml version="1.0" encoding="UTF-16"?>'
        f'<Task xmlns="{TASK_NS}"><Actions Context="original">'
        f"<Exec><Command>{escape(command)}</Command><Arguments>{escape(arguments)}</Arguments>"
        "</Exec></Actions></Task>"
    )


def xml_event(
    event_id=1,
    record_id="31",
    *,
    fields=None,
    stamp=STAMP,
    computer="original.example",
    channel=None,
    provider=None,
    namespace=True,
):
    channel = channel or ("Security" if event_id == 4698 else CHANNEL)
    provider = provider or (
        "Microsoft-Windows-Security-Auditing" if event_id == 4698 else "Microsoft-Windows-Sysmon"
    )
    ns = ' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"' if namespace else ""
    data = {} if fields is None else fields
    encoded = "".join(f'<Data Name="{escape(k)}">{escape(v)}</Data>' for k, v in data.items())
    return (
        f'<Event{ns}><System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="{stamp}"/><EventRecordID>{record_id}</EventRecordID>'
        f"<Channel>{channel}</Channel><Computer>{computer}</Computer></System>"
        f"<EventData>{encoded}</EventData></Event>"
    )


def artifact(raw, **changes):
    return base_artifact(raw, format="windows-event-xml", **changes)


def recorded(
    kind="process_create",
    *,
    record_id="31",
    fields=None,
    observed_at=NOW,
    endpoint=HOST,
    scenario="original-scenario",
):
    category, event_id, defaults = {
        "process_create": (
            "process",
            "1",
            {
                "image": r"C:\Windows\powershell.exe",
                "process_id": "42",
                "process_guid": GUID,
                "command_line": "powershell.exe -WindowStyle Hidden -ep bypass -enc INERT",
            },
        ),
        "process_access": (
            "process",
            "10",
            {
                "source_image": "mimikatz.exe",
                "source_process_id": "42",
                "source_process_guid": GUID,
                "target_image": r"C:\Windows\System32\lsass.exe",
                "target_process_id": "500",
                "target_process_guid": OTHER_GUID,
                "granted_access": "0x1010",
            },
        ),
        "task_create": (
            "persistence",
            "4698",
            {
                "task_name": "\\OriginalTask",
                "account": "original-user",
                "account_domain": "ORIGINAL",
                "configured_command": "powershell.exe",
                "configured_arguments": "Get-Process",
            },
        ),
        "file_create": (
            "file",
            "11",
            {
                "image": "powershell.exe",
                "process_id": "42",
                "process_guid": GUID,
                "target_filename": r"C:\Users\Original\Downloads\GetYouFiles.txt",
            },
        ),
        "dns_query": (
            "network",
            "22",
            {
                "image": "wscript.exe",
                "process_id": "42",
                "process_guid": GUID,
                "query_name": "pastebin.com",
                "query_status": "0",
                "query_results": "original result",
            },
        ),
    }[kind]
    channel = "Security" if kind == "task_create" else CHANNEL
    return RecordedEvent(
        event_id=f"{channel}:{record_id}",
        scenario_id=scenario,
        endpoint=endpoint,
        observed_at=observed_at,
        artifact=category,
        fields={
            "event_kind": kind,
            "windows_event_id": event_id,
            "original_record_id": record_id,
            "channel": channel,
        }
        | (defaults if fields is None else fields),
    )


def batch(events):
    raw = xml_event().encode()
    entry = artifact(raw)
    return ReplayBatch(
        source_id=entry.artifact_id,
        sha256=entry.sha256,
        origin=ReplayOrigin(source_ref=entry.source_url, transformation="windows-events-v1"),
        events=tuple(events),
        quarantine=(),
        duplicates=0,
    )


def alert(event, *, mode="replay"):
    return Alert(
        alert_id="original-alert",
        mode=mode,
        source="splunk-attack-data",
        scenario_id=event.scenario_id,
        endpoint=event.endpoint,
        event_time=event.observed_at,
        ingested_at=NOW,
        rule_id="RF-ORIGINAL",
        severity="high",
        provenance=Provenance(
            source="splunk-attack-data",
            source_ref="original:source",
            sha256="a" * 64,
            original_event_ids=(event.fields["original_record_id"],),
        ),
    )
