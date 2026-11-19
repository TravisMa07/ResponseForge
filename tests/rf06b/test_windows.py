"""Independent Windows projection semantics and untrusted XML boundaries."""

import hashlib
from datetime import UTC, datetime

import pytest

from responseforge.replay import ReplayError
from responseforge.replay.sysmon import normalize_sysmon
from responseforge.replay.windows import normalize_windows
from tests.rf06b.helpers import CHANNEL, GUID, STAMP, artifact, task_xml, xml_event


def normalize(text):
    raw = text.encode()
    return normalize_windows(raw, artifact=artifact(raw), scenario_id="original")


@pytest.mark.parametrize(
    "event_id,fields,category,kind,expected,absent",
    [
        (
            1,
            {
                "Image": "powershell.exe",
                "ProcessGuid": GUID,
                "ProcessId": "42",
                "ParentProcessGuid": GUID,
                "User": "source-user",
                "CommandLine": "INERT",
            },
            "process",
            "process_create",
            {
                "image": "powershell.exe",
                "process_guid": GUID,
                "process_id": "42",
                "parent_process_guid": GUID,
                "account": "source-user",
                "command_line": "INERT",
            },
            ("source_process_guid", "target_process_guid"),
        ),
        (
            10,
            {
                "SourceImage": "mimikatz.exe",
                "SourceProcessGUID": GUID,
                "SourceProcessId": "42",
                "TargetImage": "lsass.exe",
                "TargetProcessGUID": GUID,
                "TargetProcessId": "500",
                "GrantedAccess": "0x1010",
                "SourceUser": "actor",
                "TargetUser": "target",
            },
            "process",
            "process_access",
            {
                "source_image": "mimikatz.exe",
                "source_process_guid": GUID,
                "source_process_id": "42",
                "target_image": "lsass.exe",
                "target_process_guid": GUID,
                "target_process_id": "500",
                "granted_access": "0x1010",
                "source_account": "actor",
                "target_account": "target",
            },
            ("image", "process_guid", "command_line"),
        ),
        (
            11,
            {
                "Image": "powershell.exe",
                "ProcessGuid": GUID,
                "ProcessId": "42",
                "TargetFilename": "C:\\Original\\GetYouFiles.txt",
                "CreationUtcTime": "2025-01-01 11:59:59.125",
            },
            "file",
            "file_create",
            {
                "image": "powershell.exe",
                "process_guid": GUID,
                "process_id": "42",
                "target_filename": "C:\\Original\\GetYouFiles.txt",
                "creation_utc_time": "2025-01-01 11:59:59.125",
            },
            ("operation", "account", "parent_process_guid"),
        ),
        (
            22,
            {
                "Image": "wscript.exe",
                "ProcessGuid": GUID,
                "ProcessId": "42",
                "QueryName": "pastebin.com",
                "QueryStatus": "0",
                "QueryResults": "inert;result",
            },
            "network",
            "dns_query",
            {
                "image": "wscript.exe",
                "process_guid": GUID,
                "process_id": "42",
                "query_name": "pastebin.com",
                "query_status": "0",
                "query_results": "inert;result",
            },
            ("direction", "destination_ip", "destination_domain"),
        ),
        (
            4698,
            {
                "TaskName": "\\OriginalTask",
                "SubjectUserName": "creator",
                "SubjectDomainName": "DOMAIN",
                "SubjectUserSid": "original-sid",
                "SubjectLogonId": "0x31",
                "TaskContent": task_xml(),
            },
            "persistence",
            "task_create",
            {
                "task_name": "\\OriginalTask",
                "account": "creator",
                "account_domain": "DOMAIN",
                "account_sid": "original-sid",
                "actor_logon_id": "0x31",
                "configured_command": "powershell.exe",
                "configured_arguments": "Get-Process",
            },
            ("process_guid", "process_id", "image", "command_line"),
        ),
    ],
)
def test_exact_source_projection_does_not_fabricate_other_event_meaning(
    event_id, fields, category, kind, expected, absent
):
    raw = xml_event(event_id, fields=fields).encode()
    entry = artifact(raw)
    result = normalize_windows(raw, artifact=entry, scenario_id="original")
    value = result.events[0]
    channel = "Security" if event_id == 4698 else CHANNEL
    assert value.event_id == channel + ":31"
    assert value.artifact == category and value.fields["event_kind"] == kind
    assert value.fields["windows_event_id"] == str(event_id)
    assert value.fields["original_record_id"] == "31"
    assert value.fields["original_system_time"] == STAMP
    assert value.observed_at == datetime(2025, 1, 1, 12, 0, 0, 123456, tzinfo=UTC)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.origin.transformation == "windows-events-v1"
    assert result.origin.source_ref == entry.source_url
    assert result.origin.selected_event_ids is None
    for key, expected_value in expected.items():
        assert value.fields[key] == expected_value
    assert not set(absent).intersection(value.fields)
    assert not result.quarantine


def test_channel_record_identity_and_full_original_conflict_are_not_collapsed():
    a = xml_event(1, fields={"Image": "powershell.exe", "Unmapped": "original"})
    b = xml_event(4698, fields={"TaskName": "original"})
    duplicate = a
    conflict = a.replace(">original</Data>", ">changed</Data>")
    result = normalize("\n" + a + "\n" + b + "\n" + duplicate + "\n" + conflict)
    assert len(result.events) == 2 and result.duplicates == 1
    assert {e.event_id for e in result.events} == {CHANNEL + ":31", "Security:31"}
    assert [(q.line, q.code) for q in result.quarantine] == [(5, "duplicate_conflict")]
    assert all("Unmapped" not in e.fields for e in result.events)


@pytest.mark.parametrize(
    "field,value", [("UtcTime", "2024-12-31 23:00:00.001"), ("UtcTime", "2024-12-31T23:00:00.001Z")]
)
def test_distinct_operation_and_logging_times_remain_original(field, value):
    result = normalize(xml_event(22, fields={field: value}))
    assert result.events[0].fields["original_utc_time"] == value
    assert result.events[0].fields["original_system_time"] == STAMP


@pytest.mark.parametrize("event_id", [2, 3, 9, 12, 4624, 4702])
def test_unsupported_ids_quarantine_without_losing_neighbor(event_id):
    result = normalize(xml_event(event_id) + "\n" + xml_event(1, "32"))
    assert [e.fields["original_record_id"] for e in result.events] == ["32"]
    assert [(q.line, q.code) for q in result.quarantine] == [(1, "invalid_schema")]


@pytest.mark.parametrize(
    "before,after",
    [
        ("<EventID>1</EventID>", "<EventID>1</EventID><EventID>1</EventID>"),
        ("<EventRecordID>31</EventRecordID>", "<EventRecordID>0</EventRecordID>"),
        ("<EventRecordID>31</EventRecordID>", ""),
        ("<Computer>original.example</Computer>", "<Computer> original.example</Computer>"),
        ("<System>", "<System>UNEXPECTED"),
        ("<EventData>", "<EventData>UNEXPECTED"),
        ("</System>", "</System><System/>"),
        ("</EventData>", "</EventData><EventData/>"),
        (CHANNEL, "Security"),
        ('Microsoft-Windows-Sysmon"', 'Microsoft-Windows-Security-Auditing"'),
        (STAMP, "2025-01-01T12:00:00"),
        (STAMP, "2025-02-30T12:00:00Z"),
    ],
)
def test_ambiguous_or_invalid_schema_quarantines(before, after):
    result = normalize(xml_event().replace(before, after) + "\n" + xml_event(1, "32"))
    assert [e.fields["original_record_id"] for e in result.events] == ["32"]
    assert result.quarantine[0].code == "invalid_schema"


@pytest.mark.parametrize(
    "inner",
    [
        "<Task><Actions><Exec><Command>a</Command><Command>b</Command></Exec></Actions></Task>",
        "<Task><Actions><Exec><Command>a</Command></Exec><Exec><Command>b</Command></Exec></Actions></Task>",
        "<Task><Actions/><Actions/></Task>",
        "<Task><Actions><ComHandler/></Actions></Task>",
        "<Task><Actions><Exec><Command/></Exec></Actions></Task>",
        "<Task><Actions><Exec><Command>a</Command><Arguments>x</Arguments><Arguments>y</Arguments></Exec></Actions></Task>",
        '<Task xmlns="urn:foreign"><Actions><Exec><Command>a</Command></Exec></Actions></Task>',
        '<!DOCTYPE Task [<!ENTITY leak SYSTEM "file:///PRIVATE">]><Task/>',
        "<?arbitrary PRIVATE?><Task/>",
        "<Task><Actions>",
    ],
)
def test_task_inner_ambiguity_and_expansion_are_quarantined(inner):
    result = normalize(xml_event(4698, fields={"TaskContent": inner}) + "\n" + xml_event(1, "32"))
    assert [e.fields["original_record_id"] for e in result.events] == ["32"]
    assert result.quarantine[0].code == "invalid_schema"


def test_missing_task_content_actor_and_process_are_absent():
    value = normalize(xml_event(4698, fields={"TaskName": "original"})).events[0]
    assert value.fields["task_name"] == "original"
    assert not {
        "configured_command",
        "configured_arguments",
        "account",
        "process_id",
        "process_guid",
    }.intersection(value.fields)


def test_task_creator_never_inferred_from_inner_author_or_principal():
    inner = task_xml().replace(
        "<Actions", "<RegistrationInfo><Author>NOT-CREATOR</Author></RegistrationInfo><Actions"
    )
    value = normalize(xml_event(4698, fields={"TaskContent": inner})).events[0]
    assert "account" not in value.fields
    assert value.fields["configured_command"] == "powershell.exe"


@pytest.mark.parametrize("key", ["CommandLine", "Image", "TargetFilename", "QueryResults"])
def test_no_truncation_of_oversized_projected_fields(key):
    eid = {"CommandLine": 1, "Image": 1, "TargetFilename": 11, "QueryResults": 22}[key]
    result = normalize(xml_event(eid, fields={key: "X" * 4097}))
    assert not result.events and result.quarantine[0].code == "invalid_schema"


def test_legacy_adapter_and_new_adapter_formats_do_not_silently_mix():
    raw = xml_event().encode()
    with pytest.raises(ReplayError):
        normalize_sysmon(raw, artifact=artifact(raw), scenario_id="original")
    old = artifact(raw).model_copy(update={"format": "sysmon-xml"})
    with pytest.raises(ReplayError):
        normalize_windows(raw, artifact=old, scenario_id="original")


@pytest.mark.parametrize("text", ["<?arbitrary PRIVATE?>", "<!DOCTYPE Event>", "not XML PRIVATE"])
def test_structural_invalid_source_is_safe_refusal(text):
    raw = (text + xml_event()).encode()
    with pytest.raises(ReplayError) as captured:
        normalize_windows(raw, artifact=artifact(raw), scenario_id="original")
    assert "PRIVATE" not in str(captured.value)
