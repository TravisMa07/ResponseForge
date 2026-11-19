"""Requirement-derived XML parsing and provenance expectations."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from responseforge.contracts import CollectionRequest
from responseforge.investigation import ReplayEvidenceProvider
from responseforge.replay import ReplayError, make_alerts
from responseforge.replay.sysmon import normalize_sysmon
from responseforge.replay_contracts import RecordedEvent, ReplayBatch, ReplayOrigin
from tests.rf06a.helpers import CHANNEL, STAMP, artifact, event


def normalize(text):
    raw = text.encode()
    return normalize_sysmon(raw, artifact=artifact(raw), scenario_id="original-scenario")


def test_preserves_original_identity_hash_times_and_projection():
    raw = (event() + "\n").encode()
    entry = artifact(raw)
    batch = normalize_sysmon(raw, artifact=entry, scenario_id="original-scenario")
    assert batch.source_id == "original-sysmon"
    assert batch.sha256 == hashlib.sha256(raw).hexdigest()
    assert batch.origin.source == "splunk-attack-data"
    assert batch.origin.source_ref == entry.source_url
    assert batch.origin.transformation == "sysmon-event1-v1"
    assert len(batch.events) == 1 and not batch.quarantine
    value = batch.events[0]
    assert value.event_id == "31" and value.scenario_id == "original-scenario"
    assert value.endpoint.endpoint_id == value.endpoint.hostname == "original.example"
    assert value.endpoint.agent_id is None
    assert value.artifact == "process"
    assert value.observed_at == datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=UTC)
    assert value.fields["original_system_time"] == STAMP
    assert value.fields["channel"] == CHANNEL
    assert value.fields["original_record_id"] == "31"
    assert value.fields["sysmon_event_id"] == "1"
    assert value.fields["provider"] == "Microsoft-Windows-Sysmon"
    assert value.fields["process_id"] == "42"
    assert value.fields["image"] == r"C:\Windows\powershell.exe"
    assert value.fields["account"] == "original\\user"


@pytest.mark.parametrize("shape", ["plain", "wrapped", "unqualified"])
def test_frozen_xml_export_shapes(shape):
    text = event(namespace=shape != "unqualified")
    if shape == "wrapped":
        text = "<Events>\n" + text + "\n</Events>"
    assert normalize(text).events[0].event_id == "31"


def test_sorting_duplicate_conflict_and_physical_source_lines():
    first = event("31")
    later = event("32", stamp="2026-01-01T12:00:01Z", fields={"Image": "cmd.exe"})
    conflicting = event("31", fields={"Image": "conflicting.exe"})
    batch = normalize("\n" + later + "\n" + first + "\n" + first + "\n" + conflicting)
    assert [x.event_id for x in batch.events] == ["31", "32"]
    assert batch.duplicates == 1
    assert [(x.line, x.code) for x in batch.quarantine] == [(5, "duplicate_conflict")]
    assert batch.events[0].fields["image"] == r"C:\Windows\powershell.exe"


@pytest.mark.parametrize(
    "before,after",
    [
        ("<EventRecordID>31</EventRecordID>", ""),
        ("<EventRecordID>31</EventRecordID>", "<EventRecordID>0</EventRecordID>"),
        ("<EventRecordID>31</EventRecordID>", "<EventRecordID>-3</EventRecordID>"),
        ("<Computer>original.example</Computer>", "<Computer></Computer>"),
        ("<Computer>original.example</Computer>", "<Computer> original.example</Computer>"),
        (CHANNEL, "Security"),
        ('Microsoft-Windows-Sysmon"', 'Other-Provider"'),
        ("<EventID>1</EventID>", "<EventID>3</EventID>"),
        ("<EventID>1</EventID>", "<EventID>10</EventID>"),
        (STAMP, "2026-01-01T12:00:00"),
        (STAMP, "2026-02-30T12:00:00Z"),
        ("<EventID>1</EventID>", "<EventID>1</EventID><EventID>1</EventID>"),
        ("<EventData>", '<EventData><Data Name="Image">duplicate.exe</Data>'),
        ("</System>", "</System><System/>"),
        ("</EventData>", "</EventData><EventData/>"),
    ],
)
def test_invalid_or_ambiguous_event_is_quarantined_without_losing_neighbor(before, after):
    bad = event().replace(before, after)
    batch = normalize(bad + "\n" + event("32"))
    assert [x.event_id for x in batch.events] == ["32"]
    assert [(x.line, x.code) for x in batch.quarantine] == [(1, "invalid_schema")]


@pytest.mark.parametrize(
    "text",
    [
        "<!DOCTYPE Event [<!ENTITY leak SYSTEM 'file:///private/SECRET'>]>" + event(),
        "<!ENTITY leak 'SECRET'>" + event(),
        "<?arbitrary SECRET?>" + event(),
        event()[:-4],
        "not XML SECRET",
    ],
)
def test_structural_or_expanding_xml_refuses_safely(text):
    with pytest.raises(ReplayError) as captured:
        normalize(text)
    assert "SECRET" not in str(captured.value)


def test_foreign_namespace_is_never_supported_evidence():
    text = event().replace("http://schemas.microsoft.com/win/2004/08/events/event", "urn:foreign")
    try:
        batch = normalize(text)
    except ReplayError:
        return
    assert not batch.events and batch.quarantine


def test_invalid_utf8_and_integrity_mismatch_refuse_before_parsing():
    raw = event().encode()
    with pytest.raises(ReplayError):
        normalize_sysmon(raw + b" ", artifact=artifact(raw), scenario_id="original")
    invalid = b"\xff"
    with pytest.raises(ReplayError):
        normalize_sysmon(invalid, artifact=artifact(invalid), scenario_id="original")


def test_missing_target_fields_are_absent_and_commands_remain_inert(tmp_path):
    command = "powershell.exe $(touch NEVER) <script>SECRET</script> & echo test"
    batch = normalize(event(fields={"CommandLine": command}))
    assert batch.events[0].fields["command_line"] == command
    assert "process_id" not in batch.events[0].fields
    assert "process_guid" not in batch.events[0].fields
    assert "parent_process_guid" not in batch.events[0].fields
    assert not list(tmp_path.iterdir())


def test_oversize_mapped_value_quarantines_without_truncation():
    batch = normalize(event(fields={"CommandLine": "X" * 4097}) + "\n" + event("32"))
    assert [x.event_id for x in batch.events] == ["32"]
    assert [(x.line, x.code) for x in batch.quarantine] == [(1, "invalid_schema")]


def test_source_bounds_are_refusals_not_silent_truncation():
    text = "\n".join(event(str(index + 1), fields={}) for index in range(1001))
    with pytest.raises(ReplayError):
        normalize(text)
    with pytest.raises(ReplayError):
        normalize(event(fields={"CommandLine": "X" * (16 * 1024)}))


def test_recorded_provenance_survives_alerts_and_evidence_with_exact_scope():
    raw = event().encode()
    entry = artifact(raw)
    batch = ReplayBatch(
        source_id=entry.artifact_id,
        sha256=entry.sha256,
        events=(
            RecordedEvent(
                event_id="31",
                scenario_id="original-scenario",
                endpoint={"endpoint_id": "original.example", "hostname": "original.example"},
                observed_at=STAMP,
                artifact="process",
                fields={"image": "cmd.exe"},
            ),
        ),
        quarantine=(),
        duplicates=0,
        origin=ReplayOrigin(source_ref=entry.source_url),
    )
    now = datetime(2026, 1, 2, tzinfo=UTC)
    alerts = make_alerts(batch, ingested_at=now)
    assert alerts[0].source == "splunk-attack-data"
    assert alerts[0].provenance.source == "splunk-attack-data"
    assert alerts[0].provenance.source_ref == batch.origin.source_ref
    assert alerts[0].provenance.sha256 == batch.sha256
    assert alerts[0].provenance.original_event_ids == ("31",)
    assert alerts[0].ingested_at == now
    request = CollectionRequest(
        incident_id="original-case",
        mode="replay",
        scenario_id="original-scenario",
        endpoint=batch.events[0].endpoint,
        artifact="process",
        start=batch.events[0].observed_at,
        end=batch.events[0].observed_at + timedelta(seconds=1),
    )
    result = asyncio.run(ReplayEvidenceProvider(batch, clock=lambda: now).collect(request))
    assert result.evidence[0].provenance == alerts[0].provenance
    assert result.evidence[0].observed_at == batch.events[0].observed_at
    assert result.evidence[0].collected_at == now
    with pytest.raises(ReplayError):
        asyncio.run(
            ReplayEvidenceProvider(batch).collect(request.model_copy(update={"mode": "live"}))
        )


def test_unmapped_source_conflict_is_not_hidden_by_projection():
    first = event(fields={"Image": "cmd.exe", "IntegrityLevel": "Medium"})
    conflict = event(fields={"Image": "cmd.exe", "IntegrityLevel": "High"})
    batch = normalize(first + "\n" + conflict)
    assert len(batch.events) == 1
    assert batch.duplicates == 0
    assert [(x.line, x.code) for x in batch.quarantine] == [(2, "duplicate_conflict")]
    assert "IntegrityLevel" not in batch.events[0].fields


def test_different_host_record_identity_remains_separate():
    batch = normalize(event(computer="first.example") + "\n" + event(computer="second.example"))
    assert len(batch.events) == 2 and batch.duplicates == 0 and not batch.quarantine
    assert {x.endpoint.endpoint_id for x in batch.events} == {"first.example", "second.example"}


def test_original_utc_time_differs_legitimately_from_system_logging_time():
    batch = normalize(event())
    assert batch.events[0].fields["original_utc_time"] == "2026-01-01 12:00:00.120"
    assert batch.events[0].fields["original_system_time"] == STAMP


def test_copied_invalid_artifact_cannot_bypass_revalidation():
    raw = event().encode()
    entry = artifact(raw).model_copy(update={"size_bytes": True})
    with pytest.raises(ReplayError):
        normalize_sysmon(raw, artifact=entry, scenario_id="original")
