"""Narrow observation policies derive only from the frozen recorded fields."""

from datetime import timedelta

import pytest

from responseforge.playbooks.assessment import assess
from responseforge.playbooks.recorded import assess_recorded, recorded_signal
from responseforge.replay import make_alerts
from tests.rf06b.helpers import GUID, NOW, OTHER_GUID, alert, batch, recorded


def change(event, **fields):
    return event.model_copy(update={"fields": event.fields | fields})


@pytest.mark.parametrize(
    "kind,signal",
    [
        ("process_create", "powershell"),
        ("process_access", "lsass_access"),
        ("task_create", "task_creation"),
        ("file_create", "ransom_note"),
        ("dns_query", "process_dns"),
    ],
)
def test_five_explicit_observations_match_without_technique_labels(kind, signal):
    event = recorded(kind, scenario="unlabeled-original")
    assert recorded_signal(event) == signal


@pytest.mark.parametrize(
    "command",
    [
        "powershell.exe -WindowStyle Hidden -EncodedCommand INERT",
        "PoWeRsHeLl.ExE -NoP -NoNI -NoLogo -WindowStyle hIdDeN -enc INERT",
        '"C:\\Windows\\powershell.exe" -WindowStyle Hidden -ep bypass -enc "INERT"',
        "powershell.exe -enc INERT -executionpolicy Bypass -WindowStyle Hidden",
    ],
)
def test_exact_supported_powershell_aliases_and_quoting_are_inert(command):
    assert recorded_signal(change(recorded(), command_line=command)) == "powershell"


@pytest.mark.parametrize(
    "command",
    [
        "powershell.exe -WindowStyle Hidden -encoding INERT",
        "powershell.exe -WindowStyle Hidden -encfoo INERT",
        "powershell.exe -WindowStyle Hidden -enc",
        "powershell.exe -WindowStyle Hidden -enc -NoProfile",
        'powershell.exe -WindowStyle Hidden -enc ""',
        "powershell.exe -WindowStyle Hidden -enc INERT -Unexpected",
        'powershell.exe -Command Write-Output "-WindowStyle Hidden -enc INERT"',
        'powershell.exe -c "-WindowStyle Hidden -enc INERT"',
        "powershell.exe -File original.ps1 -WindowStyle Hidden -enc INERT",
        "powershell.exe -- -WindowStyle Hidden -enc INERT",
        "powershell.exe original.ps1 -WindowStyle Hidden -enc INERT",
        "cmd.exe -WindowStyle Hidden -enc INERT",
        'powershell.exe -WindowStyle Hidden -enc "unterminated',
        "powershell.exe -WindowStyle Hidden",
        "powershell.exe -enc INERT",
        "powershell.exe -WindowStyle Visible -enc INERT",
    ],
)
def test_text_substrings_missing_operands_unknown_options_and_script_arguments_do_not_match(
    command,
):
    assert recorded_signal(change(recorded(), command_line=command)) is None


@pytest.mark.parametrize(
    "image",
    ["cmd.exe", "firefox.exe", "powershell.exe.other", " powershell.exe", "powershell.exe "],
)
def test_image_basename_is_exact_without_trimming(image):
    assert recorded_signal(change(recorded(), image=image)) is None


@pytest.mark.parametrize(
    "source,access,expected",
    [
        ("mimikatz.exe", "0x1010", "lsass_access"),
        ("xordump.exe", "0x1fffff", "lsass_access"),
        ("xordump.exe", "0x1f3fff", "lsass_access"),
        ("svchost.exe", "0x1400", None),
        ("mimikatz.exe", "0x1000", None),
        ("mimikatz.exe", "0x1010garbage", None),
        ("mimikatz.exe", "PRIVATE", None),
    ],
)
def test_access_tool_and_hex_vm_read_mask_are_narrow(source, access, expected):
    assert (
        recorded_signal(
            change(recorded("process_access"), source_image=source, granted_access=access)
        )
        == expected
    )


def test_access_observation_does_not_authorize_lsass_target_or_source_termination():
    event = recorded("process_access")
    result = assess_recorded("process", (event,), alert(event))
    assert result.disposition == "escalate" and result.action is None and result.resource is None
    assert result.event_ids == (event.event_id,)
    gaps = " ".join(result.known_gaps).casefold()
    assert "creat" in gaps and "lineage" in gaps and ("memory" in gaps or "content" in gaps)


def test_task_configuration_always_escalates_without_execution_or_disable_effect():
    event = recorded("task_create")
    result = assess_recorded("persistence", (event,), alert(event))
    assert result.disposition == "escalate" and result.action is None
    assert result.event_ids == (event.event_id,)
    assert "execut" in " ".join(result.known_gaps).casefold()


def test_missing_task_name_actor_adds_explicit_gaps_without_inference():
    event = recorded("task_create", fields={"configured_command": "powershell.exe"})
    result = assess_recorded("persistence", (event,), alert(event))
    assert result.disposition == "escalate" and result.action is None
    gaps = " ".join(result.known_gaps).casefold()
    assert "task" in gaps and ("actor" in gaps or "account" in gaps)


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("process_access", "target_image", "not-lsass.exe"),
        ("task_create", "configured_command", "Explorer.EXE"),
        ("file_create", "target_filename", r"C:\Original\ordinary.txt"),
        ("file_create", "image", "notepad.exe"),
        ("dns_query", "image", "firefox.exe"),
        ("dns_query", "query_name", "pastebin.com.attacker.invalid"),
        ("dns_query", "query_name", " pastebin.com"),
    ],
)
def test_source_like_negative_observations_are_rule_negative_only(kind, field, value):
    assert recorded_signal(change(recorded(kind), **{field: value})) is None


def test_second_supported_dns_pair_and_case_are_exact():
    assert (
        recorded_signal(
            change(recorded("dns_query"), image="PoWeRsHeLl.ExE", query_name="CDN.DISCORDAPP.COM")
        )
        == "process_dns"
    )


@pytest.mark.parametrize(
    "kind,playbook,action,resource",
    [
        ("process_create", "process", "terminate_process", "process:42"),
        ("file_create", "containment", "isolate_host", "host:rf05-host"),
        ("dns_query", "containment", "isolate_host", "host:rf05-host"),
    ],
)
def test_unique_direct_recorded_identity_supports_only_existing_replay_action(
    kind, playbook, action, resource
):
    event = recorded(kind)
    result = assess_recorded(playbook, (event,), alert(event))
    assert (
        result.disposition == "propose" and result.action == action and result.resource == resource
    )
    assert result.event_ids == (event.event_id,)
    assert "reputation" in " ".join(result.known_gaps).casefold()
    if playbook == "containment":
        rationale = result.rationale.casefold()
        assert "connect" in rationale and ("rollback" in rationale or "unisolate" in rationale)
        gaps = " ".join(result.known_gaps).casefold()
        assert "creat" in gaps or "lineage" in gaps
        assert (
            ("encrypt" in gaps)
            if kind == "file_create"
            else ("session" in gaps or "download" in gaps)
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("process_id", "0"),
        ("process_id", "042"),
        ("process_id", "2147483648"),
        ("process_id", " 42"),
        ("process_guid", "not-a-guid"),
        ("process_guid", "00000000-0000-0000-0000-000000000000"),
        ("process_guid", "11111111111141118111111111111111"),
        ("process_guid", " " + GUID),
    ],
)
@pytest.mark.parametrize(
    "kind,playbook",
    [("process_create", "process"), ("file_create", "containment"), ("dns_query", "containment")],
)
def test_invalid_direct_target_identity_never_authorizes_action(kind, playbook, field, value):
    event = change(recorded(kind), **{field: value})
    result = assess_recorded(playbook, (event,), alert(event))
    assert result.disposition == "escalate" and result.action is None and result.resource is None


@pytest.mark.parametrize(
    "kind,playbook",
    [("process_create", "process"), ("file_create", "containment"), ("dns_query", "containment")],
)
def test_distinct_direct_anchor_identities_are_ambiguous(kind, playbook):
    first = recorded(kind)
    second = change(recorded(kind, record_id="32"), process_guid=OTHER_GUID, process_id="43")
    result = assess_recorded(playbook, (first, second), alert(first))
    assert result.disposition == "escalate" and result.action is None
    assert set(result.event_ids) == {first.event_id, second.event_id}


def test_equivalent_guid_spelling_is_not_second_identity():
    first = recorded()
    second = change(recorded(record_id="32"), process_guid="{" + GUID.upper() + "}")
    result = assess_recorded("process", (first, second), alert(first))
    assert result.disposition == "propose" and result.resource == "process:42"


@pytest.mark.parametrize(
    "kind,wrong",
    [
        ("process_create", "containment"),
        ("task_create", "process"),
        ("file_create", "persistence"),
        ("dns_query", "process"),
    ],
)
def test_playbook_kind_confines_recorded_recommendations(kind, wrong):
    event = recorded(kind)
    result = assess_recorded(wrong, (event,), alert(event))
    assert result.disposition == "no_action" and result.action is None


def test_non_anchor_indicator_does_not_change_current_case_decision():
    first = recorded(fields={"image": "cmd.exe", "command_line": "cmd.exe"})
    later = recorded(record_id="32", observed_at=NOW + timedelta(seconds=1))
    result = assess_recorded("process", (first, later), alert(first))
    assert result.disposition == "no_action" and result.action is None


def test_primary_assessment_retains_source_binding_and_scopes_late_distinct_candidate():
    first = recorded()
    outside = change(
        recorded(record_id="32", observed_at=NOW + timedelta(minutes=6)),
        process_guid=OTHER_GUID,
        process_id="43",
    )
    source = batch([first, outside])
    value = make_alerts(source, ingested_at=NOW)[0]
    assert value.rule_id == "RF-RECORDED-POWERSHELL" and value.event_time == NOW
    result = assess("process", source, value)
    assert result.disposition == "propose" and result.event_ids == (first.event_id,)


def test_incomplete_second_positive_at_same_anchor_prevents_false_unique_target():
    first = recorded()
    second = recorded(
        record_id="32",
        fields={
            "image": "powershell.exe",
            "command_line": "powershell.exe -WindowStyle Hidden -enc INERT",
            "process_id": "43",
        },
    )
    result = assess_recorded("process", (first, second), alert(first))
    assert result.disposition == "escalate" and result.action is None


def test_future_parent_create_cannot_remove_missing_recorded_parent_gap():
    child = change(recorded(), parent_process_guid=OTHER_GUID)
    future_parent = change(
        recorded(record_id="32", observed_at=NOW + timedelta(seconds=1)),
        process_guid=OTHER_GUID,
        process_id="43",
        image="explorer.exe",
        command_line="explorer.exe",
    )
    result = assess_recorded("process", (child, future_parent), alert(child))
    assert result.disposition == "propose"
    assert any("parent" in gap.casefold() for gap in result.known_gaps)
