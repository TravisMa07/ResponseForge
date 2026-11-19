"""Explicit source subsets are deterministic transformations with raw proof intact."""

import pytest

from responseforge.replay import ReplayError, make_alerts, replay_provenance
from responseforge.replay.selection import select_recorded
from responseforge.replay_contracts import QuarantineItem
from tests.rf06b.helpers import NOW, batch, recorded


def test_selection_is_order_independent_and_retains_original_records_and_source_observations():
    source = batch(
        [
            recorded(record_id="31"),
            recorded(record_id="32"),
            recorded("task_create", record_id="33"),
        ]
    )
    source = source.model_copy(
        update={"quarantine": (QuarantineItem(line=7, code="invalid_schema"),), "duplicates": 2}
    )
    ids = (source.events[2].event_id, source.events[0].event_id)
    a = select_recorded(source, event_ids=ids)
    b = select_recorded(source, event_ids=tuple(reversed(ids)))
    assert a == b
    assert a.events == (source.events[0], source.events[2])
    assert a.sha256 == source.sha256 and a.origin.source_ref == source.origin.source_ref
    assert a.origin.selected_event_ids == tuple(sorted(ids))
    assert a.quarantine == source.quarantine and a.duplicates == source.duplicates
    assert a.source_id.startswith("subset-") and a.source_id != source.source_id
    assert source.origin.selected_event_ids is None and len(source.events) == 3


@pytest.mark.parametrize(
    "ids",
    [
        (),
        ("unknown",),
        ("Security:31",),
        ("Microsoft-Windows-Sysmon/Operational:31", "Microsoft-Windows-Sysmon/Operational:31"),
        (" Microsoft-Windows-Sysmon/Operational:31",),
    ],
)
def test_empty_unknown_duplicate_or_whitespace_selection_refuses(ids):
    with pytest.raises(ReplayError):
        select_recorded(batch([recorded()]), event_ids=ids)


def test_nested_selection_and_legacy_origin_cannot_masquerade_as_original_windows_source():
    source = batch([recorded()])
    chosen = select_recorded(source, event_ids=(source.events[0].event_id,))
    with pytest.raises(ReplayError):
        select_recorded(chosen, event_ids=(source.events[0].event_id,))
    with pytest.raises(ReplayError):
        select_recorded(
            source.model_copy(update={"origin": None}), event_ids=(source.events[0].event_id,)
        )
    legacy = source.model_copy(
        update={"origin": source.origin.model_copy(update={"transformation": "sysmon-event1-v1"})}
    )
    with pytest.raises(ReplayError):
        select_recorded(legacy, event_ids=(source.events[0].event_id,))


def test_selected_source_negative_does_not_inherit_positive_or_change_original_hash():
    positive = recorded()
    negative = recorded(
        record_id="32", fields={"image": "powershell.exe", "command_line": "powershell.exe"}
    )
    source = batch([positive, negative])
    chosen = select_recorded(source, event_ids=(negative.event_id,))
    value = make_alerts(chosen, ingested_at=NOW)[0]
    assert value.rule_id == "RF-REPLAY-OBSERVATION" and value.severity == "low"
    assert value.provenance.sha256 == source.sha256
    assert value.provenance.original_event_ids == ("32",)
    assert value.alert_id != make_alerts(source, ingested_at=NOW)[0].alert_id


def test_provenance_requires_original_id_resolution_instead_of_inventing_raw_ids():
    source = batch([recorded()])
    assert replay_provenance(source, (source.events[0].event_id,)).original_event_ids == ("31",)
    with pytest.raises(ReplayError):
        replay_provenance(source, ("unknown",))


def test_selection_id_ambiguous_across_computers_refuses_without_arbitrary_pick():
    from responseforge.contracts import EndpointRef

    one = recorded()
    other = recorded(endpoint=EndpointRef(endpoint_id="other-host", hostname="other-host"))
    source = batch([one, other])
    with pytest.raises(ReplayError):
        select_recorded(source, event_ids=(one.event_id,))
