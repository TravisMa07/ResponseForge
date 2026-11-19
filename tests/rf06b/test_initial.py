"""Frozen behavior missing at the importable pre-implementation scaffold."""

from responseforge.playbooks.recorded import recorded_signal
from responseforge.replay.selection import select_recorded
from responseforge.replay.windows import normalize_windows
from tests.rf06b.helpers import CHANNEL, artifact, batch, recorded, xml_event


def test_windows_access_is_not_fabricated_creation():
    raw = xml_event(
        10,
        fields={
            "SourceImage": "mimikatz.exe",
            "TargetImage": "lsass.exe",
            "GrantedAccess": "0x1010",
        },
    ).encode()
    value = normalize_windows(raw, artifact=artifact(raw), scenario_id="original").events[0]
    assert value.event_id == CHANNEL + ":31"
    assert value.fields["event_kind"] == "process_access"
    assert value.fields["source_image"] == "mimikatz.exe"
    assert "image" not in value.fields and "process_guid" not in value.fields


def test_recorded_powershell_exact_alias_signal():
    assert recorded_signal(recorded()) == "powershell"


def test_selection_preserves_original_event_and_source_integrity():
    original = batch([recorded(record_id="31"), recorded(record_id="32")])
    selected = select_recorded(original, event_ids=(original.events[1].event_id,))
    assert selected.events == (original.events[1],)
    assert (
        selected.sha256 == original.sha256
        and selected.origin.source_ref == original.origin.source_ref
    )
    assert selected.source_id != original.source_id
    assert selected.origin.selected_event_ids == (original.events[1].event_id,)
