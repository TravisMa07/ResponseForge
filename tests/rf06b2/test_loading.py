"""Offline canonical bundle loading refuses partial or altered source authority."""

import json

import pytest

from responseforge.recorded_contracts import RecordedCase, RecordedConfig
from responseforge.replay import ReplayError
from responseforge.replay.registry import load_recorded_sources
from tests.rf06a.helpers import LICENSE
from tests.rf06b.helpers import CHANNEL, artifact, xml_event
from tests.rf06b2.helpers import canonical, config_for, write_bundle


def setup(tmp_path, **changes):
    root = tmp_path / "bundles"
    entry = write_bundle(root, **changes)
    return root, entry, config_for(root, entry)


@pytest.mark.parametrize("member", ["source.xml", "LICENSE", "manifest.json"])
def test_missing_bundle_member_is_not_success(tmp_path, member):
    root, entry, config = setup(tmp_path)
    (root / entry.artifact_id / member).unlink()
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode="replay")


@pytest.mark.parametrize("member", ["source.xml", "LICENSE", "manifest.json"])
def test_changed_bytes_preserve_original_files_and_refuse(tmp_path, member):
    root, entry, config = setup(tmp_path)
    path = root / entry.artifact_id / member
    path.write_bytes(path.read_bytes() + b" ALTERED PRIVATE")
    observed = path.read_bytes()
    with pytest.raises(ReplayError) as captured:
        load_recorded_sources(config, mode="replay")
    assert "PRIVATE" not in str(captured.value)
    assert path.read_bytes() == observed


def test_manifest_semantic_equality_is_not_exact_reviewed_manifest(tmp_path):
    root, entry, config = setup(tmp_path)
    path = root / entry.artifact_id / "manifest.json"
    path.write_text(json.dumps(entry.model_dump(mode="json")))
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode="replay")


@pytest.mark.parametrize("member", ["source.xml", "LICENSE", "manifest.json"])
def test_bundle_member_symlink_cannot_escape(tmp_path, member):
    root, entry, config = setup(tmp_path)
    path = root / entry.artifact_id / member
    external = tmp_path / "preserved-private-file"
    external.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(external)
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode="replay")
    assert external.exists() and path.is_symlink()


def test_bundle_and_ancestor_symlinks_refuse(tmp_path):
    root, entry, config = setup(tmp_path)
    link = tmp_path / "linked-root"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ReplayError):
        load_recorded_sources(config.model_copy(update={"bundle_root": str(link)}), mode="replay")
    target = root / entry.artifact_id
    relocated = tmp_path / "relocated"
    target.rename(relocated)
    target.symlink_to(relocated, target_is_directory=True)
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode="replay")
    assert relocated.is_dir()


@pytest.mark.parametrize("member", ["source.xml", "LICENSE", "manifest.json"])
def test_directory_instead_of_regular_member_refuses(tmp_path, member):
    root, entry, config = setup(tmp_path)
    path = root / entry.artifact_id / member
    path.unlink()
    path.mkdir()
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode="replay")


def test_unexpected_bundle_member_is_not_silently_ignored(tmp_path):
    root, entry, config = setup(tmp_path)
    marker = root / entry.artifact_id / "unexpected.txt"
    marker.write_text("preserve")
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode="replay")
    assert marker.read_text() == "preserve"


@pytest.mark.parametrize("mode", ["live", "unknown"])
def test_nonreplay_mode_refuses_without_mutation(tmp_path, mode):
    root, _, config = setup(tmp_path)
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    with pytest.raises(ReplayError):
        load_recorded_sources(config, mode=mode)
    after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert after == before


@pytest.mark.parametrize("selected", ["31", CHANNEL + ":999"])
def test_unknown_or_unscoped_selected_id_refuses(tmp_path, selected):
    _, _, config = setup(tmp_path)
    case = config.cases[0].model_copy(update={"event_ids": (selected,)})
    with pytest.raises(ReplayError):
        load_recorded_sources(config.model_copy(update={"cases": (case,)}), mode="replay")


def test_duplicate_case_profiles_or_scenarios_are_invalid_contracts(tmp_path):
    _, _, config = setup(tmp_path)
    first = config.cases[0]
    for second in (
        first.model_copy(update={"scenario_id": "another-scenario"}),
        first.model_copy(update={"profile": "another-profile"}),
    ):
        value = config.model_dump(mode="json")
        value["cases"] = [first.model_dump(mode="json"), second.model_dump(mode="json")]
        with pytest.raises(ValueError):
            RecordedConfig.model_validate(value)


def test_same_recorded_source_is_valid_in_distinct_case_namespaces(tmp_path):
    _, _, config = setup(tmp_path)
    first = config.cases[0]
    second = RecordedCase(
        profile="second",
        artifact=first.artifact,
        scenario_id="separate-case-scenario",
        event_ids=first.event_ids,
    )
    config = config.model_copy(update={"cases": (first, second)})
    sources = load_recorded_sources(config, mode="replay")
    assert len(sources) == 2 and sources[0].source_id == sources[1].source_id
    assert sources[0].sha256 == sources[1].sha256
    assert sources[0].events[0].scenario_id != sources[1].events[0].scenario_id


def test_selected_ambiguous_id_across_source_hosts_refuses(tmp_path):
    root = tmp_path / "bundles"
    root.mkdir()
    raw = (
        xml_event(1, computer="one.example") + "\n" + xml_event(1, computer="two.example")
    ).encode()
    entry = artifact(raw)
    bundle = root / entry.artifact_id
    bundle.mkdir()
    (bundle / "source.xml").write_bytes(raw)
    (bundle / "LICENSE").write_bytes(LICENSE)
    (bundle / "manifest.json").write_bytes(canonical(entry.model_dump(mode="json")))
    with pytest.raises(ReplayError):
        load_recorded_sources(config_for(root, entry), mode="replay")


def test_quarantined_neighbor_prevents_runtime_certification(tmp_path):
    root = tmp_path / "bundles"
    root.mkdir()
    raw = (xml_event(1) + "\n" + xml_event(3, "32")).encode()
    entry = artifact(raw)
    bundle = root / entry.artifact_id
    bundle.mkdir()
    (bundle / "source.xml").write_bytes(raw)
    (bundle / "LICENSE").write_bytes(LICENSE)
    (bundle / "manifest.json").write_bytes(canonical(entry.model_dump(mode="json")))
    with pytest.raises(ReplayError):
        load_recorded_sources(config_for(root, entry), mode="replay")


def test_loading_is_data_only_with_no_implicit_fetch_or_action(tmp_path, monkeypatch):
    import httpx

    marker = tmp_path / "never-created"
    root, entry, config = setup(
        tmp_path,
        fields={
            "Image": "powershell.exe",
            "CommandLine": f"$(touch {marker}) <script>PRIVATE</script>",
        },
    )
    monkeypatch.setattr(
        httpx, "Client", lambda *args, **kwargs: pytest.fail("Startup fetched source")
    )
    sources = load_recorded_sources(config, mode="replay")
    assert sources[0].events[0].fields["command_line"].startswith("$(touch ")
    assert not marker.exists() and sources[0].sha256 == entry.sha256
    assert sorted(p.name for p in root.iterdir()) == [entry.artifact_id]
