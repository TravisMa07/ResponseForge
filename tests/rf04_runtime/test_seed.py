"""Private volume reseeding must survive immutable files from an earlier run."""

import stat

import pytest

from responseforge.integrations.shuffle.operations import _seed_files


def test_reseed_atomically_replaces_previous_readonly_files(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    for name in ("callback.json", "ca.pem"):
        (source / name).write_text("first-" + name)
    _seed_files(target, source)
    for name in ("callback.json", "ca.pem"):
        assert stat.S_IMODE((target / name).stat().st_mode) == 0o444
        (source / name).write_text("second-" + name)
    _seed_files(target, source)
    for name in ("callback.json", "ca.pem"):
        assert (target / name).read_text() == "second-" + name
        assert stat.S_IMODE((target / name).stat().st_mode) == 0o444
    assert set(path.name for path in target.iterdir()) == {"callback.json", "ca.pem"}


def test_seed_refuses_symlink_destination(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    marker = tmp_path / "unrelated"
    marker.write_text("preserve")
    (source / "callback.json").write_text("new-config")
    (source / "ca.pem").write_text("new-ca")
    (target / "callback.json").symlink_to(marker)
    with pytest.raises(ValueError):
        _seed_files(target, source)
    assert marker.read_text() == "preserve"
