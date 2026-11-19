"""Safe filesystem and JSON behavior, using only original local test vectors."""

import hashlib
import os
import stat

import pytest

from responseforge.integrations.wazuh.security import (
    PreparationError,
    atomic_directory,
    decode_json,
    private_directory,
    read_file,
    verify_file,
)


def private_file(path, raw=b"original synthetic bytes"):
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def test_regular_bounded_read_and_exact_private_mode(tmp_path):
    path = private_file(tmp_path.resolve() / "source")
    assert read_file(path, 24, private=True) == b"original synthetic bytes"
    path.chmod(0o400)
    assert read_file(path, 24, private=True) == b"original synthetic bytes"
    with pytest.raises(PreparationError):
        read_file(path, 23, private=True)


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o660, 0o666])
def test_private_inputs_refuse_group_or_world_access(tmp_path, mode):
    path = private_file(tmp_path.resolve() / "private")
    path.chmod(mode)
    with pytest.raises(PreparationError):
        read_file(path, 64, private=True)


def test_nonprivate_material_can_be_readable_but_never_group_writable(tmp_path):
    path = private_file(tmp_path.resolve() / "ca", b"public test material")
    path.chmod(0o644)
    assert read_file(path, 64) == b"public test material"
    path.chmod(0o664)
    with pytest.raises(PreparationError):
        read_file(path, 64)


def test_wrong_owner_symlink_hardlink_and_ancestor_link_reject(tmp_path):
    root = tmp_path.resolve()
    path = private_file(root / "source")
    with pytest.raises(PreparationError):
        read_file(path, 64, owner=os.geteuid() + 1)
    alias = root / "alias"
    alias.symlink_to(path)
    with pytest.raises(PreparationError):
        read_file(alias, 64)
    hard = root / "hard"
    os.link(path, hard)
    with pytest.raises(PreparationError):
        read_file(path, 64)
    hard.unlink()
    directory = root / "actual"
    directory.mkdir()
    nested = private_file(directory / "nested")
    linked = root / "linked"
    linked.symlink_to(directory, target_is_directory=True)
    with pytest.raises(PreparationError):
        read_file(linked / nested.name, 64)


def test_directory_and_fifo_refuse_without_waiting_for_input(tmp_path):
    root = tmp_path.resolve()
    with pytest.raises(PreparationError):
        read_file(root, 64)
    fifo = root / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(PreparationError):
        read_file(fifo, 64)


def test_source_growth_during_read_is_detected(tmp_path, monkeypatch):
    import responseforge.integrations.wazuh.security as security

    path = private_file(tmp_path.resolve() / "changing", b"first")
    original = security.os.fdopen

    class ChangingRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, count):
            result = self.stream.read(count)
            with path.open("ab") as stream:
                stream.write(b"later")
            return result

    monkeypatch.setattr(
        security.os, "fdopen", lambda *args, **kwargs: ChangingRead(original(*args, **kwargs))
    )
    with pytest.raises(PreparationError):
        read_file(path, 64)


def test_private_directory_is_new_or_exact_owned_private_directory(tmp_path):
    root = tmp_path.resolve() / "private"
    with pytest.raises(PreparationError):
        private_directory(root)
    assert not root.exists()
    root.mkdir(mode=0o700)
    private_directory(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    root.chmod(0o755)
    with pytest.raises(PreparationError):
        private_directory(root)


def test_atomic_preparation_publishes_complete_artifact_and_never_overwrites(tmp_path):
    output = tmp_path.resolve() / "prepared"
    with atomic_directory(output) as stage:
        assert not output.exists()
        private_file(stage / "artifact", b"complete")
    assert (output / "artifact").read_bytes() == b"complete"
    with pytest.raises(PreparationError):
        with atomic_directory(output):
            pytest.fail("existing prepared directory was overwritten")
    assert (output / "artifact").read_bytes() == b"complete"


def test_atomic_preparation_failure_does_not_publish_partial_output(tmp_path):
    output = tmp_path.resolve() / "partial"
    with pytest.raises(RuntimeError):
        with atomic_directory(output) as stage:
            private_file(stage / "partial", b"private")
            raise RuntimeError("original injected prepublication failure")
    assert not output.exists()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"key":1,"key":2}',
        b'{"nested":{"a":1,"a":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"{} trailing",
        b"[" * 1000 + b"0" + b"]" * 1000,
    ],
)
def test_ambiguous_nonfinite_invalid_or_unbounded_json_never_escapes_safe_error(raw):
    with pytest.raises(PreparationError):
        decode_json(raw)


def test_valid_json_and_explicit_size_bound():
    assert decode_json(b'{"original":[1,"text",true,null]}') == {
        "original": [1, "text", True, None]
    }
    with pytest.raises(PreparationError):
        decode_json(b'{"secret":"not echoed"}', limit=4)


def test_generic_integrity_vector_does_not_claim_real_msi_verification(tmp_path):
    raw = b"ORIGINAL SYNTHETIC INTEGRITY VECTOR; NOT AN MSI"
    path = private_file(tmp_path.resolve() / "synthetic.bin", raw)
    expected = hashlib.sha512(raw).hexdigest()
    assert verify_file(path, expected) == raw
    with pytest.raises(PreparationError):
        verify_file(path, "0" * 128)
    path.write_bytes(raw + b"changed")
    with pytest.raises(PreparationError):
        verify_file(path, expected)


def test_private_leaf_under_replaceable_nonsticky_public_ancestor_is_not_trusted(tmp_path):
    public = tmp_path.resolve() / "replaceable"
    public.mkdir(mode=0o777)
    public.chmod(0o777)
    private = public / "private-leaf"
    private.mkdir(mode=0o700)
    with pytest.raises(PreparationError):
        private_directory(private)
