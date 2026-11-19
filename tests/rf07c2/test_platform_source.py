"""Original synthetic platform-source vectors; never full vendor build proof."""

import hashlib
import io
import json
from dataclasses import replace
from pathlib import Path

import pytest

from responseforge.integrations.wazuh.platform_source import (
    PlatformLock,
    fetch_platform_source,
    load_platform_lock,
    prepare_platform_source,
)
from responseforge.integrations.wazuh.security import PreparationError
from responseforge.integrations.wazuh.tls_source import SourceMember

PATHS = (
    ("package.json", "platform-package.json"),
    ("yarn.lock", "yarn.lock"),
    (".node-version", "node-version.txt"),
    ("LICENSE.txt", "LICENSE.txt"),
    ("NOTICE.txt", "NOTICE.txt"),
    ("packages/osd-plugin-helpers/src/tasks/write_server_files.ts", "write-server-files.ts"),
    ("packages/osd-plugin-helpers/src/tasks/yarn_install.ts", "yarn-install.ts"),
    ("packages/osd-babel-preset/node_preset.js", "node_preset.js"),
    ("packages/osd-dev-utils/src/babel.ts", "babel-helper.ts"),
    ("packages/osd-babel-preset/common_preset.js", "common_preset.js"),
    ("packages/osd-babel-preset/package.json", "preset-package.json"),
)
RAW = {name: f"Original synthetic platform member {name}\n".encode() for _, name in PATHS}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def policy():
    return PlatformLock(
        "5" * 40,
        tuple(SourceMember(path, name, len(RAW[name]), digest(RAW[name])) for path, name in PATHS),
    )


def material(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    for name, raw in RAW.items():
        (source / name).write_bytes(raw)
    return source


class Response(io.BytesIO):
    def __init__(self, raw, *, status=200, headers=None):
        super().__init__(raw)
        self.status = status
        self.headers = {"Content-Length": str(len(raw))} if headers is None else headers


def transport(calls):
    values = {path: RAW[name] for path, name in PATHS}

    def get(url):
        calls.append(url)
        path = url.split("/" + "5" * 40 + "/", 1)[1]
        return Response(values[path])

    return get


def test_valid_platform_acquisition_verifies_all_eleven_members_before_publication(tmp_path):
    calls = []
    output = tmp_path / "out"
    assert (
        fetch_platform_source(output, policy(), allow_download=True, transport=transport(calls))
        == output
    )
    assert len(calls) == 11
    assert set(p.name for p in output.iterdir()) == set(RAW)
    assert output.stat().st_mode & 0o077 == 0
    for name, raw in RAW.items():
        assert (output / name).read_bytes() == raw
        assert (output / name).stat().st_mode & 0o077 == 0


def test_valid_preparation_retains_all_source_license_notice_and_marks_unqualified(tmp_path):
    source = material(tmp_path)
    output = tmp_path / "out"
    assert prepare_platform_source(source, output, policy()) == output
    assert set(p.name for p in output.iterdir()) == set(RAW) | {
        "package.json",
        "RESPONSEFORGE_CHANGES.txt",
        "manifest.json",
    }
    for name, raw in RAW.items():
        assert (source / name).read_bytes() == raw
        assert (output / name).read_bytes() == raw
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["revision"] == "5" * 40
    assert manifest["ready"] is False
    assert manifest["runtime_qualified"] is False
    assert manifest["full_plugin_build"] is False
    assert (
        "Component" in (output / "RESPONSEFORGE_CHANGES.txt").read_text()
        or "component" in (output / "RESPONSEFORGE_CHANGES.txt").read_text()
    )


def test_reviewed_platform_source_identities_and_members_are_fixed():
    value = load_platform_lock()
    assert value.revision == "4a81e59ee597c0014e1d72666aa32423a964ba27"
    assert [(m.path, m.name) for m in value.members] == list(PATHS)
    members = {m.name: m for m in value.members}
    assert members["yarn.lock"].size == 891027
    assert (
        members["yarn.lock"].sha256
        == "db5c4f5233c26dea247bb32a071a6ab84dba8327369bfe88e67cb91429728c9d"
    )
    assert (
        members["node_preset.js"].sha256
        == "b76332559781d2f7bff9df19ecab8c65839962118f173d9d10db0b59df77280c"
    )
    assert (
        members["common_preset.js"].sha256
        == "d2bbe1ade56ebb9f0a67f4203372665383919dc4a57c54a3e9be14e59c81ffbb"
    )
    assert (
        members["LICENSE.txt"].sha256
        == "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    )
    assert (
        members["NOTICE.txt"].sha256
        == "6affa18ffb4db4e416a36abaa5892dbfd42bf0e76aa299c157ea0874c645d06e"
    )


@pytest.mark.parametrize("opt_in", [False, "true", 1, None])
def test_download_requires_literal_opt_in_without_network_or_publication(tmp_path, opt_in):
    calls = []
    with pytest.raises(PreparationError):
        fetch_platform_source(
            tmp_path / "out", policy(), allow_download=opt_in, transport=transport(calls)
        )
    assert calls == [] and not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "raw,status,headers",
    [
        (b"private error body", 500, None),
        (b"", 302, None),
        (b"", 301, None),
        (RAW["platform-package.json"], 200, {"Content-Encoding": "gzip"}),
        (RAW["platform-package.json"], 200, {"Content-Encoding": "deflate"}),
        (RAW["platform-package.json"], 200, {"Content-Length": "invalid"}),
        (RAW["platform-package.json"], 200, {"Content-Length": "-1"}),
        (RAW["platform-package.json"], 200, {"Content-Length": "1"}),
        (RAW["platform-package.json"] + b"tampered", 200, None),
        (RAW["platform-package.json"][:-1], 200, None),
        (b"X" * len(RAW["platform-package.json"]), 200, None),
    ],
)
def test_untrusted_http_response_never_publishes_or_discloses_body(tmp_path, raw, status, headers):
    calls = []

    def bad(url):
        calls.append(url)
        return Response(raw, status=status, headers=headers)

    with pytest.raises(PreparationError) as error:
        fetch_platform_source(tmp_path / "out", policy(), allow_download=True, transport=bad)
    assert len(calls) == 1
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob(".rf07b-*"))
    assert "private error body" not in str(error.value)


@pytest.mark.parametrize(
    "change", ["revision", "members", "path", "name", "size", "zero", "bool", "hash", "total"]
)
def test_invalid_policy_refused_before_network(tmp_path, change):
    value = policy()
    if change == "revision":
        value = replace(value, revision="../not-a-source")
    elif change == "members":
        value = replace(value, members=value.members[:-1])
    elif change == "total":
        value = replace(value, members=tuple(replace(m, size=1024 * 1024) for m in value.members))
    else:
        field = {
            "path": {"path": "../escape"},
            "name": {"name": "../escape"},
            "size": {"size": 1024 * 1024 + 1},
            "zero": {"size": 0},
            "bool": {"size": True},
            "hash": {"sha256": "not-a-hash"},
        }[change]
        value = replace(value, members=(replace(value.members[0], **field),) + value.members[1:])
    calls = []
    with pytest.raises(PreparationError):
        fetch_platform_source(
            tmp_path / "out", value, allow_download=True, transport=transport(calls)
        )
    assert calls == [] and not (tmp_path / "out").exists()


def test_interrupted_second_member_rolls_back_and_clean_retry_recovers(tmp_path):
    calls = []
    good = transport(calls)

    def interrupted(url):
        if url.endswith("/yarn.lock"):
            raise OSError("private transport diagnostic")
        return good(url)

    output = tmp_path / "out"
    with pytest.raises(PreparationError) as error:
        fetch_platform_source(output, policy(), allow_download=True, transport=interrupted)
    assert not output.exists() and not list(tmp_path.glob(".rf07b-*"))
    assert "private transport diagnostic" not in str(error.value)
    assert (
        fetch_platform_source(output, policy(), allow_download=True, transport=transport([]))
        == output
    )
    assert (output / "NOTICE.txt").read_bytes() == RAW["NOTICE.txt"]


def test_existing_output_is_preserved_without_network(tmp_path):
    output = tmp_path / "out"
    output.mkdir(mode=0o700)
    retained = output / "retained"
    retained.write_bytes(b"original retained bytes")
    calls = []
    with pytest.raises(PreparationError):
        fetch_platform_source(output, policy(), allow_download=True, transport=transport(calls))
    assert calls == []
    with pytest.raises(PreparationError):
        prepare_platform_source(material(tmp_path), output, policy())
    assert retained.read_bytes() == b"original retained bytes"
    assert set(p.name for p in output.iterdir()) == {"retained"}


@pytest.mark.parametrize("kind", ["missing", "extra", "tamper", "symlink", "hardlink", "fifo"])
def test_unsafe_incomplete_or_tampered_source_refused_before_output(tmp_path, kind):
    source = material(tmp_path)
    target = source / "common_preset.js"
    if kind == "extra":
        (source / "unexpected.js").write_bytes(b"untrusted extra")
    elif kind == "tamper":
        target.write_bytes(RAW[target.name] + b"tamper")
    else:
        target.unlink()
        if kind in {"symlink", "hardlink"}:
            original = tmp_path / "other"
            original.write_bytes(RAW[target.name])
            if kind == "symlink":
                target.symlink_to(original)
            else:
                target.hardlink_to(original)
        elif kind == "fifo":
            import os

            os.mkfifo(target)
    with pytest.raises(PreparationError):
        prepare_platform_source(source, tmp_path / "out", policy())
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("phase", ["fetch", "prepare"])
def test_replaceable_output_ancestry_is_refused(tmp_path, phase):
    replaceable = tmp_path / "replaceable"
    replaceable.mkdir(mode=0o777)
    replaceable.chmod(0o777)
    private = replaceable / "private"
    private.mkdir(mode=0o700)
    output = private / "out"
    calls = []
    with pytest.raises(PreparationError):
        if phase == "fetch":
            fetch_platform_source(output, policy(), allow_download=True, transport=transport(calls))
        else:
            prepare_platform_source(material(tmp_path), output, policy())
    assert not output.exists() and calls == []


def test_symlink_output_does_not_mutate_referenced_directory(tmp_path):
    retained = tmp_path / "retained"
    retained.mkdir(mode=0o700)
    (retained / "marker").write_bytes(b"preserve")
    output = tmp_path / "out"
    output.symlink_to(retained, target_is_directory=True)
    with pytest.raises(PreparationError):
        prepare_platform_source(material(tmp_path), output, policy())
    assert (retained / "marker").read_bytes() == b"preserve"
    assert set(p.name for p in retained.iterdir()) == {"marker"}


def test_response_streams_close_on_success_and_rejection(tmp_path):
    opened = []
    values = {path: RAW[name] for path, name in PATHS}

    def get(url):
        response = Response(values[url.split("/" + "5" * 40 + "/", 1)[1]])
        opened.append(response)
        return response

    fetch_platform_source(tmp_path / "out", policy(), allow_download=True, transport=get)
    assert len(opened) == 11 and all(response.closed for response in opened)
    rejected = Response(b"private refusal", status=500)
    with pytest.raises(PreparationError):
        fetch_platform_source(
            tmp_path / "bad", policy(), allow_download=True, transport=lambda _: rejected
        )
    assert rejected.closed


def test_nonprivate_source_and_group_writable_member_are_refused(tmp_path):
    source = material(tmp_path)
    source.chmod(0o755)
    with pytest.raises(PreparationError):
        prepare_platform_source(source, tmp_path / "out", policy())
    source.chmod(0o700)
    (source / "node_preset.js").chmod(0o666)
    with pytest.raises(PreparationError):
        prepare_platform_source(source, tmp_path / "out", policy())
    assert not (tmp_path / "out").exists()


def test_prepare_manifest_binds_source_originals_and_reviewed_minimal_package(tmp_path):
    source = material(tmp_path)
    output = tmp_path / "out"
    prepare_platform_source(source, output, policy())
    manifest = json.loads((output / "manifest.json").read_text())
    assert set(manifest["files"]) == set(RAW) | {"package.json", "RESPONSEFORGE_CHANGES.txt"}
    for name, raw in RAW.items():
        assert manifest["files"][name] == digest(raw)
    package = Path(__file__).resolve().parents[2] / "tools/wazuh-platform/package.json"
    assert (output / "package.json").read_bytes() == package.read_bytes()
    assert manifest["files"]["package.json"] == digest(package.read_bytes())
    assert output.stat().st_mode & 0o077 == 0
    assert all(p.stat().st_mode & 0o077 == 0 for p in output.iterdir())


def test_cli_fetch_default_has_no_implicit_network_and_safe_error(tmp_path, monkeypatch, capsys):
    import urllib.request

    from scripts import wazuh_platform

    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *args: pytest.fail("implicit opener")
    )
    output = tmp_path / "out"
    assert wazuh_platform.main(["fetch", "--output", str(output)]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "prepared": False,
        "ready": False,
        "error": "Source preparation refused",
    }
    assert not output.exists()


def test_cli_source_refusal_does_not_print_private_contents(tmp_path, capsys):
    from scripts import wazuh_platform

    source = material(tmp_path)
    (source / "node_preset.js").write_bytes(b"PRIVATE SYNTHETIC CONTENT DO NOT PRINT")
    assert (
        wazuh_platform.main(["prepare", "--source", str(source), "--output", str(tmp_path / "out")])
        == 1
    )
    captured = capsys.readouterr()
    assert "PRIVATE SYNTHETIC" not in captured.out + captured.err
    assert "Source preparation refused" in captured.out


def test_cli_valid_private_prepare_keeps_readiness_false(tmp_path, monkeypatch, capsys):
    from scripts import wazuh_platform

    monkeypatch.setattr(wazuh_platform, "load_platform_lock", policy)
    source = material(tmp_path)
    output = tmp_path / "out"
    assert wazuh_platform.main(["prepare", "--source", str(source), "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "prepared": True,
        "ready": False,
        "runtime_qualified": False,
    }
    assert (output / "LICENSE.txt").read_bytes() == RAW["LICENSE.txt"]
    assert (output / "NOTICE.txt").read_bytes() == RAW["NOTICE.txt"]
