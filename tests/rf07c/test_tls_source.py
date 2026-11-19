"""Original synthetic vectors: source preparation, never vendor runtime proof."""

import hashlib
import io
import json
from dataclasses import replace

import pytest

from responseforge.integrations.wazuh.security import PreparationError
from responseforge.integrations.wazuh.tls_source import (
    SourceLock,
    SourceMember,
    fetch_tls_source,
    load_source_lock,
    patch_client,
    prepare_tls_source,
)

OLD = b"""    const httpsAgent = new https.Agent({
      rejectUnauthorized: false,
    });
    this._axios = axios.create({ httpsAgent });"""
RAW = b"// Original synthetic source, not vendor bytes\nclass Synthetic {\n" + OLD + b"\n}\n"
NEW = b"    const httpsAgent = new https.Agent({\n      rejectUnauthorized: true,\n    });\n    this._axios = axios.create({ httpsAgent, maxRedirects: 0, proxy: false });\n    this._axios.interceptors.request.use(config => {\n      if (typeof config.url !== 'string' ||\n          /[\\u0000-\\u0020\\u007f]/.test(config.url)) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      let target: URL;\n      try {\n        target = new URL(config.url);\n      } catch {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      if (target.protocol !== 'https:' || target.username || target.password || target.hash) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      return config;\n    });"
COOKIE = b"// Original synthetic cookie helper\n"
LICENSE = b"Original synthetic license fixture\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def lock():
    members = tuple(
        SourceMember(path, name, len(raw), digest(raw))
        for path, name, raw in (
            (
                "plugins/wazuh-core/server/services/server-api-client.ts",
                "upstream-server-api-client.ts",
                RAW,
            ),
            ("plugins/wazuh-core/server/services/cookie.ts", "cookie.ts", COOKIE),
            ("LICENSE", "LICENSE", LICENSE),
        )
    )
    return SourceLock("5" * 40, members, digest(RAW.replace(OLD, NEW)))


def material(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    for name, raw in [
        ("upstream-server-api-client.ts", RAW),
        ("cookie.ts", COOKIE),
        ("LICENSE", LICENSE),
    ]:
        (source / name).write_bytes(raw)
    return source


def test_pinned_source_identities_are_fixed():
    value = load_source_lock()
    assert value.revision == "5005c3e2213abeb5c7798f489a7304a6abb7c6d1"
    assert [(m.name, m.size, m.sha256) for m in value.members] == [
        (
            "upstream-server-api-client.ts",
            9065,
            "b55c5947bab7c9b0b1e97238edb4f2c26ceae8f6bd4d5a33801d8a8d5fde6ca5",
        ),
        ("cookie.ts", 671, "2acfdac9af159576cc0deede34516dac790269ce6d132fadd1430c153130cbd4"),
        ("LICENSE", 18091, "7a8af52a46a18822fe4858a963871ce0cca465d72ea312e25e28b15b158beec0"),
    ]


def test_exact_constructor_is_corrected_deterministically_preserving_surroundings():
    result = patch_client(RAW, digest(RAW))
    assert result == RAW.replace(OLD, NEW)
    assert result == patch_client(RAW, digest(RAW))
    assert result.startswith(RAW.split(OLD)[0]) and result.endswith(b"\n}\n")
    assert b"rejectUnauthorized: true" in result and b"rejectUnauthorized: false" not in result
    assert b"maxRedirects: 0" in result and b"proxy: false" in result
    assert b"target.protocol !== 'https:'" in result
    assert b"target.username" in result and b"target.password" in result
    assert b"interceptors.request.use" in result


@pytest.mark.parametrize(
    "raw,expected",
    [
        (RAW + b"changed", digest(RAW)),
        (RAW.replace(OLD, b""), None),
        (RAW + OLD, None),
        (RAW.replace(b"false", b"true"), None),
    ],
)
def test_hash_and_anchor_fail_closed(raw, expected):
    with pytest.raises(PreparationError):
        patch_client(raw, expected or digest(raw))


class Response(io.BytesIO):
    status = 200

    def __init__(self, raw, *, status=200, headers=None):
        super().__init__(raw)
        self.status = status
        self.headers = {"Content-Length": str(len(raw))} if headers is None else headers


def transport(calls, *, failing=None):
    values = {"server-api-client.ts": RAW, "cookie.ts": COOKIE, "LICENSE": LICENSE}

    def get(url):
        calls.append(url)
        name = url.rsplit("/", 1)[-1]
        return failing if failing is not None else Response(values[name])

    return get


@pytest.mark.parametrize("opt_in", [False, "true", 1, None])
def test_acquisition_needs_literal_opt_in_before_network(tmp_path, opt_in):
    policy = lock()
    calls = []
    with pytest.raises(PreparationError):
        fetch_tls_source(
            tmp_path / "out", policy, allow_download=opt_in, transport=transport(calls)
        )
    assert calls == [] and not (tmp_path / "out").exists()


def test_acquisition_all_members_verified_then_private_atomic_publication(tmp_path):
    policy = lock()
    calls = []
    output = tmp_path / "out"
    assert (
        fetch_tls_source(output, policy, allow_download=True, transport=transport(calls)) == output
    )
    assert len(calls) == 3
    assert all(
        url.startswith(
            "https://raw.githubusercontent.com/wazuh/wazuh-dashboard-plugins/" + "5" * 40 + "/"
        )
        for url in calls
    )
    assert (output / "upstream-server-api-client.ts").read_bytes() == RAW
    assert output.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "response",
    [
        Response(b"", status=302),
        Response(b"private body", status=500),
        Response(RAW, headers={"Content-Encoding": "gzip"}),
        Response(RAW, headers={"Content-Length": "invalid"}),
        Response(RAW + b"tamper"),
        Response(RAW[:-1]),
    ],
)
def test_invalid_response_never_publishes(tmp_path, response):
    policy = lock()
    calls = []
    with pytest.raises(PreparationError) as error:
        fetch_tls_source(
            tmp_path / "out",
            policy,
            allow_download=True,
            transport=transport(calls, failing=response),
        )
    assert not (tmp_path / "out").exists() and len(calls) == 1
    assert "private body" not in str(error.value)


def test_prepare_preserves_original_and_refuses_wrong_modified_hash(tmp_path):
    source = material(tmp_path)
    policy = lock()
    with pytest.raises(PreparationError):
        prepare_tls_source(source, tmp_path / "out", replace(policy, patched_sha256="0" * 64))
    assert not (tmp_path / "out").exists()
    assert (source / "upstream-server-api-client.ts").read_bytes() == RAW


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "changed"])
def test_unsafe_source_member_refused_before_output(tmp_path, kind):
    source = material(tmp_path)
    target = source / "cookie.ts"
    if kind == "changed":
        target.write_bytes(COOKIE + b"tampered")
    else:
        target.unlink()
        original = tmp_path / "other"
        original.write_bytes(COOKIE)
        if kind == "symlink":
            target.symlink_to(original)
        else:
            target.hardlink_to(original)
    policy = lock()
    with pytest.raises(PreparationError):
        prepare_tls_source(source, tmp_path / "out", policy)
    assert not (tmp_path / "out").exists()


def test_prepare_complete_bundle_originals_notice_and_safe_manifest(tmp_path):
    source = material(tmp_path)
    policy = lock()
    output = tmp_path / "prepared"
    assert prepare_tls_source(source, output, policy) == output
    assert (output / "upstream-server-api-client.ts").read_bytes() == RAW
    assert (output / "server-api-client.ts").read_bytes() == RAW.replace(OLD, NEW)
    assert (output / "cookie.ts").read_bytes() == COOKIE
    assert (output / "LICENSE").read_bytes() == LICENSE
    assert b"RF-07C1" in (output / "RESPONSEFORGE_CHANGES.txt").read_bytes()
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["ready"] is False and manifest["runtime_qualified"] is False
    assert manifest["revision"] == policy.revision
    assert manifest["files"]["server-api-client.ts"] == policy.patched_sha256
    assert all(p.stat().st_mode & 0o077 == 0 for p in output.iterdir())


@pytest.mark.parametrize("existing", ["directory", "symlink"])
def test_existing_output_preserved_without_network_or_replacement(tmp_path, existing):
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "retained").write_bytes(b"original retained material")
    output = tmp_path / "out"
    if existing == "symlink":
        output.symlink_to(sentinel, target_is_directory=True)
    else:
        output.mkdir()
        (output / "retained").write_bytes(b"original retained material")
    calls = []
    with pytest.raises(PreparationError):
        fetch_tls_source(output, lock(), allow_download=True, transport=transport(calls))
    assert calls == []
    assert (output / "retained").read_bytes() == b"original retained material"
    with pytest.raises(PreparationError):
        prepare_tls_source(material(tmp_path), output, lock())
    assert (output / "retained").read_bytes() == b"original retained material"


@pytest.mark.parametrize("change", ["revision", "size", "hash", "members", "path"])
def test_invalid_trusted_lock_rejected_before_network(tmp_path, change):
    policy = lock()
    if change == "revision":
        policy = replace(policy, revision="../not-a-revision")
    elif change == "members":
        policy = replace(policy, members=policy.members[:2])
    else:
        member = policy.members[0]
        member = replace(
            member,
            **{"size": 32769}
            if change == "size"
            else {"sha256": "not-a-hash"}
            if change == "hash"
            else {"path": "../escape"},
        )
        policy = replace(policy, members=(member,) + policy.members[1:])
    calls = []
    with pytest.raises(PreparationError):
        fetch_tls_source(tmp_path / "out", policy, allow_download=True, transport=transport(calls))
    assert calls == [] and not (tmp_path / "out").exists()


def test_partial_second_member_failure_cleans_stage_and_can_recover(tmp_path):
    calls = []
    good = transport(calls)

    def interrupted(url):
        if url.endswith("/cookie.ts"):
            raise OSError("private interrupted transport")
        return good(url)

    output = tmp_path / "out"
    with pytest.raises(PreparationError) as error:
        fetch_tls_source(output, lock(), allow_download=True, transport=interrupted)
    assert "private interrupted" not in str(error.value)
    assert not output.exists()
    assert not list(tmp_path.glob(".rf07b-*"))
    assert fetch_tls_source(output, lock(), allow_download=True, transport=transport([])) == output


def test_cli_default_fetch_no_download_and_safe_error(tmp_path, monkeypatch, capsys):
    import urllib.request

    from scripts import wazuh_tls

    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *a: pytest.fail("implicit network opener")
    )
    output = tmp_path / "out"
    assert wazuh_tls.main(["fetch", "--output", str(output)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result == {"prepared": False, "ready": False, "error": "Source preparation refused"}
    assert not output.exists()


def test_cli_malformed_source_never_prints_private_source_content(tmp_path, capsys):
    from scripts import wazuh_tls

    source = material(tmp_path)
    (source / "cookie.ts").write_bytes(b"SYNTHETIC PRIVATE SOURCE CONTENT; DO NOT PRINT")
    assert (
        wazuh_tls.main(["prepare", "--source", str(source), "--output", str(tmp_path / "out")]) == 1
    )
    captured = capsys.readouterr()
    assert "PRIVATE SOURCE" not in captured.out + captured.err
    assert "Source preparation refused" in captured.out
