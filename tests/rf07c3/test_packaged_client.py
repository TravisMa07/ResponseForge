"""Original synthetic archive/source vectors; never packaged vendor runtime proof."""

import base64
import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import replace

import httpx
import pytest

from responseforge.integrations.wazuh.packaged_client import (
    BlobSpec,
    FileSpec,
    PackagedLock,
    fetch_packaged_payload,
    load_packaged_lock,
    patch_packaged_client,
    prepare_packaged_client,
)
from responseforge.integrations.wazuh.security import PreparationError
from responseforge.integrations.wazuh.tls_source import SourceLock, SourceMember

ROOT = "usr/share/wazuh-dashboard"
CLIENT = ROOT + "/plugins/wazuhCore/server/services/server-api-client.js"
COOKIE_PATH = ROOT + "/plugins/wazuhCore/server/services/cookie.js"
AXIOS = ROOT + "/node_modules/axios/dist/node/axios.cjs"
OLD = b"""    const httpsAgent = new _https.default.Agent({
      rejectUnauthorized: false
    });
    this._axios = _axios.default.create({
      httpsAgent
    });"""
NEW = b"""    const httpsAgent = new _https.default.Agent({
      rejectUnauthorized: true
    });
    this._axios = _axios.default.create({
      httpsAgent,
      maxRedirects: 0,
      proxy: false
    });
    this._axios.interceptors.request.use(config => {
      if (typeof config.url !== 'string' || /[\\u0000-\\u0020\\u007f]/.test(config.url)) {
        throw new Error('Verified HTTPS manager API URL required');
      }
      let target;
      try {
        target = new URL(config.url);
      } catch {
        throw new Error('Verified HTTPS manager API URL required');
      }
      if (target.protocol !== 'https:' || target.username || target.password || target.hash) {
        throw new Error('Verified HTTPS manager API URL required');
      }
      return config;
    });"""
PREFIX = b"// ResponseForge RF-07C3: verified HTTPS correction; modified 2026-11-19.\n"
MARKER = b"//# sourceMappingURL=data:application/json;charset=utf-8;base64,"
TS_OLD = b"""    const httpsAgent = new https.Agent({
      rejectUnauthorized: false,
    });
    this._axios = axios.create({ httpsAgent });"""
TS_NEW = b"    const httpsAgent = new https.Agent({\n      rejectUnauthorized: true,\n    });\n    this._axios = axios.create({ httpsAgent, maxRedirects: 0, proxy: false });\n    this._axios.interceptors.request.use(config => {\n      if (typeof config.url !== 'string' ||\n          /[\\u0000-\\u0020\\u007f]/.test(config.url)) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      let target: URL;\n      try {\n        target = new URL(config.url);\n      } catch {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      if (target.protocol !== 'https:' || target.username || target.password || target.hash) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      return config;\n    });"
TS = b"// Original synthetic source\nclass Synthetic {\n" + TS_OLD + b"\n}\n"
COOKIE_TS = b"// Original synthetic cookie helper\nexport const cookie = 'synthetic';\n"
LICENSE = b"Original synthetic license terms\n"
BODY = b"// Original synthetic compiled class\nclass Synthetic {\n" + OLD + b"\n}\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def mapped(body, name, content):
    value = {
        "version": 3,
        "sources": [name],
        "sourcesContent": [content.decode()],
        "names": [],
        "mappings": "",
    }
    return body + MARKER + base64.b64encode(json.dumps(value).encode()) + b"\n"


RAW = mapped(BODY, "server-api-client.ts", TS)
COOKIE_JS = mapped(
    b"// Original synthetic compiled helper\nexports.cookie='synthetic';\n", "cookie.ts", COOKIE_TS
)
PATCHED = PREFIX + BODY.replace(OLD, NEW)


def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o600
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def vectors():
    contents = {
        CLIENT: RAW,
        COOKIE_PATH: COOKIE_JS,
        AXIOS: b"// Original synthetic dependency\n",
        ROOT + "/LICENSE.txt": LICENSE,
        ROOT + "/NOTICE.txt": b"Original synthetic notice\n",
    }
    payload = tar_bytes(list(contents.items()))
    expanded = [payload] + [tar_bytes([]) for _ in range(3)]
    blobs = {
        name: gzip.compress(raw, mtime=0)
        for name, raw in zip(
            ["payload.tar.gz", "post-10.tar.gz", "post-11.tar.gz", "post-12.tar.gz"],
            expanded,
            strict=True,
        )
    }
    policy = PackagedLock(
        "sha256:" + "5" * 64,
        tuple(
            BlobSpec(name, len(raw), digest(raw), digest(expanded[index]))
            for index, (name, raw) in enumerate(blobs.items())
        ),
        tuple(FileSpec(name, len(raw), digest(raw)) for name, raw in contents.items()),
        CLIENT,
        COOKIE_PATH,
        AXIOS,
        digest(BODY),
        digest(PATCHED),
    )
    return policy, blobs, contents


def source_material(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    values = {
        "upstream-server-api-client.ts": TS,
        "server-api-client.ts": TS.replace(TS_OLD, TS_NEW),
        "cookie.ts": COOKIE_TS,
        "LICENSE": LICENSE,
    }
    for name, raw in values.items():
        (source / name).write_bytes(raw)
        (source / name).chmod(0o600)
    members = tuple(
        SourceMember(path, name, len(values[name]), digest(values[name]))
        for path, name in [
            (
                "plugins/wazuh-core/server/services/server-api-client.ts",
                "upstream-server-api-client.ts",
            ),
            ("plugins/wazuh-core/server/services/cookie.ts", "cookie.ts"),
            ("LICENSE", "LICENSE"),
        ]
    )
    return source, SourceLock("5" * 40, members, digest(values["server-api-client.ts"]))


def cache_material(tmp_path, blobs):
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    for name, raw in blobs.items():
        (cache / name).write_bytes(raw)
        (cache / name).chmod(0o600)
    return cache


def mock_transport(blobs, calls):
    by_hash = {digest(raw): raw for raw in blobs.values()}

    def respond(request):
        calls.append(request)
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "synthetic-private-registry-token"})
        raw = by_hash[request.url.path.rsplit(":", 1)[-1]]
        return httpx.Response(200, content=raw, headers={"Content-Length": str(len(raw))})

    return httpx.MockTransport(respond)


def test_valid_compiled_constructor_correction_preserves_body_and_removes_stale_map():
    result = patch_packaged_client(RAW, digest(RAW))
    assert result == PATCHED
    assert MARKER not in result
    assert result.count(b"rejectUnauthorized: true") == 1
    assert b"rejectUnauthorized: false" not in result


def test_valid_fixed_payload_acquisition_and_prepare(tmp_path):
    policy, blobs, contents = vectors()
    calls = []
    output = tmp_path / "cache"
    assert (
        fetch_packaged_payload(
            output, policy, allow_download=True, transport=mock_transport(blobs, calls)
        )
        == output
    )
    assert len(calls) == 5
    assert calls[0].url.host == "auth.docker.io"
    assert all((output / name).read_bytes() == raw for name, raw in blobs.items())
    source, source_lock = source_material(tmp_path)
    prepared = tmp_path / "prepared"
    assert prepare_packaged_client(output, source, prepared, policy, source_lock) == prepared
    assert (prepared / "patched/server-api-client.js").read_bytes() == PATCHED
    for name, raw in contents.items():
        assert (prepared / "root" / name).read_bytes() == raw


def test_valid_private_cache_preparation_without_network(tmp_path):
    policy, blobs, contents = vectors()
    cache = cache_material(tmp_path, blobs)
    source, source_lock = source_material(tmp_path)
    output = tmp_path / "prepared"
    assert prepare_packaged_client(cache, source, output, policy, source_lock) == output
    assert (output / "patched/server-api-client.js").read_bytes() == PATCHED
    for name, raw in contents.items():
        assert (output / "root" / name).read_bytes() == raw


def test_reviewed_artifact_identities_and_caps_are_fixed():
    policy = load_packaged_lock()
    assert (
        policy.image_digest
        == "sha256:83560991be21e1cc50f396bd2c8281f903b9a6a33918632057294b2300cfea65"
    )
    assert [(b.name, b.size, b.sha256) for b in policy.blobs] == [
        (
            "payload.tar.gz",
            292316387,
            "77117a11f0736bfe3b558431afcbe11c1797b3b6b0ba8afbf6698e47b5e3c097",
        ),
        ("post-10.tar.gz", 261, "404e7844a8b59ddc985194cb9058f92316fa5ef1d281f18598a318eb6a38d08b"),
        ("post-11.tar.gz", 261, "1f7d2e94ed74517ee4d9e22fcabcd3ee91e7a706832c89d425e550d8cba7cf6e"),
        ("post-12.tar.gz", 32, "4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1"),
    ]
    assert len(policy.files) == 297
    assert policy.client_path == CLIENT and policy.cookie_path == COOKIE_PATH
    assert policy.axios_entry == AXIOS
    assert max(f.size for f in policy.files) >= 1423978


@pytest.mark.parametrize(
    "raw,expected",
    [
        (RAW + b"changed", digest(RAW)),
        (mapped(BODY.replace(OLD, b""), "server-api-client.ts", TS), None),
        (mapped(BODY + OLD, "server-api-client.ts", TS), None),
        (mapped(BODY.replace(OLD, NEW), "server-api-client.ts", TS), None),
        (BODY, None),
        (RAW + MARKER + b"invalid", None),
    ],
)
def test_wrong_compiled_identity_anchor_or_map_refuses(raw, expected):
    with pytest.raises(PreparationError):
        patch_packaged_client(raw, expected or digest(raw))


@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_download_needs_literal_opt_in_before_any_network_or_output(tmp_path, value):
    policy, blobs, _ = vectors()
    calls = []
    with pytest.raises(PreparationError):
        fetch_packaged_payload(
            tmp_path / "out", policy, allow_download=value, transport=mock_transport(blobs, calls)
        )
    assert calls == [] and not (tmp_path / "out").exists()


def test_existing_fetch_output_preserved_without_token_request(tmp_path):
    policy, blobs, _ = vectors()
    output = tmp_path / "out"
    output.mkdir(mode=0o700)
    (output / "retained").write_bytes(b"existing original material")
    calls = []
    with pytest.raises(PreparationError):
        fetch_packaged_payload(
            output, policy, allow_download=True, transport=mock_transport(blobs, calls)
        )
    assert calls == [] and (output / "retained").read_bytes() == b"existing original material"


@pytest.mark.parametrize(
    "kind", ["status", "encoding", "length", "truncated", "excess", "hash", "bad-redirect"]
)
def test_bad_blob_http_never_publishes_or_discloses_private_body(tmp_path, kind):
    policy, blobs, _ = vectors()
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "SYNTHETIC-PRIVATE-TOKEN"})
        raw = blobs["payload.tar.gz"]
        if kind == "status":
            return httpx.Response(500, content=b"SYNTHETIC-PRIVATE-BODY")
        if kind == "encoding":
            return httpx.Response(200, content=raw, headers={"Content-Encoding": "br"})
        if kind == "length":
            return httpx.Response(200, content=raw, headers={"Content-Length": "invalid"})
        if kind == "truncated":
            raw = raw[:-1]
        elif kind == "excess":
            raw += b"extra"
        elif kind == "hash":
            raw = b"x" * len(raw)
        elif kind == "bad-redirect":
            return httpx.Response(
                302,
                headers={"Location": "https://unexpected.invalid/blob?SYNTHETIC-PRIVATE-SIGNATURE"},
            )
        return httpx.Response(200, content=raw, headers={"Content-Length": str(len(raw))})

    with pytest.raises(PreparationError) as error:
        fetch_packaged_payload(
            tmp_path / "out", policy, allow_download=True, transport=httpx.MockTransport(respond)
        )
    assert not (tmp_path / "out").exists()
    assert "SYNTHETIC-PRIVATE" not in str(error.value)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "https://unexpected.invalid/token"}),
        httpx.Response(500, content=b"SYNTHETIC-PRIVATE-TOKEN"),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"token": 7}),
        httpx.Response(200, content=b"x" * 65537),
    ],
)
def test_token_failure_stops_before_registry(tmp_path, response):
    policy, _, _ = vectors()
    calls = []

    def respond(request):
        calls.append(request)
        return response

    with pytest.raises(PreparationError) as error:
        fetch_packaged_payload(
            tmp_path / "out", policy, allow_download=True, transport=httpx.MockTransport(respond)
        )
    assert len(calls) == 1 and calls[0].url.host == "auth.docker.io"
    assert not (tmp_path / "out").exists() and "SYNTHETIC-PRIVATE" not in str(error.value)


def test_allowed_cdn_redirect_strips_registry_authorization(tmp_path):
    policy, blobs, _ = vectors()
    calls = []
    by_hash = {digest(raw): raw for raw in blobs.values()}

    def respond(request):
        calls.append(request)
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "synthetic-private-token"})
        if request.url.host == "registry-1.docker.io":
            assert request.headers["authorization"] == "Bearer synthetic-private-token"
            return httpx.Response(
                307,
                headers={
                    "Location": "https://production.cloudfront.docker.com/"
                    + request.url.path.rsplit(":", 1)[-1]
                    + "?signature=synthetic-private-signature"
                },
            )
        assert request.url.host == "production.cloudfront.docker.com"
        assert "authorization" not in request.headers
        raw = by_hash[request.url.path.rsplit("/", 1)[-1]]
        return httpx.Response(200, content=raw, headers={"Content-Length": str(len(raw))})

    output = tmp_path / "out"
    assert (
        fetch_packaged_payload(
            output, policy, allow_download=True, transport=httpx.MockTransport(respond)
        )
        == output
    )
    assert len(calls) == 9


def altered_blob(policy, blobs, expanded, *, index=0, wrong_diff=False):
    raw = gzip.compress(expanded, mtime=0)
    spec = policy.blobs[index]
    replacement = replace(
        spec,
        size=len(raw),
        sha256=digest(raw),
        diff_id=spec.diff_id if wrong_diff else digest(expanded),
    )
    changed = replace(
        policy, blobs=policy.blobs[:index] + (replacement,) + policy.blobs[index + 1 :]
    )
    return changed, {**blobs, spec.name: raw}


def prepare_fixture(tmp_path, policy, blobs):
    cache = cache_material(tmp_path, blobs)
    source, source_lock = source_material(tmp_path)
    output = tmp_path / "out"
    return cache, source, source_lock, output


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "wrong-content",
        "duplicate",
        "traversal",
        "absolute",
        "control",
        "whiteout",
        "opaque",
    ],
)
def test_unsafe_or_incomplete_archive_never_publishes(tmp_path, kind):
    policy, blobs, contents = vectors()
    entries = list(contents.items())
    if kind == "missing":
        entries = entries[1:]
    elif kind == "wrong-content":
        entries[0] = (CLIENT, RAW + b"tampered")
    elif kind == "duplicate":
        entries.append(entries[0])
    else:
        path = {
            "traversal": "../outside",
            "absolute": "/outside",
            "control": ROOT + "/bad\nname",
            "whiteout": ROOT + "/.wh.server",
            "opaque": ROOT + "/.wh..wh..opq",
        }[kind]
        entries.append((path, b""))
    policy, blobs = altered_blob(policy, blobs, tar_bytes(entries))
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists() and not (tmp_path / "outside").exists()
    assert (cache / "payload.tar.gz").read_bytes() == blobs["payload.tar.gz"]


def tar_with_link(entries, name, kind):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.type = {
            "symlink": tarfile.SYMTYPE,
            "hardlink": tarfile.LNKTYPE,
            "fifo": tarfile.FIFOTYPE,
        }[kind]
        info.linkname = "/outside"
        archive.addfile(info)
        for path, raw in entries:
            leaf = tarfile.TarInfo(path)
            leaf.size = len(raw)
            archive.addfile(leaf, io.BytesIO(raw))
    return stream.getvalue()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "ancestor-symlink"])
def test_archive_links_and_selected_ancestor_links_refuse(tmp_path, kind):
    policy, blobs, contents = vectors()
    name = ROOT + "/plugins/wazuhCore" if kind == "ancestor-symlink" else CLIENT
    entries = [(p, raw) for p, raw in contents.items() if p != name]
    policy, blobs = altered_blob(
        policy,
        blobs,
        tar_with_link(entries, name, "symlink" if kind == "ancestor-symlink" else kind),
    )
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


def test_later_layer_cannot_override_even_unselected_regular_file(tmp_path):
    policy, blobs, _ = vectors()
    policy, blobs = altered_blob(
        policy, blobs, tar_bytes([(ROOT + "/unselected", b"unexpected later data")]), index=1
    )
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


def test_decompressed_diffid_covers_tar_trailer_and_extra_gzip_members(tmp_path):
    policy, blobs, contents = vectors()
    expanded = tar_bytes(list(contents.items())) + b"not ignored after tar EOF"
    policy, blobs = altered_blob(policy, blobs, expanded, wrong_diff=True)
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "changed", "unsafe-mode"])
def test_unsafe_cache_leaf_refuses(tmp_path, kind):
    policy, blobs, _ = vectors()
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    target = cache / "payload.tar.gz"
    if kind == "changed":
        target.write_bytes(b"tampered")
    elif kind == "unsafe-mode":
        target.chmod(0o666)
    else:
        target.unlink()
        other = tmp_path / "other"
        other.write_bytes(blobs["payload.tar.gz"])
        if kind == "symlink":
            target.symlink_to(other)
        elif kind == "hardlink":
            target.hardlink_to(other)
        else:
            import os

            os.mkfifo(target)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


@pytest.mark.parametrize(
    "name", ["upstream-server-api-client.ts", "server-api-client.ts", "cookie.ts", "LICENSE"]
)
def test_wrong_c1_source_member_refuses(tmp_path, name):
    policy, blobs, _ = vectors()
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    (source / name).write_bytes(b"unreviewed source member")
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


def test_existing_prepare_output_is_preserved(tmp_path):
    policy, blobs, _ = vectors()
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    output.mkdir(mode=0o700)
    (output / "retained").write_bytes(b"original")
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert (output / "retained").read_bytes() == b"original"


def test_private_prepared_manifest_source_preservation_and_build_context(tmp_path):
    policy, blobs, contents = vectors()
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    assert prepare_packaged_client(cache, source, output, policy, source_lock) == output
    assert output.stat().st_mode & 0o077 == 0
    for member in source.iterdir():
        assert (output / member.name).read_bytes() == member.read_bytes()
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["ready"] is False and manifest["runtime_qualified"] is False
    assert manifest["image_built"] is False and manifest["image_executed"] is False
    assert manifest["full_plugin_build"] is False
    context = output / "build-context"
    dockerfile = (context / "Dockerfile").read_text()
    lines = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(lines) == 2
    assert lines[0] == "FROM wazuh/wazuh-dashboard@" + policy.image_digest
    assert lines[1].startswith("COPY --chown=1000:1000 --chmod=0644 ")
    words = lines[1].split()
    assert words[-1] == "/" + CLIENT
    assert (context / words[-2]).read_bytes() == PATCHED
    assert "RUN " not in dockerfile and "ENTRYPOINT" not in dockerfile and "USER " not in dockerfile
    assert (output / "root" / ROOT / "LICENSE.txt").read_bytes() == LICENSE
    for member in output.rglob("*"):
        assert not member.is_symlink()
        if member.is_file():
            assert member.stat().st_mode & 0o077 == 0
    for name, raw in contents.items():
        assert (output / "root" / name).read_bytes() == raw


@pytest.mark.parametrize(
    "constant,value",
    [
        ("MAX_BLOB", 8),
        ("MAX_FILE", 8),
        ("MAX_FILES", 2),
        ("MAX_SELECTED", 16),
        ("MAX_ENTRIES", 2),
        ("MAX_EXPANDED", 512),
    ],
)
def test_resource_caps_fail_closed_before_complete_publication(
    tmp_path, monkeypatch, constant, value
):
    from responseforge.integrations.wazuh import packaged_client

    policy, blobs, _ = vectors()
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    monkeypatch.setattr(packaged_client, constant, value, raising=False)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


@pytest.mark.parametrize(
    "kind",
    [
        "image",
        "blob-name",
        "blob-size",
        "blob-hash",
        "blob-diff",
        "file-path",
        "file-size",
        "file-hash",
        "file-duplicate",
        "blob-missing",
    ],
)
def test_invalid_trusted_policy_refuses_before_fetch(tmp_path, kind):
    policy, blobs, _ = vectors()
    if kind == "image":
        policy = replace(policy, image_digest="mutable-tag")
    elif kind.startswith("blob-"):
        if kind == "blob-missing":
            policy = replace(policy, blobs=policy.blobs[:-1])
        else:
            changes = {
                "blob-name": {"name": "../outside"},
                "blob-size": {"size": 350000001},
                "blob-hash": {"sha256": "bad"},
                "blob-diff": {"diff_id": "bad"},
            }[kind]
            policy = replace(
                policy, blobs=(replace(policy.blobs[0], **changes),) + policy.blobs[1:]
            )
    else:
        if kind == "file-duplicate":
            policy = replace(policy, files=policy.files + (policy.files[0],))
        else:
            changes = {
                "file-path": {"path": "../../outside"},
                "file-size": {"size": 4194305},
                "file-hash": {"sha256": "bad"},
            }[kind]
            policy = replace(
                policy, files=(replace(policy.files[0], **changes),) + policy.files[1:]
            )
    calls = []
    with pytest.raises(PreparationError):
        fetch_packaged_payload(
            tmp_path / "out", policy, allow_download=True, transport=mock_transport(blobs, calls)
        )
    assert calls == [] and not (tmp_path / "out").exists()


def test_interrupted_later_blob_rolls_back_and_explicit_retry_recovers(tmp_path):
    policy, blobs, _ = vectors()
    output = tmp_path / "out"
    count = 0

    def fail_later(request):
        nonlocal count
        count += 1
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "synthetic-private-token"})
        if count >= 3:
            raise httpx.ReadError("SYNTHETIC-PRIVATE-INTERRUPTION", request=request)
        raw = blobs["payload.tar.gz"]
        return httpx.Response(200, content=raw)

    with pytest.raises(PreparationError) as error:
        fetch_packaged_payload(
            output, policy, allow_download=True, transport=httpx.MockTransport(fail_later)
        )
    assert not output.exists() and "SYNTHETIC-PRIVATE" not in str(error.value)
    assert not any(p.name.startswith(".rf") for p in tmp_path.iterdir())
    assert (
        fetch_packaged_payload(
            output, policy, allow_download=True, transport=mock_transport(blobs, [])
        )
        == output
    )


@pytest.mark.parametrize("target", [CLIENT, COOKIE_PATH])
def test_compiled_map_must_correspond_to_verified_original_source(tmp_path, target):
    policy, blobs, contents = vectors()
    original = TS if target == CLIENT else COOKIE_TS
    body = (
        BODY
        if target == CLIENT
        else b"// Original synthetic compiled helper\nexports.cookie='synthetic';\n"
    )
    name = "server-api-client.ts" if target == CLIENT else "cookie.ts"
    contents[target] = mapped(body, name, original + b"unreviewed source")
    policy = replace(
        policy,
        files=tuple(
            replace(f, size=len(contents[target]), sha256=digest(contents[target]))
            if f.path == target
            else f
            for f in policy.files
        ),
    )
    policy, blobs = altered_blob(policy, blobs, tar_bytes(list(contents.items())))
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, output, policy, source_lock)
    assert not output.exists()


def test_wrong_body_identity_and_expected_corrected_identity_refuse(tmp_path):
    policy, blobs, _ = vectors()
    cache, source, source_lock, output = prepare_fixture(tmp_path, policy, blobs)
    for wrong in [replace(policy, body_sha256="0" * 64), replace(policy, patched_sha256="0" * 64)]:
        with pytest.raises(PreparationError):
            prepare_packaged_client(cache, source, output, wrong, source_lock)
        assert not output.exists()


def test_replaceable_output_parent_refused_without_changing_permissions(tmp_path):
    policy, blobs, _ = vectors()
    cache, source, source_lock, _ = prepare_fixture(tmp_path, policy, blobs)
    parent = tmp_path / "replaceable"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, parent / "out", policy, source_lock)
    assert parent.stat().st_mode & 0o777 == 0o777 and not (parent / "out").exists()


@pytest.mark.parametrize(
    "location",
    [
        "http://production.cloudfront.docker.com/blob",
        "https://production.cloudfront.docker.com:444/blob",
        "https://user:pass@production.cloudfront.docker.com/blob",
        "https://production.cloudfront.docker.com.evil.invalid/blob",
    ],
)
def test_cdn_redirect_must_have_exact_https_origin_without_userinfo(tmp_path, location):
    policy, _, _ = vectors()
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "synthetic-private-token"})
        return httpx.Response(302, headers={"Location": location})

    with pytest.raises(PreparationError):
        fetch_packaged_payload(
            tmp_path / "out", policy, allow_download=True, transport=httpx.MockTransport(respond)
        )
    assert len(calls) == 2 and not (tmp_path / "out").exists()


def test_redirect_loop_is_bounded_and_removes_auth_on_each_cdn_hop(tmp_path):
    policy, _, _ = vectors()
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "synthetic-private-token"})
        if request.url.host == "production.cloudfront.docker.com":
            assert "authorization" not in request.headers
        return httpx.Response(
            307,
            headers={
                "Location": "https://production.cloudfront.docker.com/loop?synthetic-private-signature"
            },
        )

    with pytest.raises(PreparationError) as error:
        fetch_packaged_payload(
            tmp_path / "out", policy, allow_download=True, transport=httpx.MockTransport(respond)
        )
    assert 2 < len(calls) <= 10
    assert "synthetic-private" not in str(error.value)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "value",
    [
        b"not-base64",
        base64.b64encode(b"not json"),
        base64.b64encode(
            json.dumps(
                {"version": 2, "sources": ["server-api-client.ts"], "sourcesContent": [TS.decode()]}
            ).encode()
        ),
        base64.b64encode(
            json.dumps(
                {"version": 3, "sources": ["server-api-client.ts"], "sourcesContent": []}
            ).encode()
        ),
    ],
)
def test_invalid_final_inline_source_map_refuses(value):
    raw = BODY + MARKER + value + b"\n"
    with pytest.raises(PreparationError):
        patch_packaged_client(raw, digest(raw))


def test_cli_default_fetch_has_no_auth_or_network_side_effect(tmp_path, monkeypatch, capsys):
    from scripts import wazuh_packaged

    monkeypatch.setattr(
        httpx, "Client", lambda *args, **kwargs: pytest.fail("implicit HTTP client")
    )
    output = tmp_path / "out"
    assert wazuh_packaged.main(["fetch", "--output", str(output)]) == 1
    value = json.loads(capsys.readouterr().out)
    assert value["prepared"] is False and value["ready"] is False
    assert not output.exists()


def test_cli_prepare_error_does_not_print_private_blob_or_source(tmp_path, monkeypatch, capsys):
    from scripts import wazuh_packaged

    policy, blobs, _ = vectors()
    cache, source, _, output = prepare_fixture(tmp_path, policy, blobs)
    (cache / "payload.tar.gz").write_bytes(b"SYNTHETIC PRIVATE BLOB CONTENT")
    monkeypatch.setattr(wazuh_packaged, "load_packaged_lock", lambda: policy)
    monkeypatch.setattr(
        httpx, "Client", lambda *args, **kwargs: pytest.fail("prepare must remain offline")
    )
    assert (
        wazuh_packaged.main(
            [
                "prepare",
                "--cache",
                str(cache),
                "--source-bundle",
                str(source),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert "PRIVATE BLOB" not in captured.out + captured.err
    assert json.loads(captured.out)["prepared"] is False
    assert not output.exists()


@pytest.mark.parametrize("directory", [CLIENT, CLIENT + "/nested"])
def test_review_later_directory_cannot_replace_selected_file(tmp_path, directory):
    policy, blobs, _ = vectors()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        info = tarfile.TarInfo(directory)
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    expanded = raw.getvalue()
    changed = gzip.compress(expanded, mtime=0)
    blobs["post-10.tar.gz"] = changed
    policy = replace(
        policy,
        blobs=(
            policy.blobs[0],
            BlobSpec("post-10.tar.gz", len(changed), digest(changed), digest(expanded)),
        )
        + policy.blobs[2:],
    )
    cache = cache_material(tmp_path, blobs)
    source, source_lock = source_material(tmp_path)
    with pytest.raises(PreparationError):
        prepare_packaged_client(cache, source, tmp_path / "out", policy, source_lock)
    assert not (tmp_path / "out").exists()


def test_review_growing_cached_blob_stops_at_declared_size_plus_one(tmp_path, monkeypatch):
    from responseforge.integrations.wazuh import packaged_client as module

    policy, blobs, _ = vectors()
    cache = cache_material(tmp_path, blobs)
    target = cache / "payload.tar.gz"
    original = module.os.fdopen
    observed = {"calls": 0, "bytes": 0}

    class Growing:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            observed["calls"] += 1
            if observed["calls"] > 2:
                raise AssertionError("Growing source was read beyond its bounded inspection")
            data = self.stream.read(size)
            observed["bytes"] += len(data)
            with target.open("ab") as writer:
                writer.write(b"x" * policy.blobs[0].size)
            return data

    monkeypatch.setattr(module.os, "fdopen", lambda fd, mode: Growing(original(fd, mode)))
    with pytest.raises(PreparationError):
        with module._blob(cache, policy.blobs[0]):
            pytest.fail("Changed blob was trusted")
    assert observed["bytes"] <= policy.blobs[0].size + 1


def test_review_post_hash_empty_gzip_growth_stays_compressed_bounded(tmp_path, monkeypatch):
    from responseforge.integrations.wazuh import packaged_client as module

    policy, blobs, _ = vectors()
    cache = cache_material(tmp_path, blobs)
    target = cache / "payload.tar.gz"
    original = module.os.fdopen
    observed = {"second_pass": False, "bytes": 0}

    class GrowingGzip:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def seek(self, offset, whence=0):
            observed["second_pass"] = True
            return self.stream.seek(offset, whence)

        def read(self, size):
            data = self.stream.read(size)
            if observed["second_pass"]:
                observed["bytes"] += len(data)
                if observed["bytes"] > policy.blobs[0].size + 1:
                    raise AssertionError("Second pass consumed post-hash compressed growth")
                with target.open("ab") as writer:
                    writer.write(gzip.compress(b"", mtime=0))
            return data

    monkeypatch.setattr(module.os, "fdopen", lambda fd, mode: GrowingGzip(original(fd, mode)))
    with pytest.raises(PreparationError):
        with module._blob(cache, policy.blobs[0]) as stream:
            with gzip.GzipFile(fileobj=stream) as reader:
                while reader.read(1024):
                    pass
    assert observed["bytes"] <= policy.blobs[0].size + 1
