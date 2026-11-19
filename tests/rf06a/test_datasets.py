"""Independent selective acquisition, integrity and retention tests."""

import os

import httpx
import pytest
from pydantic import ValidationError

from responseforge.dataset_contracts import DatasetArtifact
from responseforge.datasets import fetch_artifact
from responseforge.replay import ReplayError
from tests.rf06a.helpers import LICENSE, REVISION, artifact, event


def transport_for(entry, raw, requests, *, source_response=None, license_bytes=LICENSE):
    def respond(request):
        requests.append(request)
        if str(request.url) == entry.license_url:
            return httpx.Response(200, content=license_bytes)
        assert str(request.url) == entry.download_url
        return source_response or httpx.Response(200, content=raw)

    return httpx.MockTransport(respond)


def test_selective_verified_acquisition_publishes_original_private_bundle(tmp_path):
    raw = event().encode()
    entry = artifact(raw)
    seen = []
    output = fetch_artifact(
        entry, tmp_path / "private", opt_in=True, transport=transport_for(entry, raw, seen)
    )
    assert output == tmp_path / "private" / entry.artifact_id / "source.xml"
    assert output.read_bytes() == raw
    assert (output.parent / "LICENSE").read_bytes() == LICENSE
    assert (
        DatasetArtifact.model_validate_json((output.parent / "manifest.json").read_bytes()) == entry
    )
    assert {str(r.url) for r in seen} == {entry.license_url, entry.download_url}
    assert len(seen) == 2
    assert os.stat(output.parent).st_mode & 0o077 == 0
    assert not any("authorization" in r.headers for r in seen)


def test_no_opt_in_refuses_before_network_or_filesystem(tmp_path):
    entry = artifact(event().encode())
    calls = []
    root = tmp_path / "must-not-exist"
    with pytest.raises(ReplayError):
        fetch_artifact(entry, root, transport=httpx.MockTransport(lambda r: calls.append(r)))
    assert calls == [] and not root.exists()


@pytest.mark.parametrize("opt_in", [1, "true", None])
def test_opt_in_requires_exact_true(tmp_path, opt_in):
    with pytest.raises(ReplayError):
        fetch_artifact(artifact(event().encode()), tmp_path / "private", opt_in=opt_in)
    assert not (tmp_path / "private").exists()


def test_verified_bundle_reuses_offline_and_still_requires_opt_in(tmp_path):
    raw = event().encode()
    entry = artifact(raw)
    root = tmp_path / "private"
    output = fetch_artifact(entry, root, opt_in=True, transport=transport_for(entry, raw, []))
    calls = []
    unused = httpx.MockTransport(lambda r: calls.append(r))
    assert fetch_artifact(entry, root, opt_in=True, transport=unused) == output
    assert calls == []
    with pytest.raises(ReplayError):
        fetch_artifact(entry, root, transport=unused)
    assert output.read_bytes() == raw and calls == []


@pytest.mark.parametrize("kind", ["size", "hash", "license", "status", "redirect", "encoding"])
def test_failed_transport_or_integrity_leaves_no_published_artifact(tmp_path, kind):
    raw = event().encode()
    entry = artifact(raw)
    response = None
    license_bytes = LICENSE
    if kind == "size":
        response = httpx.Response(200, content=raw + b"oversize")
    elif kind == "hash":
        response = httpx.Response(200, content=b"X" * len(raw))
    elif kind == "license":
        license_bytes = b"Different license"
    elif kind == "status":
        response = httpx.Response(503, content=b"SECRET")
    elif kind == "redirect":
        response = httpx.Response(302, headers={"location": "https://other.example/SECRET"})
    else:
        response = httpx.Response(200, headers={"content-encoding": "identity,bogus"}, content=raw)
    calls = []
    root = tmp_path / "private"
    with pytest.raises(ReplayError) as captured:
        fetch_artifact(
            entry,
            root,
            opt_in=True,
            transport=transport_for(
                entry, raw, calls, source_response=response, license_bytes=license_bytes
            ),
        )
    assert "SECRET" not in str(captured.value)
    assert not (root / entry.artifact_id).exists()
    assert len(calls) <= 2


def test_network_error_does_not_retry_or_publish(tmp_path):
    raw = event().encode()
    entry = artifact(raw)
    calls = []

    def fail(request):
        calls.append(request)
        raise httpx.ConnectError("SECRET private error", request=request)

    with pytest.raises(ReplayError) as captured:
        fetch_artifact(
            entry, tmp_path / "private", opt_in=True, transport=httpx.MockTransport(fail)
        )
    assert len(calls) == 1
    assert "SECRET" not in str(captured.value)
    assert not (tmp_path / "private" / entry.artifact_id).exists()


def test_conflicting_existing_bundle_is_preserved(tmp_path):
    raw = event().encode()
    entry = artifact(raw)
    bundle = tmp_path / "private" / entry.artifact_id
    bundle.mkdir(parents=True)
    source = bundle / "source.xml"
    source.write_bytes(b"unrelated preserved bytes")
    with pytest.raises(ReplayError):
        fetch_artifact(entry, bundle.parent, opt_in=True, transport=transport_for(entry, raw, []))
    assert source.read_bytes() == b"unrelated preserved bytes"


@pytest.mark.parametrize("where", ["root", "bundle", "source"])
def test_symlink_output_or_parent_is_refused(tmp_path, where):
    raw = event().encode()
    entry = artifact(raw)
    destination = tmp_path / "unrelated"
    destination.mkdir()
    root = tmp_path / "private"
    if where == "root":
        root.symlink_to(destination, target_is_directory=True)
    elif where == "bundle":
        root.mkdir()
        (root / entry.artifact_id).symlink_to(destination, target_is_directory=True)
    else:
        bundle = root / entry.artifact_id
        bundle.mkdir(parents=True)
        target = destination / "original"
        target.write_text("preserve")
        (bundle / "source.xml").symlink_to(target)
    with pytest.raises(ReplayError):
        fetch_artifact(entry, root, opt_in=True, transport=transport_for(entry, raw, []))
    if where == "source":
        assert (destination / "original").read_text() == "preserve"


@pytest.mark.parametrize(
    "field,value",
    [
        ("revision", "main"),
        ("revision", "A" * 40),
        ("path", "../outside"),
        ("path", "/absolute"),
        ("path", "datasets/a%2fb"),
        ("path", "datasets/a?secret"),
        ("path", "datasets/a#fragment"),
        ("path", r"datasets\a"),
        ("path", "datasets//a"),
        ("path", "datasets/./a"),
        ("size_bytes", True),
        ("size_bytes", 0),
        ("size_bytes", 1048577),
        ("sha256", "A" * 64),
        ("artifact_id", "../unsafe"),
        ("format", "evtx"),
    ],
)
def test_manifest_rejects_unsafe_or_mutable_identity(field, value):
    entry = artifact(event().encode())
    with pytest.raises(ValidationError):
        DatasetArtifact.model_validate(entry.model_dump(mode="json") | {field: value})


@pytest.mark.parametrize("rights", [None, {}, {"license_id": "unknown"}])
def test_missing_unreviewed_rights_refuse(rights):
    with pytest.raises(ValidationError):
        artifact(event().encode(), rights=rights)


def test_copy_bypass_revalidated_before_network(tmp_path):
    entry = artifact(event().encode()).model_copy(update={"path": "../SECRET"})
    calls = []
    with pytest.raises(ReplayError):
        fetch_artifact(
            entry,
            tmp_path / "private",
            opt_in=True,
            transport=httpx.MockTransport(lambda r: calls.append(r)),
        )
    assert calls == []


def test_artifact_urls_bind_one_fixed_repository_and_revision():
    entry = artifact(event().encode())
    assert entry.source_url == f"https://github.com/splunk/attack_data/blob/{REVISION}/{entry.path}"
    assert entry.download_url == (
        f"https://media.githubusercontent.com/media/splunk/attack_data/{REVISION}/{entry.path}"
    )
    assert (
        entry.license_url
        == f"https://raw.githubusercontent.com/splunk/attack_data/{REVISION}/LICENSE"
    )
