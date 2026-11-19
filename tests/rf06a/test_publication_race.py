"""An unrelated empty directory created during publication must survive."""

from pathlib import Path

import httpx
import pytest

from responseforge.datasets import fetch_artifact
from responseforge.replay import ReplayError
from tests.rf06a.helpers import LICENSE, artifact, event


def test_racing_empty_destination_is_preserved(tmp_path, monkeypatch):
    raw = event().encode()
    entry = artifact(raw)
    destination = tmp_path / entry.artifact_id
    original_exists = Path.exists
    checks = 0
    created_inode = []

    def exists(path):
        nonlocal checks
        if path == destination:
            checks += 1
            if checks == 2:
                path.mkdir()
                created_inode.append(path.stat().st_ino)
                # Another creator won after our absence observation.
                return False
        return original_exists(path)

    def respond(request):
        return httpx.Response(200, content=LICENSE if request.url == entry.license_url else raw)

    monkeypatch.setattr(Path, "exists", exists)
    with pytest.raises(ReplayError):
        fetch_artifact(entry, tmp_path, opt_in=True, transport=httpx.MockTransport(respond))
    assert destination.stat().st_ino == created_inode[0]
    assert not list(destination.iterdir())
    assert list(tmp_path.iterdir()) == [destination]


def test_unsupported_atomic_publication_fails_closed_without_partial_bundle(tmp_path, monkeypatch):
    import responseforge.datasets as module

    raw = event().encode()
    entry = artifact(raw)

    def respond(request):
        return httpx.Response(200, content=LICENSE if request.url == entry.license_url else raw)

    monkeypatch.setattr(module.sys, "platform", "unsupported-test-platform")
    with pytest.raises(ReplayError):
        fetch_artifact(entry, tmp_path, opt_in=True, transport=httpx.MockTransport(respond))
    assert not list(tmp_path.iterdir())
