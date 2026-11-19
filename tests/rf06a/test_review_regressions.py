"""Strict structure and failure preservation from independent artifact review."""

import httpx
import pytest

from responseforge.datasets import fetch_artifact
from responseforge.replay import ReplayError
from responseforge.replay.sysmon import normalize_sysmon
from tests.rf06a.helpers import LICENSE, artifact, event


@pytest.mark.parametrize("tag", ["Event", "System", "EventData"])
def test_mixed_structural_text_is_quarantined(tag):
    raw = event().replace(f"<{tag}>", f"<{tag}>UNEXPECTED", 1).encode()
    # Event carries a namespace attribute in the fixture.
    if tag == "Event":
        raw = event(namespace=False).replace("<Event>", "<Event>UNEXPECTED", 1).encode()
    batch = normalize_sysmon(raw, artifact=artifact(raw), scenario_id="original")
    assert not batch.events
    assert [item.code for item in batch.quarantine] == ["invalid_schema"]


def test_unknown_length_stream_overflow_then_explicit_corrected_acquisition(tmp_path):
    raw = event().encode()
    entry = artifact(raw)

    class Oversized(httpx.SyncByteStream):
        def __iter__(self):
            yield raw
            yield b"EXCESS"

    def overflow(request):
        if request.url == entry.license_url:
            return httpx.Response(200, content=LICENSE)
        return httpx.Response(200, stream=Oversized())

    with pytest.raises(ReplayError):
        fetch_artifact(entry, tmp_path, opt_in=True, transport=httpx.MockTransport(overflow))
    assert not list(tmp_path.iterdir())

    def corrected(request):
        return httpx.Response(200, content=LICENSE if request.url == entry.license_url else raw)

    source = fetch_artifact(entry, tmp_path, opt_in=True, transport=httpx.MockTransport(corrected))
    assert source.read_bytes() == raw


@pytest.mark.parametrize("fault", ["short-body", "read-timeout"])
def test_stream_failure_preserves_empty_output_root(tmp_path, fault):
    raw = event().encode()
    entry = artifact(raw)

    class FailedStream(httpx.SyncByteStream):
        def __iter__(self):
            yield raw[:10]
            if fault == "read-timeout":
                raise httpx.ReadTimeout("PRIVATE source SECRET")

    def failed(request):
        if request.url == entry.license_url:
            return httpx.Response(200, content=LICENSE)
        return httpx.Response(200, headers={"Content-Length": str(len(raw))}, stream=FailedStream())

    with pytest.raises(ReplayError) as captured:
        fetch_artifact(entry, tmp_path, opt_in=True, transport=httpx.MockTransport(failed))
    assert "SECRET" not in str(captured.value)
    assert not list(tmp_path.iterdir())
