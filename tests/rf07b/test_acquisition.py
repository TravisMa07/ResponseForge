"""Fixed artifact acquisition controls; synthetic vectors are not real MSI proof."""

import hashlib

import httpx
import pytest

import responseforge.integrations.wazuh.acquisition as acquisition
from responseforge.integrations.wazuh.preparation_models import MSI_NAME, MSI_SHA512, MSI_URL
from responseforge.integrations.wazuh.security import PreparationError


def test_official_artifact_metadata_is_fixed_and_not_a_native_signature_claim():
    assert MSI_URL == "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.10-1.msi"
    assert MSI_NAME == "wazuh-agent-4.14.10-1.msi"
    assert (
        MSI_SHA512
        == "54f83c01dd35573d8501eab553ebdd72ad4de75383636efb25f01e782521e83281065f8075a369239c13a5a5e3f3599a754eb3204ff56cfce2b2afd9ae911152"
    )


@pytest.mark.parametrize("opt_in", [False, "true", 1, None])
def test_download_requires_literal_opt_in_before_any_output_or_network(tmp_path, opt_in):
    output = tmp_path.resolve() / "acquired"
    with pytest.raises(PreparationError):
        acquisition.fetch_msi(
            output,
            allow_download=opt_in,
            transport=httpx.MockTransport(lambda r: pytest.fail("implicit download")),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "code,headers,raw",
    [
        (302, {"Location": "https://attacker.invalid"}, b""),
        (500, {}, b"private remote failure"),
        (200, {"Content-Encoding": "gzip"}, b"encoded"),
        (200, {"Content-Length": "67108865"}, b""),
        (200, {"Content-Length": "0"}, b""),
        (200, {"Content-Length": "BAD"}, b""),
        (200, {}, b"ORIGINAL SYNTHETIC NON-MSI BYTES"),
    ],
)
def test_untrusted_artifact_response_never_publishes_or_follows_redirect(
    tmp_path, code, headers, raw
):
    calls = []
    output = tmp_path.resolve() / "artifact"
    transport = httpx.MockTransport(
        lambda request: (
            calls.append(request),
            httpx.Response(code, headers=headers, stream=httpx.ByteStream(raw)),
        )[1]
    )
    with pytest.raises(PreparationError) as captured:
        acquisition.fetch_msi(output, allow_download=True, transport=transport)
    assert len(calls) == 1 and str(calls[0].url) == MSI_URL
    assert not output.exists() and "remote failure" not in str(captured.value)


def test_generic_atomic_acquisition_with_original_vector_does_not_claim_real_msi(
    tmp_path, monkeypatch
):
    # Trusted checksum substitution isolates generic publication/reuse behavior.
    # Production metadata is independently fixed above; this is not an MSI.
    raw = b"ORIGINAL SYNTHETIC ACQUISITION VECTOR; NOT AN MSI"
    monkeypatch.setattr(acquisition, "MSI_SHA512", hashlib.sha512(raw).hexdigest())
    output = tmp_path.resolve() / "artifact"
    calls = []
    transport = httpx.MockTransport(
        lambda request: (
            calls.append(request),
            httpx.Response(
                200, headers={"Content-Length": str(len(raw))}, stream=httpx.ByteStream(raw)
            ),
        )[1]
    )
    first = acquisition.fetch_msi(output, allow_download=True, transport=transport)
    assert first == output / MSI_NAME and first.read_bytes() == raw
    second = acquisition.fetch_msi(output, allow_download=True, transport=transport)
    assert second == first and len(calls) == 1
    first.write_bytes(raw + b"tampered")
    with pytest.raises(PreparationError):
        acquisition.fetch_msi(output, allow_download=True, transport=transport)
    assert len(calls) == 1


def test_http_failure_does_not_publish_partial_artifact(tmp_path):
    output = tmp_path.resolve() / "artifact"

    class Interrupted(httpx.SyncByteStream):
        def __iter__(self):
            yield b"original partial bytes"
            raise httpx.ReadError("private interrupt")

    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=Interrupted()))
    with pytest.raises(PreparationError):
        acquisition.fetch_msi(output, allow_download=True, transport=transport)
    assert not output.exists()
