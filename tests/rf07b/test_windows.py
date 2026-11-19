"""Private artifact preparation only; no native Windows installation is asserted."""

import hashlib
import json
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from responseforge.integrations.wazuh.preparation_models import MSI_NAME, MSI_SHA512, MSI_URL
from responseforge.integrations.wazuh.security import PreparationError
from responseforge.integrations.wazuh.windows import prepare_windows
from tests.rf07b.helpers import windows_config


def test_manifest_and_script_bind_exact_target_trust_and_private_material(tmp_path, material):
    config = windows_config(material)
    output = tmp_path.resolve() / "bundle"
    result = prepare_windows(config, output)
    raw = (output / "bundle.json").read_bytes()
    manifest = json.loads(raw)
    assert manifest["target_machine"] == "RF07-WIN" and manifest["agent_name"] == "RF07-WIN"
    assert manifest["manager_host"] == "10.77.0.10"
    assert (
        manifest["signer_subject"] == config.signer_subject
        and manifest["signer_thumbprint"] == config.signer_thumbprint
    )
    assert manifest["artifact"] == {"filename": MSI_NAME, "url": MSI_URL, "sha512": MSI_SHA512}
    assert (
        manifest["enrolled"]
        is manifest["verified_live"]
        is manifest["windows_runtime_qualified"]
        is False
    )
    assert result["prepared"] is True and result["msi_included"] is False
    assert (
        result["enrolled"]
        is result["verified_live"]
        is result["windows_runtime_qualified"]
        is False
    )
    assert result["manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    script = (output / "Install.ps1").read_bytes()
    assert hashlib.sha256(raw).hexdigest().encode() in script
    assert result["script_sha256"] == hashlib.sha256(script).hexdigest()
    for name, source in zip(
        ("root-ca.pem", "agent-cert.pem", "agent-key.pem"), material, strict=True
    ):
        assert (output / name).read_bytes() == source.read_bytes()
        assert manifest["material"][name] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    # These are artifact checks, not proof of native ACL/Authenticode/MSI behavior.
    assert b"-----BEGIN PRIVATE KEY-----" not in script
    assert b"WAZUH_REGISTRATION_PASSWORD" not in script
    assert b"Invoke-Expression" not in script


def test_existing_bundle_is_immutable_and_conflict_does_not_delete_source(tmp_path, material):
    config = windows_config(material)
    output = tmp_path.resolve() / "bundle"
    prepare_windows(config, output)
    original = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(PreparationError):
        prepare_windows(config.model_copy(update={"manager_host": "10.77.0.11"}), output)
    assert {p.name: p.read_bytes() for p in output.iterdir()} == original
    assert all(path.exists() for path in material)


def test_concurrent_preparation_cannot_replace_a_published_bundle(tmp_path, material):
    config = windows_config(material)
    output = tmp_path.resolve() / "bundle"

    def prepare(_):
        try:
            return prepare_windows(config, output)["prepared"]
        except PreparationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(prepare, range(2)))
    assert results.count(True) == 1 and results.count(False) == 1
    manifest = json.loads((output / "bundle.json").read_text())
    assert (
        manifest["material"]["agent-key.pem"]
        == hashlib.sha256(material[2].read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    "kind", ["ca", "certificate", "key", "key-mode", "key-link", "output-link"]
)
def test_unsafe_or_mismatched_material_never_publishes_partial_bundle(tmp_path, material, kind):
    root = tmp_path.resolve()
    ca, cert, key = material
    config = windows_config(material)
    bad = root / "bad"
    bad.write_bytes(b"ORIGINAL SYNTHETIC INVALID TLS MATERIAL")
    bad.chmod(0o600)
    output = root / "bundle"
    if kind == "ca":
        config = config.model_copy(update={"ca_file": str(bad)})
    elif kind == "certificate":
        config = config.model_copy(update={"agent_certificate_file": str(bad)})
    elif kind == "key":
        config = config.model_copy(update={"agent_key_file": str(bad)})
    elif kind == "key-mode":
        bad.write_bytes(key.read_bytes())
        bad.chmod(0o644)
        config = config.model_copy(update={"agent_key_file": str(bad)})
    elif kind == "key-link":
        linked = root / "key-link"
        linked.symlink_to(key)
        config = config.model_copy(update={"agent_key_file": str(linked)})
    else:
        elsewhere = root / "elsewhere"
        elsewhere.mkdir()
        output.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(PreparationError):
        prepare_windows(config, output)
    if kind != "output-link":
        assert not output.exists()


def test_encrypted_key_refuses_without_prompt_or_partial_publication(tmp_path, material):
    key = tmp_path.resolve() / "encrypted.key"
    key.write_bytes(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC-PRIVATE\n-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    key.chmod(0o600)
    config = windows_config(material, agent_key_file=str(key))
    with pytest.raises(PreparationError) as captured:
        prepare_windows(config, tmp_path.resolve() / "bundle")
    assert "SYNTHETIC-PRIVATE" not in str(captured.value)
    assert not (tmp_path.resolve() / "bundle").exists()


def test_unverified_local_msi_never_enters_a_prepared_bundle(tmp_path, material):
    fake = tmp_path.resolve() / MSI_NAME
    fake.write_bytes(b"ORIGINAL SYNTHETIC DATA, NOT A SIGNED MSI")
    fake.chmod(0o600)
    with pytest.raises(PreparationError):
        prepare_windows(windows_config(material), tmp_path.resolve() / "bundle", msi_path=fake)
    assert not (tmp_path.resolve() / "bundle").exists()
    assert fake.exists()
