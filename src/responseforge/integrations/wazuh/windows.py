"""Prepare a private, integrity-bound Windows package without executing it."""

import hashlib
import json
import os
import ssl
from pathlib import Path

from responseforge.integrations.wazuh.preparation_models import (
    MSI_NAME,
    MSI_SHA512,
    MSI_URL,
    WindowsBundleConfig,
)
from responseforge.integrations.wazuh.security import (
    PreparationError,
    atomic_directory,
    read_file,
    verify_file,
)

_TEMPLATE = Path(__file__).with_name("Install.ps1")
_MATERIAL = ("root-ca.pem", "agent-cert.pem", "agent-key.pem")


def _write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_windows(
    config: WindowsBundleConfig, output: Path, *, msi_path: Path | None = None
) -> dict[str, object]:
    """Publish an all-or-nothing package; never fetch, install or enroll.

    Hash verification of an optional local MSI is not native signature proof.
    Authenticode and all Windows-only mutation checks stay inside the explicitly
    invoked installer, which is separately unqualified until tested on Windows.
    """
    try:
        trusted = WindowsBundleConfig.model_validate(config.model_dump(mode="json", warnings=False))
        if not trusted.signer_subject.strip():
            raise ValueError("Independent signer subject required")
        material = (
            read_file(Path(trusted.ca_file), 65536),
            read_file(Path(trusted.agent_certificate_file), 65536),
            read_file(Path(trusted.agent_key_file), 65536, private=True),
        )
        # Encrypted inputs are unsupported. Suppress OpenSSL's interactive
        # passphrase fallback as well as rejecting its recognizable PEM headers.
        if b"ENCRYPTED" in material[2]:
            raise ValueError("Encrypted private key unsupported")
        artifact = None if msi_path is None else verify_file(Path(msi_path), MSI_SHA512)
        manifest: dict[str, object] = {
            "schema_version": "1.0",
            "bundle_version": "rf07b-windows-v1",
            "target_machine": trusted.target_machine,
            "agent_name": trusted.agent_name,
            "manager_host": trusted.manager_host,
            "signer_subject": trusted.signer_subject,
            "signer_thumbprint": trusted.signer_thumbprint,
            "artifact": {"filename": MSI_NAME, "url": MSI_URL, "sha512": MSI_SHA512},
            "material": {
                name: hashlib.sha256(value).hexdigest()
                for name, value in zip(_MATERIAL, material, strict=True)
            },
            "verified_live": False,
            "enrolled": False,
            "windows_runtime_qualified": False,
        }
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        manifest_hash = hashlib.sha256(encoded).hexdigest()
        template = read_file(_TEMPLATE, 131072).decode("utf-8")
        if template.count("__MANIFEST_SHA256__") != 1:
            raise ValueError("Installer template identity unavailable")
        script = template.replace("__MANIFEST_SHA256__", manifest_hash).encode("utf-8")
        with atomic_directory(Path(output)) as staging:
            for name, value in zip(_MATERIAL, material, strict=True):
                _write_private(staging / name, value)
            # Validate only checked bytes already copied into the new private
            # stage, rather than reopening possibly replaced source paths.
            context = ssl.create_default_context(cadata=material[0].decode("ascii"))
            context.load_cert_chain(
                certfile=staging / "agent-cert.pem",
                keyfile=staging / "agent-key.pem",
                password=lambda: b"",
            )
            _write_private(staging / "bundle.json", encoded)
            _write_private(staging / "Install.ps1", script)
            if artifact is not None:
                _write_private(staging / MSI_NAME, artifact)
        return {
            "prepared": True,
            "manifest_sha256": manifest_hash,
            "script_sha256": hashlib.sha256(script).hexdigest(),
            "msi_included": artifact is not None,
            "contains_private_material": True,
            "verified_live": False,
            "enrolled": False,
            "windows_runtime_qualified": False,
        }
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
        raise PreparationError("Windows package preparation refused") from None
