"""Explicit fixed-URL MSI acquisition; byte integrity is not signature proof."""

from pathlib import Path

import httpx

from responseforge.integrations.wazuh.preparation_models import (
    MAX_MSI,
    MSI_NAME,
    MSI_SHA512,
    MSI_URL,
)
from responseforge.integrations.wazuh.security import (
    PreparationError,
    atomic_directory,
    verify_file,
    write_private,
)


def fetch_msi(
    output: Path, *, allow_download: bool = False, transport: httpx.BaseTransport | None = None
) -> Path:
    if allow_download is not True:
        raise PreparationError("Explicit MSI download opt-in required")
    try:
        if output.exists() or output.is_symlink():
            from responseforge.integrations.wazuh.security import private_directory

            private_directory(output)
            if {p.name for p in output.iterdir()} != {MSI_NAME}:
                raise ValueError
            verify_file(output / MSI_NAME, MSI_SHA512)
            return output / MSI_NAME
        with atomic_directory(output) as stage:
            import hashlib

            digest = hashlib.sha512()
            data = bytearray()
            with httpx.Client(
                verify=True,
                follow_redirects=False,
                trust_env=False,
                timeout=30.0,
                transport=transport,
            ) as client:
                with client.stream(
                    "GET", MSI_URL, headers={"Accept-Encoding": "identity"}
                ) as response:
                    if (
                        response.status_code != 200
                        or response.headers.get("content-encoding", "identity").lower()
                        != "identity"
                    ):
                        raise ValueError
                    length = response.headers.get("content-length")
                    if length is not None and (
                        not length.isascii()
                        or not length.isdecimal()
                        or not 1 <= int(length) <= MAX_MSI
                    ):
                        raise ValueError
                    for chunk in response.iter_raw():
                        if len(data) + len(chunk) > MAX_MSI:
                            raise ValueError
                        digest.update(chunk)
                        data.extend(chunk)
                    if (
                        not data
                        or digest.hexdigest() != MSI_SHA512
                        or length is not None
                        and len(data) != int(length)
                    ):
                        raise ValueError
            write_private(stage / MSI_NAME, bytes(data))
        return output / MSI_NAME
    except (OSError, ValueError, httpx.HTTPError):
        raise PreparationError("MSI acquisition refused; no signature or install proof") from None
