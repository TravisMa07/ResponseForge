"""Original synthetic Windows event text, not copied dataset telemetry."""

import hashlib
from xml.sax.saxutils import escape

from responseforge.dataset_contracts import DatasetArtifact

REVISION = "a" * 40
LICENSE = b"Original synthetic license bytes for integrity tests only.\n"
STAMP = "2026-01-01T12:00:00.123456700Z"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def event(record_id="31", stamp=STAMP, computer="original.example", fields=None, namespace=True):
    data = (
        {
            "UtcTime": "2026-01-01 12:00:00.120",
            "Image": r"C:\Windows\powershell.exe",
            "ProcessId": "42",
            "ProcessGuid": "{00000000-0000-0000-0000-000000000042}",
            "ParentProcessGuid": "{00000000-0000-0000-0000-000000000041}",
            "CommandLine": "powershell.exe -WindowStyle Hidden -EncodedCommand INERT",
            "User": "original\\user",
        }
        if fields is None
        else fields
    )
    ns = ' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"' if namespace else ""
    encoded = "".join(f'<Data Name="{escape(k)}">{escape(v)}</Data>' for k, v in data.items())
    return (
        f'<Event{ns}><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f'<EventID>1</EventID><TimeCreated SystemTime="{stamp}"/>'
        f"<EventRecordID>{record_id}</EventRecordID><Channel>{CHANNEL}</Channel>"
        f"<Computer>{computer}</Computer></System><EventData>{encoded}</EventData></Event>"
    )


def artifact(raw: bytes, **changes):
    document = {
        "artifact_id": "original-sysmon",
        "revision": REVISION,
        "path": "datasets/original/sysmon.log",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "format": "sysmon-xml",
        "rights": {
            "license_id": "Apache-2.0",
            "license_sha256": hashlib.sha256(LICENSE).hexdigest(),
            "reviewed_paths": ["LICENSE", "README.md", "datasets/original/data.yml"],
            "review_note": "Synthetic test declaration; no third-party data or rights assertion.",
        },
    }
    return DatasetArtifact.model_validate(document | changes)
