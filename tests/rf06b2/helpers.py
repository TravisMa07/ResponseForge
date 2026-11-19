"""Original synthetic bundles; no downloaded corpus, daemon or network."""

import hashlib
import json
from pathlib import Path

from responseforge.recorded_contracts import RecordedCase, RecordedConfig
from tests.rf06a.helpers import LICENSE
from tests.rf06b.helpers import CHANNEL, GUID, artifact, xml_event

QUALIFICATION = "33333333-3333-4333-8333-333333333333"


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def write_bundle(
    root: Path,
    *,
    artifact_id="original-sysmon",
    event_id=1,
    record_id="31",
    fields=None,
    computer="original.example",
):
    root.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = {
            "Image": "powershell.exe",
            "ProcessId": "42",
            "ProcessGuid": GUID,
            "CommandLine": "powershell.exe -WindowStyle Hidden -enc INERT",
        }
    raw = xml_event(event_id, record_id, fields=fields, computer=computer).encode()
    entry = artifact(raw, artifact_id=artifact_id)
    bundle = root / artifact_id
    bundle.mkdir()
    (bundle / "source.xml").write_bytes(raw)
    (bundle / "LICENSE").write_bytes(LICENSE)
    (bundle / "manifest.json").write_bytes(canonical(entry.model_dump(mode="json")))
    return entry


def config_for(root: Path, entry, *, profile="original", scenario=None, mock_path=None):
    scenario = scenario or "rf06-" + profile + "-" + QUALIFICATION
    return RecordedConfig(
        qualification_id=QUALIFICATION,
        cases=(
            RecordedCase(
                profile=profile, artifact=entry, scenario_id=scenario, event_ids=(CHANNEL + ":31",)
            ),
        ),
        bundle_root=str(root),
        mock_path=str(mock_path or root.parent / "recorded.sqlite3"),
    )


def write_prepared_config(root: Path, config):
    document = config.model_dump(mode="json")
    document["bundle_root"] = "/run/responseforge/recorded"
    document["mock_path"] = "/var/lib/responseforge/mock-recorded-" + QUALIFICATION + ".sqlite3"
    (root / "cases.json").write_bytes(canonical(document))
    return hashlib.sha256((root / "cases.json").read_bytes()).hexdigest()


def memory_source(
    *,
    scenario="source-a",
    artifact_id="source-a",
    record_id="31",
    computer="original.example",
    fields=None,
):
    from responseforge.replay.windows import normalize_windows

    if fields is None:
        fields = {
            "Image": "powershell.exe",
            "ProcessId": "42",
            "ProcessGuid": GUID,
            "CommandLine": "powershell.exe -WindowStyle Hidden -enc INERT",
        }
    raw = xml_event(1, record_id, fields=fields, computer=computer).encode()
    entry = artifact(raw, artifact_id=artifact_id)
    return normalize_windows(raw, artifact=entry, scenario_id=scenario)


def qualification_tree(tmp_path):
    from responseforge.recorded_contracts import RecordedCaseManifest
    from tests.rf06b.helpers import OTHER_GUID, task_xml

    root = tmp_path / "qualification-bundles"
    root.mkdir()
    specifications = {
        "powershell": (
            "splunk-powershell-create",
            1,
            {
                "Image": "powershell.exe",
                "ProcessId": "42",
                "ProcessGuid": GUID,
                "CommandLine": "powershell.exe -WindowStyle Hidden -enc INERT",
            },
            1,
            {"Image": "cmd.exe", "ProcessId": "43", "ProcessGuid": OTHER_GUID},
        ),
        "lsass": (
            "splunk-lsass-access",
            10,
            {
                "SourceImage": "mimikatz.exe",
                "SourceProcessId": "42",
                "SourceProcessGUID": GUID,
                "TargetImage": "lsass.exe",
                "TargetProcessId": "500",
                "TargetProcessGUID": OTHER_GUID,
                "GrantedAccess": "0x1010",
            },
            10,
            {"SourceImage": "svchost.exe", "TargetImage": "lsass.exe", "GrantedAccess": "0x1400"},
        ),
        "task": (
            "splunk-task-create",
            4698,
            {
                "TaskName": "\\OriginalTask",
                "SubjectUserName": "creator",
                "TaskContent": task_xml(),
            },
            4698,
            {
                "TaskName": "\\Explorer",
                "SubjectUserName": "creator",
                "TaskContent": task_xml("Explorer.EXE", "/NOUACCHECK"),
            },
        ),
        "note": (
            "splunk-ransom-note",
            11,
            {
                "Image": "powershell.exe",
                "ProcessId": "42",
                "ProcessGuid": GUID,
                "TargetFilename": "C:\\Original\\GetYouFiles.txt",
            },
            1,
            {"Image": "Splunk.exe", "ProcessId": "43", "ProcessGuid": OTHER_GUID},
        ),
        "dns": (
            "splunk-process-dns",
            22,
            {
                "Image": "wscript.exe",
                "ProcessId": "42",
                "ProcessGuid": GUID,
                "QueryName": "pastebin.com",
                "QueryStatus": "0",
            },
            22,
            {
                "Image": "firefox.exe",
                "ProcessId": "43",
                "ProcessGuid": OTHER_GUID,
                "QueryName": "pastebin.com",
                "QueryStatus": "0",
            },
        ),
    }
    artifacts = {}
    selected = {}
    for name, (identity, event_id, positive, negative_id, negative) in specifications.items():
        computer = "recorded-" + name + ".example"
        raw = (
            xml_event(event_id, "31", fields=positive, computer=computer)
            + "\n"
            + xml_event(negative_id, "32", fields=negative, computer=computer)
        ).encode()
        entry = artifact(raw, artifact_id=identity)
        bundle = root / identity
        bundle.mkdir()
        (bundle / "source.xml").write_bytes(raw)
        (bundle / "LICENSE").write_bytes(LICENSE)
        (bundle / "manifest.json").write_bytes(canonical(entry.model_dump(mode="json")))
        artifacts[name] = entry
        selected[name] = ("Security" if event_id == 4698 else CHANNEL) + ":31"
        selected[name + "-negative"] = ("Security" if negative_id == 4698 else CHANNEL) + ":32"
    profiles = ["powershell", "lsass", "task", "note", "dns"]
    profiles += [name + "-negative" for name in profiles]
    profiles += ["denied", "expired", "callback-loss", "task-failure"]
    cases = []
    for profile in profiles:
        family = profile.removesuffix("-negative")
        if family in {"denied", "expired", "callback-loss", "task-failure"}:
            family = "powershell"
        cases.append(
            RecordedCase(
                profile=profile,
                artifact=artifacts[family],
                scenario_id="rf06-" + profile + "-" + QUALIFICATION,
                event_ids=(selected.get(profile, selected[family]),),
            )
        )
    manifest = RecordedCaseManifest(qualification_id=QUALIFICATION, cases=tuple(cases))
    cases_path = tmp_path / "private-cases.json"
    cases_path.write_bytes(canonical(manifest.model_dump(mode="json")))
    catalog_path = tmp_path / "trusted-synthetic-catalog.json"
    catalog_path.write_bytes(
        canonical(
            {
                "schema_version": "1.0",
                "artifacts": [entry.model_dump(mode="json") for entry in artifacts.values()],
            }
        )
    )
    return root, manifest, cases_path, catalog_path


def recorded_file_value(tmp_path):
    from responseforge.replay.registry import load_recorded_sources
    from tests.rf05b.test_runtime import file_config

    root, manifest, _, _ = qualification_tree(tmp_path)
    config = RecordedConfig(
        **manifest.model_dump(mode="python"),
        bundle_root=str(root),
        mock_path=str(tmp_path / "loaded-recorded.sqlite3"),
    )
    value, legacy_world = file_config(tmp_path)
    sources = load_recorded_sources(config, mode="replay")
    endpoints = {entry["endpoint_id"]: entry for entry in value["endpoints"]}
    resources = {
        identity: set(entries) for identity, entries in value["resource_allowlist"].items()
    }
    for source in sources:
        for event in source.events:
            endpoints[event.endpoint.endpoint_id] = event.endpoint.model_dump(mode="json")
            allowed = resources.setdefault(event.endpoint.endpoint_id, set())
            allowed.add("host:" + event.endpoint.endpoint_id)
            if event.fields.get("event_kind") == "process_create" and event.fields.get(
                "process_id"
            ):
                allowed.add("process:" + event.fields["process_id"])
    value["endpoints"] = list(endpoints.values())
    value["resource_allowlist"] = {
        identity: sorted(entries) for identity, entries in resources.items()
    }
    all_resources = set().union(*resources.values())
    for actor in value["credentials"].values():
        actor["endpoint_ids"] = sorted(set(actor["endpoint_ids"]) | set(endpoints))
        if set(actor["roles"]) & {"analyst", "executor", "approver"}:
            actor["resources"] = sorted(set(actor["resources"]) | all_resources)
        if actor["roles"] == ["source"]:
            actor["sources"] = sorted(set(actor["sources"]) | {"splunk-attack-data"})
    value["recorded"] = config.model_dump(mode="json")
    return value, config, sources, legacy_world
