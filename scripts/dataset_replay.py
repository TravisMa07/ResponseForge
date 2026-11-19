"""Acquire reviewed selected telemetry or inspect its bounded Event 1 projection."""

import argparse
import json
from pathlib import Path

from responseforge.dataset_contracts import DatasetArtifact
from responseforge.datasets import fetch_artifact
from responseforge.playbooks.assessment import assess
from responseforge.replay import MAX_BYTES, ReplayError, logical_receipt, make_alerts
from responseforge.replay.selection import select_recorded
from responseforge.replay.sysmon import normalize_sysmon
from responseforge.replay.windows import normalize_windows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("fetch", "inspect"))
    parser.add_argument("--catalog", type=Path, default=Path("datasets/catalog.json"))
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--directory", type=Path, default=Path("datasets/downloads"))
    parser.add_argument("--allow-download", action="store_true")
    parser.add_argument("--scenario-id", default="recorded-process-observation")
    parser.add_argument("--event-id", action="append", default=[])
    arguments = parser.parse_args()
    try:
        if arguments.catalog.is_symlink():
            raise ReplayError("Invalid dataset catalog")
        with arguments.catalog.open("rb") as stream:
            catalog_raw = stream.read(MAX_BYTES + 1)
        if len(catalog_raw) > MAX_BYTES:
            raise ReplayError("Dataset catalog exceeds byte limit")
        catalog = json.loads(catalog_raw)
        if set(catalog) != {"schema_version", "artifacts"} or catalog["schema_version"] != "1.0":
            raise ReplayError("Invalid dataset catalog")
        if not isinstance(catalog["artifacts"], list) or not 1 <= len(catalog["artifacts"]) <= 32:
            raise ReplayError("Invalid dataset catalog")
        artifacts = [DatasetArtifact.model_validate(item) for item in catalog["artifacts"]]
        if len({item.artifact_id for item in artifacts}) != len(artifacts):
            raise ReplayError("Duplicate dataset identity")
        selected = next((item for item in artifacts if item.artifact_id == arguments.artifact), None)
        if selected is None:
            raise ReplayError("Unknown dataset identity")
        if arguments.operation == "fetch":
            fetch_artifact(selected, arguments.directory, opt_in=arguments.allow_download)
            print(json.dumps({"artifact_id": selected.artifact_id, "sha256": selected.sha256,
                              "size_bytes": selected.size_bytes, "acquired": True}))
            return 0
        # Inspection never downloads. Read only the explicitly selected retained source.
        source = arguments.directory / selected.artifact_id / "source.xml"
        if source.is_symlink() or any(parent.is_symlink() for parent in source.parents):
            raise ReplayError("Invalid retained dataset path")
        with source.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        normalize = normalize_sysmon if selected.format == "sysmon-xml" else normalize_windows
        batch = normalize(raw, artifact=selected, scenario_id=arguments.scenario_id)
        if arguments.event_id:
            batch = select_recorded(batch, event_ids=tuple(arguments.event_id))
        decisions = []
        if batch.events:
            for alert in make_alerts(batch, ingested_at=logical_receipt(batch)):
                decisions.append({
                    "rule_id": alert.rule_id,
                    "assessments": {
                        kind: assess(kind, batch, alert).disposition
                        for kind in ("process", "persistence", "containment")
                    },
                })
        print(json.dumps({"artifact_id": selected.artifact_id, "sha256": batch.sha256,
                          "events": len(batch.events), "duplicates": batch.duplicates,
                          "selection_count": len(arguments.event_id), "decisions": decisions,
                          "quarantine": [item.model_dump(mode="json") for item in batch.quarantine],
                          "scenario_qualified": False, "verified_live": False}))
        return 0 if batch.events else 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Dataset operation refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
