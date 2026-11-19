"""Offline CLI refusal smoke checks; no downloads or runtime claims."""

import json
import sys

import pytest

from scripts import dataset_replay
from tests.rf06a.helpers import artifact, event


def test_fetch_cli_requires_opt_in_before_output_mutation(tmp_path, monkeypatch, capsys):
    entry = artifact(event().encode())
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps({"schema_version": "1.0", "artifacts": [entry.model_dump(mode="json")]})
    )
    root = tmp_path / "must-not-exist"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dataset_replay.py",
            "fetch",
            "--catalog",
            str(catalog),
            "--artifact",
            entry.artifact_id,
            "--directory",
            str(root),
        ],
    )
    assert dataset_replay.main() == 1
    assert capsys.readouterr().out == "Dataset operation refused\n"
    assert not root.exists()


@pytest.mark.parametrize(
    "content", ["not-json SECRET", "[]", '{"schema_version":"1.0","artifacts":[]}']
)
def test_malformed_catalog_refuses_without_source_content(tmp_path, monkeypatch, capsys, content):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(content)
    monkeypatch.setattr(
        sys,
        "argv",
        ["dataset_replay.py", "inspect", "--catalog", str(catalog), "--artifact", "unknown"],
    )
    assert dataset_replay.main() == 1
    assert capsys.readouterr().out == "Dataset operation refused\n"
