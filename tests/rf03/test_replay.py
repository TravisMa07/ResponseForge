"""R01-R05: requirement-derived parsing, ordering and replay clock oracles."""

import asyncio
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from responseforge.replay import (
    ReplayError,
    ReplaySource,
    load_replay,
    logical_receipt,
    make_alerts,
)
from tests.rf03.helpers import NOW, event, fixture


def test_source_order_hash_and_receipt_are_preserved(tmp_path: Path) -> None:
    path = fixture(
        tmp_path / "original.jsonl",
        [
            event("later", observed_at="2026-01-01T12:00:10+00:00"),
            event("z-tie"),
            event("a-tie"),
        ],
    )
    batch = load_replay(path, source_id="original")
    assert [x.event_id for x in batch.events] == ["a-tie", "z-tie", "later"]
    assert batch.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert logical_receipt(batch).isoformat() == "2026-01-01T12:00:11+00:00"
    first = make_alerts(batch, ingested_at=NOW)
    second = make_alerts(load_replay(path, source_id="original"), ingested_at=NOW)
    assert first == second
    assert first[0].event_time.isoformat() == "2026-01-01T12:00:00+00:00"
    assert first[0].ingested_at == NOW
    assert first[0].provenance.original_event_ids == ("a-tie", "z-tie", "later")
    assert first[0].provenance.sha256 == batch.sha256
    assert first[0].mode == "replay"


def test_quarantine_exact_lines_and_duplicate_semantics(tmp_path: Path) -> None:
    path = tmp_path / "quarantine.jsonl"
    rows = [
        json.dumps(event()),
        "SECRET-invalid-not-json",
        json.dumps(event("missing", observed_at=None)),
        json.dumps(event()),
        json.dumps(event(fields={"changed": "different"})),
    ]
    path.write_text("\n".join(rows) + "\n")
    batch = load_replay(path, source_id="original")
    assert len(batch.events) == 1
    assert batch.duplicates == 1
    assert [(x.line, x.code) for x in batch.quarantine] == [
        (2, "invalid_json"),
        (3, "invalid_schema"),
        (5, "duplicate_conflict"),
    ]
    assert "SECRET" not in str(batch.quarantine)


@pytest.mark.parametrize(
    "changes",
    [
        {"observed_at": "2026-01-01T12:00:00"},
        {"observed_at": 1767268800},
        {"observed_at": "1767268800"},
        {"unexpected": True},
        {"fields": {"process_id": 42}},
        {"fields": {"key": "x" * 4097}},
    ],
)
def test_ambiguous_or_untrusted_records_quarantined(tmp_path: Path, changes: dict) -> None:
    batch = load_replay(fixture(tmp_path / "bad.jsonl", [event(**changes)]), source_id="original")
    assert not batch.events
    assert [(x.line, x.code) for x in batch.quarantine] == [(1, "invalid_schema")]


def test_json_array_and_blank_jsonl_records(tmp_path: Path) -> None:
    path = tmp_path / "array.json"
    path.write_text(
        json.dumps([event("second", observed_at="2026-01-01T12:00:02Z"), event("first")])
    )
    assert [x.event_id for x in load_replay(path, source_id="original").events] == [
        "first",
        "second",
    ]
    lines = tmp_path / "blank.jsonl"
    lines.write_text("\n" + json.dumps(event()) + "\n\nnot-json\n")
    batch = load_replay(lines, source_id="original")
    assert len(batch.events) == 1 and batch.quarantine[0].line == 4


@pytest.mark.parametrize("kind", ["bytes", "rows", "line", "format"])
def test_resource_limits_refuse_instead_of_truncating(tmp_path: Path, kind: str) -> None:
    path = tmp_path / ("bad.txt" if kind == "format" else "bounded.jsonl")
    if kind == "bytes":
        path.write_bytes(b" " * (1024 * 1024 + 1))
    elif kind == "rows":
        path.write_text((json.dumps(event()) + "\n") * 1001)
    elif kind == "line":
        path.write_text(" " * (16 * 1024 + 1) + "\n")
    else:
        path.write_text(json.dumps(event()))
    with pytest.raises(ReplayError):
        load_replay(path, source_id="original")


@pytest.mark.parametrize(
    "fields,expected",
    [
        (
            {
                "image": "powershell.exe",
                "command_line": "powershell -WindowStyle Hidden -EncodedCommand inert",
            },
            "RF-REPLAY-ENCODED-PS",
        ),
        (
            {
                "image": "POWERSHELL.EXE",
                "command_line": "powershell -WINDOWSTYLE HIDDEN -ENCODEDCOMMAND inert",
            },
            "RF-REPLAY-ENCODED-PS",
        ),
        (
            {"image": "powershell.exe", "command_line": "powershell Get-Date"},
            "RF-REPLAY-OBSERVATION",
        ),
        (
            {
                "image": "notpowershell.exe",
                "command_line": "-WindowStyle Hidden -EncodedCommand inert",
            },
            "RF-REPLAY-OBSERVATION",
        ),
    ],
)
def test_rule_uses_observed_fields_not_labels(tmp_path: Path, fields: dict, expected: str) -> None:
    batch = load_replay(
        fixture(tmp_path / "rule.jsonl", [event(fields=fields)]), source_id="original"
    )
    result = make_alerts(batch, ingested_at=NOW)
    assert result[0].rule_id == expected


def test_speed_only_changes_pacing_not_alerts(tmp_path: Path) -> None:
    batch = load_replay(
        fixture(
            tmp_path / "groups.jsonl",
            [
                event("later", scenario_id="second", observed_at="2026-01-01T12:00:10Z"),
                event("first"),
            ],
        ),
        source_id="original",
    )
    sleeps = []

    async def record_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    async def consume(speed: float):
        return [
            item
            async for item in ReplaySource(
                batch, ingested_at=NOW, speed=speed, sleep=record_sleep
            ).ingest()
        ]

    immediate = asyncio.run(consume(0))
    assert sleeps == []
    paced = asyncio.run(consume(2))
    assert immediate == paced
    assert sleeps == [5.0]
    assert (paced[1].event_time - paced[0].event_time) == timedelta(seconds=10)


@pytest.mark.parametrize("speed", [-1, float("nan"), float("inf")])
def test_invalid_speed_rejected(tmp_path: Path, speed: float) -> None:
    batch = load_replay(fixture(tmp_path / "one.jsonl", [event()]), source_id="original")
    with pytest.raises(ReplayError):
        ReplaySource(batch, ingested_at=NOW, speed=speed)


def test_oversized_json_integer_quarantines_without_losing_neighboring_rows(tmp_path: Path) -> None:
    large_number = "9" * 5000
    path = tmp_path / "integer.jsonl"
    path.write_text(json.dumps(event()) + "\n" + '{"oversized":' + large_number + "}\n")
    assert len(path.read_bytes()) < 16 * 1024
    batch = load_replay(path, source_id="integer-original")
    assert [item.event_id for item in batch.events] == ["event-1"]
    assert [(item.line, item.code) for item in batch.quarantine] == [(2, "invalid_json")]
    array = tmp_path / "integer.json"
    array.write_text("[" + large_number + "]")
    rejected = load_replay(array, source_id="integer-array")
    assert not rejected.events
    assert len(rejected.quarantine) == 1 and rejected.quarantine[0].code == "invalid_json"
