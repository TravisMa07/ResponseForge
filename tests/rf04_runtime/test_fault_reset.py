"""Fault injection cannot leave an authorized pilot delayed after qualification."""

import asyncio
import json
from pathlib import Path

import pytest

from responseforge.integrations.shuffle import qualification


@pytest.mark.parametrize("fails", [False, True])
def test_checked_attempt_resets_fault_after_success_or_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    qualification._save(tmp_path / "fault.json", {"ack_delay_seconds": 8}, readable=True)
    monkeypatch.setattr(qualification.DockerRuntime, "_verified", lambda *a, **k: {})

    async def attempt(state: Path) -> dict:
        assert state == tmp_path
        if fails:
            raise ValueError("actual attempt failed")
        return {"runtime_qualified": True}

    monkeypatch.setattr(qualification, "_qualify", attempt)
    if fails:
        with pytest.raises(ValueError, match="actual attempt failed"):
            asyncio.run(qualification.qualify(tmp_path))
    else:
        assert asyncio.run(qualification.qualify(tmp_path))["runtime_qualified"] is True
    assert json.loads((tmp_path / "fault.json").read_text()) == {}
    assert (tmp_path / "fault.json").stat().st_mode & 0o777 == 0o444


def test_rejected_engine_does_not_write_fault_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def rejected(*a: object, **k: object) -> None:
        raise ValueError("engine rejected")

    monkeypatch.setattr(qualification.DockerRuntime, "_verified", rejected)
    with pytest.raises(ValueError, match="engine rejected"):
        asyncio.run(qualification.qualify(tmp_path))
    assert not (tmp_path / "fault.json").exists()
