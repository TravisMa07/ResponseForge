"""D13/D14: actual process death with test-only marker effects, never an endpoint."""

import asyncio
import subprocess
import sys
from pathlib import Path

import pytest

from tests.rf02.helpers import approved, world


@pytest.mark.parametrize("phase", ["before-effect", "after-effect"])
def test_process_death_keeps_reservation_and_reconciles_without_redispatch(
    tmp_path: Path, phase: str
) -> None:
    path = tmp_path / "process-crash.sqlite"
    marker = tmp_path / "synthetic-effect.txt"
    w = world(path)
    proposal = approved(w)
    child = r"""
import asyncio
import os
import sys
from pathlib import Path
from tests.rf02.helpers import world
w = world(Path(sys.argv[1]))
marker = Path(sys.argv[2])
phase = sys.argv[3]
async def crash(action):
    if phase == "after-effect":
        marker.write_text("synthetic-effect:" + action.proposal.proposal_id + "\n")
    os._exit(73)
w.provider.execute = crash
asyncio.run(w.service.execute("proposal-1", "controlled", w.actors["executor"]))
raise AssertionError("controlled process crash was not reached")
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(path), str(marker), phase],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 73, result.stderr
    assert marker.exists() == (phase == "after-effect")
    restarted = w.reopened()
    saved = restarted.service.action(proposal.proposal_id, w.actors["analyst"]).execution
    assert saved is not None and saved.dispatch_state == "pending"
    duplicate = asyncio.run(
        restarted.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert duplicate == saved
    assert w.provider.execute_calls == w.provider.effect_count == 0

    async def verify_original_marker(execution):
        w.provider.verify_calls += 1
        assert execution.execution_id == "exec-proposal-1"
        assert execution.proposal_id == proposal.proposal_id
        if marker.exists():
            assert marker.read_text() == "synthetic-effect:proposal-1\n"
            return w.provider._verification("verified")
        return w.provider._verification("pending")

    w.provider.verify = verify_original_marker
    recovered = asyncio.run(
        restarted.service.reconcile(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert recovered.verification.status == ("verified" if marker.exists() else "pending")
    assert w.provider.verify_calls == 1
    assert w.provider.execute_calls == 0
    if marker.exists():
        assert marker.read_text().count("synthetic-effect:") == 1
        assert (
            restarted.service.get_incident(proposal.incident_id, w.actors["analyst"]).status
            == "RESOLVED"
        )
    else:
        assert (
            restarted.service.get_incident(proposal.incident_id, w.actors["analyst"]).status
            == "RESPONDING"
        )
