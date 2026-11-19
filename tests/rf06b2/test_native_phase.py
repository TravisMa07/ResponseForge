"""A valid graph from another phase cannot certify a cached original phase."""

import pytest

from responseforge.integrations.shuffle.recorded_qualification import _check_native_phase

RUN = "66666666-6666-4666-8666-666666666666"


def execution(gate="awaiting_approval", native="SKIPPED"):
    return {"results": [
        {"action": {"app_name": "responseforge_tasks", "name": step},
         "status": native if step == "dispatch" else "SUCCESS",
         "result": {"run_id": RUN, "step": step, "kind": "process", "mode": "replay",
                    "status": "prepared" if step == "prepare" else gate if step == "gate" else "skipped",
                    "delivery": "skipped" if step == "dispatch" else "accepted"}}
        for step in ("prepare", "gate", "dispatch")
    ]}


def test_valid_original_awaiting_phase_is_accepted():
    assert _check_native_phase("powershell-awaiting", execution(), RUN) is None


def test_other_phase_gate_cannot_satisfy_cached_awaiting():
    raw = execution(gate="ready", native="SUCCESS")
    raw["results"][2]["result"].update(status="completed", delivery="accepted")
    with pytest.raises(ValueError):
        _check_native_phase("powershell-awaiting", raw, RUN)
