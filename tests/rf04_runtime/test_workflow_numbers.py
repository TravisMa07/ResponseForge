"""Real Shuffle JSON round trips must preserve semantic graph identity."""

from uuid import uuid4

import pytest

from responseforge.integrations.shuffle.models import workflow_artifact


def test_integer_valued_json_numbers_have_same_graph_identity() -> None:
    identity = str(uuid4())
    stored = {"id": identity, "actions": [{"position": {"x": 10.0, "y": 20.0}}]}
    executed = {"id": identity, "actions": [{"position": {"x": 10, "y": 20}}]}
    assert workflow_artifact(stored).sha256 == workflow_artifact(executed).sha256


@pytest.mark.parametrize("changed", [10.5, "10", True, 11])
def test_different_json_values_keep_different_graph_identity(changed: object) -> None:
    identity = str(uuid4())
    original = {"id": identity, "actions": [{"parameters": [{"value": 10}]}]}
    altered = {"id": identity, "actions": [{"parameters": [{"value": changed}]}]}
    assert workflow_artifact(original).sha256 != workflow_artifact(altered).sha256


def test_qualification_workflow_supplies_integral_diagram_coordinates() -> None:
    from responseforge.integrations.shuffle.qualification import _workflow

    value = _workflow(str(uuid4()), "Qualification", "succeeded")
    assert value["actions"][0]["position"] == {"x": 10, "y": 10}


def test_diagram_placement_is_not_executable_graph_identity() -> None:
    identity = str(uuid4())
    stored = {"id": identity, "actions": [{"id": "node", "position": {"x": 10.001, "y": 5}}]}
    executed = {"id": identity, "actions": [{"id": "node", "position": {"x": 0, "y": 0}}]}
    assert workflow_artifact(stored).sha256 == workflow_artifact(executed).sha256


def test_nested_position_parameter_remains_bound() -> None:
    identity = str(uuid4())
    a = {"id": identity, "actions": [{"parameters": [{"position": {"x": 10}}]}]}
    b = {"id": identity, "actions": [{"parameters": [{"position": {"x": 0}}]}]}
    assert workflow_artifact(a).sha256 != workflow_artifact(b).sha256
