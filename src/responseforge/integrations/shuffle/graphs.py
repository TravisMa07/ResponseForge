"""Versioned native Shuffle domain graphs and their narrow dispatch predicate.

The reviewed app evaluates branch predicates, as the upstream SDK does. Shuffle
still schedules nodes, waits for parents, persists results and converges branches.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from responseforge.integrations.shuffle.models import ShuffleArgument, TaskResult, canonical_uuid
from responseforge.playbooks.models import PlaybookKind

_KINDS = frozenset({"process", "persistence", "containment"})
_STEPS = ("prepare", "gate", "dispatch", "callback")
_PATTERN = "^(ready|uncertain)$"
_MAX_BYTES = 1048576
_PARAMETER_DEFAULTS = {
    "description",
    "example",
    "action_field",
    "schema",
    "id",
    "multiline",
    "multiselect",
    "options",
    "required",
    "tags",
    "skip_multicheck",
    "custom_value",
    "value_replace",
    "unique_toggled",
    "error",
    "hidden",
}
_ACTION_DEFAULTS = {
    "description",
    "errors",
    "public",
    "generated",
    "execution_variable",
    "position",
    "authentication_id",
    "category",
    "reference_url",
    "sub_action",
    "run_magic_output",
    "run_magic_input",
    "execution_delay",
    "category_label",
    "suggestion",
    "parent_controlled",
    "source_workflow",
    "source_execution",
    "large_image",
    "small_image",
}
_ROOT_METADATA = frozenset(
    {
        "id",
        "name",
        "description",
        "visual_branches",
        "comments",
        "created",
        "edited",
        "last_runtime",
        "due_date",
        "is_valid",
        "owner",
        "sharing",
        "execution_org",
        "org_id",
        "execution_environment",
        "previously_saved",
        "categories",
        "example_argument",
        "public",
        "default_return_value",
        "contact_info",
        "published_id",
        "revision_id",
        "usecase_ids",
        "input_questions",
        "form_control",
        "blogpost",
        "video",
        "status",
        "workflow_type",
        "generated",
        "hidden",
        "background_processing",
        "updated_by",
        "validated",
        "validation",
        "parentorg_workflow",
        "childorg_workflow_ids",
        "suborg_distribution",
        "backup_config",
    }
)


def _uuid(kind: str, identity: str) -> str:
    return str(uuid5(NAMESPACE_URL, "responseforge:shuffle:v1:" + kind + ":" + identity))


def _input(kind: object, task_app_id: str, callback_app_id: str) -> None:
    if not isinstance(kind, str) or kind not in _KINDS:
        raise ValueError("Unknown domain workflow kind")
    canonical_uuid(task_app_id)
    canonical_uuid(callback_app_id)


def _parameter(name: str, value: str, identity: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "value": value,
        "variant": "STATIC_VALUE",
        "configuration": False,
    }
    if identity is not None:
        result["id"] = identity
    return result


def build_workflow(kind: PlaybookKind, task_app_id: str, callback_app_id: str) -> dict[str, Any]:
    """Render original importable native JSON using actual registered app UUIDs."""
    _input(kind, task_app_id, callback_app_id)
    actions: list[dict[str, Any]] = []
    for index, step in enumerate(_STEPS):
        actions.append(
            {
                "id": _uuid(kind, step),
                "app_name": "responseforge_callback"
                if step == "callback"
                else "responseforge_tasks",
                "app_version": "1.0.0",
                "app_id": callback_app_id if step == "callback" else task_app_id,
                "name": step,
                "label": step.title(),
                "environment": "ResponseForge",
                "is_valid": True,
                "isStartNode": step == "prepare",
                "position": {"x": index * 300 + 10, "y": 10},
                "parameters": [
                    _parameter("outcome", "succeeded"),
                    _parameter("delay_seconds", "0"),
                ]
                if step == "callback"
                else [],
            }
        )
    branches = []
    for source, destination in (
        ("prepare", "gate"),
        ("gate", "dispatch"),
        ("gate", "callback"),
        ("dispatch", "callback"),
    ):
        conditions = []
        if destination == "dispatch":
            identity = _uuid(kind, "dispatch-condition")
            conditions.append(
                {
                    "source": _parameter("source", "$Gate.status", identity),
                    "condition": _parameter("condition", "matches regex", identity),
                    "destination": _parameter("destination", _PATTERN, identity),
                }
            )
        branches.append(
            {
                "id": _uuid(kind, source + "->" + destination),
                "source_id": _uuid(kind, source),
                "destination_id": _uuid(kind, destination),
                "label": "Ready or uncertain" if destination == "dispatch" else "",
                "conditions": conditions,
            }
        )
    return {
        "name": "ResponseForge " + kind.title() + " Investigation v1",
        "description": "Original replay domain workflow; human authorization remains in core",
        "start": _uuid(kind, "prepare"),
        "actions": actions,
        "branches": branches,
        "triggers": [],
        "workflow_variables": [],
        "execution_variables": [],
        "configuration": {
            "exit_on_error": True,
            "start_from_top": False,
            "skip_notifications": True,
        },
    }


def _bounded(value: object) -> None:
    if len(json.dumps(value, allow_nan=False).encode()) > _MAX_BYTES:
        raise ValueError("Domain graph bounds exceeded")


def _empty(value: object) -> bool:
    if value is None or value is False or value == "" or value == 0:
        return True
    if isinstance(value, dict):
        return all(_empty(item) for item in value.values())
    if isinstance(value, list):
        return all(_empty(item) for item in value)
    return False


def _params(value: Any, *, callback: bool = False) -> None:
    if not callback:
        if value is not None and value != []:
            raise ValueError
        return
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError
    expected = {"outcome": "succeeded", "delay_seconds": "0"}
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError
        name = item.get("name")
        if name not in expected or name in seen or item.get("value") != expected[name]:
            raise ValueError
        seen.add(name)
        if item.get("variant") != "STATIC_VALUE" or item.get("configuration", False) is not False:
            raise ValueError
        if set(item) - {"name", "value", "variant", "configuration"} - _PARAMETER_DEFAULTS:
            raise ValueError
        for key in _PARAMETER_DEFAULTS:
            if key == "id" and item.get(key):
                canonical_uuid(item[key])
            elif key in item and not _empty(item[key]):
                raise ValueError


def _nodes(
    document: dict[str, Any], task_app_id: str, callback_app_id: str
) -> dict[str, dict[str, Any]]:
    actions = document.get("actions")
    if not isinstance(actions, list) or len(actions) != 4:
        raise ValueError
    nodes: dict[str, dict[str, Any]] = {}
    identities: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            raise ValueError
        step = action.get("name")
        if step not in _STEPS or step in nodes:
            raise ValueError
        identity = canonical_uuid(action["id"])
        if identity in identities:
            raise ValueError
        identities.add(identity)
        app = "responseforge_callback" if step == "callback" else "responseforge_tasks"
        if (
            action.get("app_name") != app
            or action.get("app_version") != "1.0.0"
            or action.get("app_id") != (callback_app_id if step == "callback" else task_app_id)
            or action.get("environment") != "ResponseForge"
            or action.get("label") != step.title()
            or action.get("isStartNode", step == "prepare") is not (step == "prepare")
            or action.get("is_valid", True) is not True
        ):
            raise ValueError
        _params(action.get("parameters"), callback=step == "callback")
        if (
            set(action)
            - {
                "id",
                "app_id",
                "app_name",
                "app_version",
                "name",
                "label",
                "environment",
                "isStartNode",
                "is_valid",
                "parameters",
            }
            - _ACTION_DEFAULTS
        ):
            raise ValueError
        for key in _ACTION_DEFAULTS - {"description", "position"}:
            if key in action and not _empty(action[key]):
                raise ValueError
        if "description" in action and not isinstance(action["description"], str):
            raise ValueError
        if "position" in action:
            position = action["position"]
            if (
                not isinstance(position, dict)
                or set(position) != {"x", "y"}
                or any(type(value) not in {int, float} for value in position.values())
            ):
                raise ValueError
        nodes[step] = action
    return nodes


def _condition(value: Any) -> None:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError
    condition = value[0]
    if set(condition) != {"source", "condition", "destination"}:
        raise ValueError
    for name, text in (
        ("source", "$Gate.status"),
        ("condition", "matches regex"),
        ("destination", _PATTERN),
    ):
        part = condition[name]
        if not isinstance(part, dict) or part.get("value") != text:
            raise ValueError
        if part.get("name", name) not in {"", name}:
            raise ValueError
        if name != "condition" and part.get("variant") != "STATIC_VALUE":
            raise ValueError
        if name == "condition" and part.get("variant", "STATIC_VALUE") not in {"", "STATIC_VALUE"}:
            raise ValueError
        if part.get("configuration", False) is not False:
            raise ValueError
        if set(part) - {"name", "value", "variant", "configuration"} - _PARAMETER_DEFAULTS:
            raise ValueError
        for key in _PARAMETER_DEFAULTS:
            if key == "id" and part.get(key):
                canonical_uuid(part[key])
            elif key in part and not _empty(part[key]):
                raise ValueError


def validate_workflow(
    document: dict[str, Any], kind: PlaybookKind, task_app_id: str, callback_app_id: str
) -> None:
    """Accept the exact reviewed executable diamond and harmless vendor defaults."""
    try:
        _input(kind, task_app_id, callback_app_id)
        _bounded(document)
        if not isinstance(document, dict):
            raise ValueError
        if "id" in document:
            canonical_uuid(document["id"])
        known = {
            "actions",
            "branches",
            "start",
            "configuration",
            "triggers",
            "workflow_variables",
            "execution_variables",
            "auth_groups",
            "workflow_as_code",
        } | _ROOT_METADATA
        if set(document) - known:
            raise ValueError
        for key in (
            "triggers",
            "workflow_variables",
            "execution_variables",
            "auth_groups",
            "workflow_as_code",
            "visual_branches",
            "input_questions",
        ):
            if not _empty(document.get(key)):
                raise ValueError
        for key in ("public", "generated", "background_processing"):
            if document.get(key, False) is not False:
                raise ValueError
        nodes = _nodes(document, task_app_id, callback_app_id)
        if document.get("start") != nodes["prepare"]["id"]:
            raise ValueError
        config = document.get("configuration")
        if (
            not isinstance(config, dict)
            or config.get("exit_on_error") is not True
            or set(config) - {"exit_on_error", "start_from_top", "skip_notifications"}
            or config.get("start_from_top", False) is not False
            or config.get("skip_notifications", True) is not True
        ):
            raise ValueError
        branches = document.get("branches")
        if not isinstance(branches, list) or len(branches) != 4:
            raise ValueError
        expected = {
            (nodes[a]["id"], nodes[b]["id"])
            for a, b in (
                ("prepare", "gate"),
                ("gate", "dispatch"),
                ("gate", "callback"),
                ("dispatch", "callback"),
            )
        }
        seen: set[tuple[str, str]] = set()
        for branch in branches:
            if not isinstance(branch, dict):
                raise ValueError
            pair = (branch.get("source_id"), branch.get("destination_id"))
            if pair not in expected or pair in seen:
                raise ValueError
            seen.add(pair)
            if set(branch) - {
                "source_id",
                "destination_id",
                "id",
                "label",
                "conditions",
                "has_errors",
                "decorator",
                "parent_controlled",
                "source_parent",
            }:
                raise ValueError
            if branch.get("id"):
                canonical_uuid(branch["id"])
            if any(
                not _empty(branch.get(key))
                for key in ("has_errors", "decorator", "parent_controlled", "source_parent")
            ):
                raise ValueError
            if pair[1] == nodes["dispatch"]["id"]:
                _condition(branch.get("conditions"))
            elif branch.get("conditions") not in (None, []):
                raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Workflow differs from the reviewed domain graph") from None


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _json(value: Any) -> dict[str, Any]:
    if not isinstance(value, str) or len(value.encode()) > _MAX_BYTES:
        raise ValueError

    def constant(value: str) -> None:
        raise ValueError

    decoded = json.loads(value, object_pairs_hook=_object, parse_constant=constant)
    if not isinstance(decoded, dict):
        raise ValueError
    return dict(decoded)


def dispatch_selected(execution: dict[str, Any]) -> bool:
    """Resolve only the reviewed `$Gate.status` predicate from bound native proof."""
    try:
        _bounded(execution)
        run = canonical_uuid(execution["execution_id"])
        workflow_id = canonical_uuid(execution["workflow_id"])
        argument = ShuffleArgument.model_validate(_json(execution["execution_argument"]))
        if argument.run_id != run or argument.mode.value != "replay":
            raise ValueError
        graph = execution["workflow"]
        if not isinstance(graph, dict) or graph.get("id") != workflow_id:
            raise ValueError
        actions = graph.get("actions")
        if not isinstance(actions, list):
            raise ValueError
        gates = [
            item
            for item in actions
            if isinstance(item, dict)
            and item.get("app_name") == "responseforge_tasks"
            and item.get("name") == "gate"
        ]
        if len(gates) != 1:
            raise ValueError
        gate = gates[0]
        identity = canonical_uuid(gate["id"])
        app_id = canonical_uuid(gate["app_id"])
        if gate.get("app_version") != "1.0.0" or gate.get("label") != "Gate":
            raise ValueError
        results = execution.get("results")
        if not isinstance(results, list):
            raise ValueError
        candidates = [
            item
            for item in results
            if isinstance(item, dict)
            and isinstance(item.get("action"), dict)
            and (
                item["action"].get("id") == identity
                or (
                    item["action"].get("app_name") == "responseforge_tasks"
                    and item["action"].get("name") == "gate"
                )
            )
        ]
        if len(candidates) != 1:
            raise ValueError
        result = candidates[0]
        action = result["action"]
        if (
            result.get("execution_id") != run
            or result.get("status") != "SUCCESS"
            or action.get("app_id") not in (None, "", app_id)
            or any(
                action.get(key) != gate.get(key)
                for key in ("id", "app_name", "app_version", "name")
            )
        ):
            raise ValueError
        safe = TaskResult.model_validate(_json(result.get("result")))
        if (
            safe.delivery != "accepted"
            or safe.step != "gate"
            or safe.run_id != run
            or safe.status
            not in {
                "no_action",
                "awaiting_approval",
                "denied",
                "expired",
                "ready",
                "uncertain",
                "completed",
                "failed",
            }
        ):
            raise ValueError
        return safe.status in {"ready", "uncertain"}
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Native Gate proof is not verified") from None
