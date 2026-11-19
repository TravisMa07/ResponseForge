"""Bounded native Wazuh JSON projection; no I/O or executable telemetry."""

import hashlib
import json
import math
import re
from typing import NoReturn, cast

from responseforge.integrations.wazuh.models import WazuhConfig, WazuhObservation


class WazuhError(ValueError):
    """Native source could not be safely projected."""


class WazuhScopeError(WazuhError):
    """Native agent is outside configured source authority."""


def _reject_constant(value: str) -> NoReturn:
    raise ValueError("Nonfinite JSON number")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Ambiguous JSON object")
        result[key] = value
    return result


def _string(value: object, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Unsupported JSON string")
    # JSON escapes may decode to lone surrogates even though the original byte
    # stream was valid UTF-8. Only Unicode scalar strings may enter contracts.
    value.encode("utf-8", errors="strict")
    return value


def _bounded(document: object) -> None:
    stack: list[tuple[object, int]] = [(document, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 10000:
            raise ValueError("JSON resource limit")
        if isinstance(value, dict):
            for key, child in value.items():
                _string(key, 16384)
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            _string(value, 16384)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Nonfinite JSON number")


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return cast(dict[str, object], value)


def project_alert(raw: bytes, config: WazuhConfig) -> WazuhObservation:
    """Project only observed native fields under detached server authority.

    The digest identifies received integration-delivery bytes. Integrator may
    have reserialized the original alert, so this is not an alerts.json digest.
    """
    try:
        if not isinstance(raw, bytes) or not raw or len(raw) > 262144:
            raise ValueError("Unsupported delivery bytes")
        trusted = WazuhConfig.model_validate(config.model_dump(mode="json", warnings=False))
        text = raw.decode("utf-8", errors="strict")
        value: object = json.loads(
            text, object_pairs_hook=_unique, parse_constant=_reject_constant
        )
        _bounded(value)
        source = _object(value)
        rule, agent = _object(source.get("rule")), _object(source.get("agent"))
        agent_id = _string(agent.get("id"), 8)
        name = _string(agent.get("name"), 256)
        if not re.fullmatch(r"[0-9]{1,8}", agent_id) or not name:
            raise ValueError("Unsupported agent identity")
        binding = next((item for item in trusted.agents if item.agent_id == agent_id), None)
        if int(agent_id) == 0 or binding is None or name != binding.endpoint.hostname:
            raise WazuhScopeError("Native agent is not authorized")
        timestamp = _string(source.get("timestamp"), 16384)
        return WazuhObservation(
            manager_id=trusted.manager_id,
            native_id=source.get("id"),
            agent_id=agent_id,
            endpoint=binding.endpoint,
            event_time=timestamp,
            original_timestamp=timestamp,
            rule_id=rule.get("id"),
            level=rule.get("level"),
            sha256=hashlib.sha256(raw).hexdigest(),
            raw_json=text,
        )
    except WazuhScopeError:
        raise
    except (ValueError, TypeError, AttributeError, RecursionError, OverflowError):
        # Decoder and model errors can contain raw data; none cross this API.
        raise WazuhError("Native alert could not be safely projected") from None
