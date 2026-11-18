"""Original source-derived wire fixtures; no real workflow or credentials."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from responseforge.integrations.shuffle.models import ShuffleArgument, ShuffleConfig

WF = "11111111-1111-4111-8111-111111111111"
OTHER_WF = "22222222-2222-4222-8222-222222222222"
RUN = "33333333-3333-4333-8333-333333333333"
OTHER_RUN = "44444444-4444-4444-8444-444444444444"
ORG = "55555555-5555-4555-8555-555555555555"
KEY = "SYNTHETIC_PRIVATE_API_CREDENTIAL_NOT_FOR_NETWORK"
EXECUTION_SECRET = "SYNTHETIC_VENDOR_EXECUTION_SECRET_MUST_BE_DISCARDED"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def config(**changes: Any) -> ShuffleConfig:
    return ShuffleConfig(
        **(
            {
                "base_url": "https://shuffle.invalid",
                "api_key": KEY,
                "workflow_ids": frozenset({WF}),
                "org_id": ORG,
            }
            | changes
        )
    )


def argument(**changes: Any) -> ShuffleArgument:
    return ShuffleArgument.model_validate(
        {
            "incident_id": "case-1",
            "run_id": RUN,
            "correlation_id": "correlation-1",
            "mode": "replay",
        }
        | changes
    )


def workflow(**changes: Any) -> dict[str, Any]:
    return {
        "id": WF,
        "name": "Original qualification stub",
        "actions": [{"id": RUN, "app_name": "original-test-only", "name": "no_runtime_execution"}],
        "branches": [],
        "triggers": [],
        "start": RUN,
        "workflow_variables": [],
        "execution_variables": [],
        "configuration": {},
        "authorization": EXECUTION_SECRET,
    } | changes


def fingerprint(value: dict[str, Any]) -> str:
    # Independently implement the frozen public projection, not production output.
    projection = {
        key: value.get(key, {} if key == "configuration" else "" if key == "start" else [])
        for key in (
            "id",
            "actions",
            "branches",
            "triggers",
            "start",
            "workflow_variables",
            "execution_variables",
            "configuration",
        )
    }
    return hashlib.sha256(
        json.dumps(projection, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def execution(**changes: Any) -> dict[str, Any]:
    return {
        "execution_id": RUN,
        "workflow_id": WF,
        "workflow": {"id": WF},
        "execution_argument": argument().model_dump_json(),
        "status": "FINISHED",
        "authorization": EXECUTION_SECRET,
        "results": [{"raw": "PRIVATE_RESULT"}],
    } | changes
