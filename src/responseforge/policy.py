"""Pure policy checks for trusted server callers.

These checks do not authenticate requests, load approvals, or dispatch effects.
RF-02 must supply authenticated server context, a stored approval, and the
selected provider's trusted capability registry immediately before dispatch.
"""

from dataclasses import dataclass
from datetime import datetime

from responseforge.contracts import (
    ActionCapability,
    ActionProposal,
    ActionType,
    Approval,
    ApprovedAction,
    IncidentStatus,
    Mode,
)


class PolicyError(ValueError):
    """The requested transition or approval does not meet policy."""


@dataclass(frozen=True)
class AuthorizationContext:
    """Server-constructed authority; never deserialize this from a wire body."""

    actor_id: str
    authenticated: bool
    roles: frozenset[str]
    allowed_endpoint_ids: frozenset[str]
    allowed_actions: frozenset[ActionType]


# Explicit edges preserve the independent architecture's lifecycle. Closing a
# final state requires a separate review decision, not merely a terminal status.
_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("RECEIVED", "TRIAGING"),
        ("TRIAGING", "INVESTIGATING"),
        ("INVESTIGATING", "AWAITING_APPROVAL"),
        ("INVESTIGATING", "RESOLVED"),
        ("AWAITING_APPROVAL", "RESPONDING"),
        ("AWAITING_APPROVAL", "RESOLVED"),
        ("RESPONDING", "CONTAINED"),
        ("RESPONDING", "RESOLVED"),
        ("RESPONDING", "FAILED"),
        ("CONTAINED", "CLOSED"),
        ("RESOLVED", "CLOSED"),
        ("FAILED", "CLOSED"),
    }
)


def validate_transition(
    current: IncidentStatus,
    requested: IncidentStatus,
    *,
    reviewed: bool = False,
) -> None:
    """Validate a lifecycle edge; durable effect/review evidence is separate."""
    if (current, requested) not in _TRANSITIONS:
        raise PolicyError(f"Forbidden incident transition: {current} -> {requested}")
    if requested == "CLOSED" and reviewed is not True:
        raise PolicyError("Closing a final incident requires review")


def validate_approval(
    proposal: ActionProposal,
    approval: Approval,
    *,
    context: AuthorizationContext,
    stored_approval: Approval | None,
    capabilities: tuple[ActionCapability, ...],
    runtime_mode: Mode,
    now: datetime,
) -> ApprovedAction:
    """Authorize an exact stored approval scope, without dispatch or mutation.

    Equality with ``stored_approval`` is meaningful only when the caller loaded
    that value from trusted storage. Neither this carrier nor a client-supplied
    approval object is a bearer token or proof of server authorization.
    """
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PolicyError("Approval validation requires an aware current time")
    if context.authenticated is not True or "approver" not in context.roles:
        raise PolicyError("An authenticated approver is required")
    if context.actor_id != approval.approver_id:
        raise PolicyError("Approval identity does not match authenticated actor")
    if proposal.target.endpoint.endpoint_id not in context.allowed_endpoint_ids:
        raise PolicyError("Target endpoint is not authorized")
    if proposal.action not in context.allowed_actions:
        raise PolicyError("Action is not authorized")
    if stored_approval is None or approval != stored_approval:
        raise PolicyError("Approval must match the server-stored approval")
    if approval.decision != "approved":
        raise PolicyError("Approval decision does not permit dispatch")
    if approval.proposal != proposal:
        raise PolicyError("Approval scope does not match the current proposal")
    if not (
        proposal.created_at
        <= approval.decided_at
        <= now
        < approval.expires_at
        <= proposal.expires_at
    ):
        raise PolicyError("Approval is not currently valid")
    if proposal.mode != runtime_mode:
        raise PolicyError("Proposal and runtime mode do not match")
    if runtime_mode == "live" and not proposal.target.endpoint.agent_id:
        raise PolicyError("Live actions require an enrolled agent identity")
    if not any(
        capability.mode == runtime_mode and capability.action == proposal.action
        for capability in capabilities
    ):
        raise PolicyError("Selected provider does not support this action and mode")
    return ApprovedAction(proposal=proposal, approval=approval)
