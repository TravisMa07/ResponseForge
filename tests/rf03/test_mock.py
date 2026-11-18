"""M01-M06: count durable simulated effects, not optimistic return flags."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest

from responseforge.contracts import ApprovedAction
from responseforge.integrations.mock_edr import MockError, MockResponseProvider
from tests.rf03.helpers import ENDPOINT, NOW, approved


def provider(path: Path, **kwargs):
    value = MockResponseProvider(path, clock=kwargs.pop("clock", lambda: NOW), **kwargs)
    value.seed_endpoint(ENDPOINT, processes=("42",))
    return value


def test_only_real_supported_simulated_capabilities_are_advertised(tmp_path: Path) -> None:
    mock = provider(tmp_path / "mock.sqlite")
    caps = asyncio.run(mock.capabilities(ENDPOINT))
    assert {x.action for x in caps} == {
        "terminate_process",
        "isolate_host",
        "unisolate_host",
        "test_marker",
    }
    assert all(
        x.mode == "replay" and x.provider == "mock-edr" and x.provider_version == "1.0"
        for x in caps
    )
    assert asyncio.run(mock.capabilities(ENDPOINT.model_copy(update={"agent_id": "unknown"}))) == ()


def test_terminate_is_durable_and_reseed_never_restores_effect(tmp_path: Path) -> None:
    path = tmp_path / "mock.sqlite"
    mock = provider(path)
    action = approved()
    result = asyncio.run(mock.execute(action))
    assert result.execution_id == "exec-proposal-1" and result.dispatch_state == "acknowledged"
    assert result.verification.simulated and not result.verification.verified_live
    assert result.verification.status == "pending"
    state = mock.snapshot(ENDPOINT)
    assert state["running_processes"] == [] and state["effect_count"] == 1
    reopened = provider(path)
    assert reopened.snapshot(ENDPOINT) == state
    assert asyncio.run(reopened.verify(result)).status == "verified"
    assert asyncio.run(reopened.execute(action)) == result
    assert reopened.snapshot(ENDPOINT)["effect_count"] == 1


def test_idempotency_survives_concurrent_delivery_and_expiry(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.sqlite"
    provider(path)
    action = approved()

    def deliver(_):
        return asyncio.run(provider(path).execute(action))

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(deliver, range(8)))
    assert all(value == results[0] for value in results)

    def expired_clock():
        return NOW + timedelta(days=2)

    later = provider(path, clock=expired_clock)
    assert asyncio.run(later.execute(action)) == results[0]
    assert later.snapshot(ENDPOINT)["effect_count"] == 1
    changed = approved(resource="host:original-host", action="isolate_host")
    with pytest.raises(MockError):
        asyncio.run(later.execute(changed))
    assert not later.snapshot(ENDPOINT)["isolated"]


@pytest.mark.parametrize(
    "change",
    [
        {"action": "quarantine_file"},
        {"resource": "process:unrecorded"},
        {"endpoint": ENDPOINT.model_copy(update={"hostname": "forged"})},
        {"mode": "live"},
    ],
)
def test_unsupported_or_forged_scope_has_zero_effect(tmp_path: Path, change: dict) -> None:
    mock = provider(tmp_path / "deny.sqlite")
    grant = approved(**change)
    with pytest.raises((MockError, ValueError)):
        asyncio.run(mock.execute(grant))
    assert mock.snapshot(ENDPOINT)["effect_count"] == 0


def test_forged_approval_or_invalid_copy_does_not_authorize(tmp_path: Path) -> None:
    mock = provider(tmp_path / "forgery.sqlite")
    original = approved()
    rejected = original.approval.model_copy(update={"decision": "rejected"})
    with pytest.raises(MockError):
        asyncio.run(mock.execute(ApprovedAction(proposal=original.proposal, approval=rejected)))
    changed = original.proposal.model_copy(update={"target": {"resource": "bad"}})
    with pytest.raises(ValueError):
        asyncio.run(mock.execute(original.model_copy(update={"proposal": changed})))
    assert mock.snapshot(ENDPOINT)["effect_count"] == 0


def test_failed_before_effect_is_durable_and_not_verified(tmp_path: Path) -> None:
    path = tmp_path / "fail.sqlite"
    mock = provider(path, fault="fail_before_effect")
    result = asyncio.run(mock.execute(approved()))
    assert result.dispatch_state == "failed"
    assert mock.snapshot(ENDPOINT)["effect_count"] == 0
    assert asyncio.run(provider(path).verify(result)).status == "failed"
    assert asyncio.run(provider(path).execute(approved())) == result


@pytest.mark.parametrize("fault", ["error_after_effect", "timeout_after_effect"])
def test_effect_commit_precedes_lost_ack_and_recovery_queries_original(
    tmp_path: Path, fault: str
) -> None:
    path = tmp_path / "uncertain.sqlite"
    mock = provider(path, fault=fault)

    async def deliver():
        return await asyncio.wait_for(mock.execute(approved()), timeout=0.02)

    with pytest.raises((MockError, TimeoutError)):
        asyncio.run(deliver())
    assert mock.snapshot(ENDPOINT)["effect_count"] == 1
    recovered = provider(path)
    receipt = asyncio.run(recovered.execute(approved()))
    assert recovered.snapshot(ENDPOINT)["effect_count"] == 1
    proof = asyncio.run(recovered.verify(receipt))
    assert proof.status == "verified" and proof.simulated and not proof.verified_live


def test_isolation_and_approved_rollback_have_separate_effects(tmp_path: Path) -> None:
    mock = provider(tmp_path / "rollback.sqlite")
    isolate = asyncio.run(
        mock.execute(approved(action="isolate_host", resource="host:original-host"))
    )
    assert mock.snapshot(ENDPOINT)["isolated"] is True
    assert asyncio.run(mock.verify(isolate)).status == "verified"
    rollback = asyncio.run(
        mock.execute(
            approved(proposal_id="rollback", action="unisolate_host", resource="host:original-host")
        )
    )
    assert mock.snapshot(ENDPOINT)["isolated"] is False
    assert mock.snapshot(ENDPOINT)["effect_count"] == 2
    assert asyncio.run(mock.verify(rollback)).status == "verified"
    assert asyncio.run(mock.verify(isolate)).status != "verified"


def test_verification_requires_original_bound_receipt(tmp_path: Path) -> None:
    mock = provider(tmp_path / "bound.sqlite")
    original = asyncio.run(mock.execute(approved()))
    for field in ("execution_id", "proposal_id", "incident_id", "provider"):
        with pytest.raises(MockError):
            asyncio.run(mock.verify(original.model_copy(update={field: "another"})))
    other = provider(tmp_path / "empty.sqlite")
    assert asyncio.run(other.verify(original)).status == "pending"


@pytest.mark.parametrize(
    "fault,effects,initial",
    [
        ("fail_before_effect", 0, "failed"),
        ("error_after_effect", 1, "uncertain"),
        ("timeout_after_effect", 1, "uncertain"),
    ],
)
def test_real_mock_and_core_recover_original_effect_after_restart(
    tmp_path: Path, fault: str, effects: int, initial: str
) -> None:
    from tests.rf02.helpers import approved as prepare_approved
    from tests.rf02.helpers import world

    w = world(tmp_path / "cases.sqlite", timeout=0.02)
    mock_path = tmp_path / "actual-mock.sqlite"
    endpoint = w.settings.endpoints[0]
    adapter = MockResponseProvider(mock_path, clock=w.clock, fault=fault)
    adapter.seed_endpoint(endpoint, processes=("42",))
    w = w.reopened(providers={"mock-edr": adapter}, provider_versions={"mock-edr": "1.0"})
    action = prepare_approved(w)
    result = asyncio.run(w.service.execute(action.proposal_id, "mock-edr", w.actors["executor"]))
    assert result.dispatch_state == initial
    assert adapter.snapshot(endpoint)["effect_count"] == effects
    restarted_adapter = MockResponseProvider(mock_path, clock=w.clock)
    restarted = w.reopened(
        providers={"mock-edr": restarted_adapter}, provider_versions={"mock-edr": "1.0"}
    )
    duplicate = asyncio.run(
        restarted.service.execute(action.proposal_id, "mock-edr", w.actors["executor"])
    )
    assert duplicate == result
    if effects:
        recovered = asyncio.run(
            restarted.service.reconcile(action.proposal_id, "mock-edr", w.actors["executor"])
        )
        assert recovered.verification.status == "verified"
        assert (
            restarted.service.get_incident(action.incident_id, w.actors["analyst"]).status
            == "RESOLVED"
        )
    else:
        assert (
            restarted.service.get_incident(action.incident_id, w.actors["analyst"]).status
            == "FAILED"
        )
    assert restarted_adapter.snapshot(endpoint)["effect_count"] == effects


def test_changed_seed_or_canonical_identity_cannot_reset_state(tmp_path: Path) -> None:
    mock = provider(tmp_path / "seed.sqlite")
    asyncio.run(mock.execute(approved()))
    with pytest.raises(MockError):
        mock.seed_endpoint(ENDPOINT, processes=("42", "99"))
    with pytest.raises(MockError):
        mock.seed_endpoint(
            ENDPOINT.model_copy(update={"agent_id": "another-agent"}), processes=("42",)
        )
    assert mock.snapshot(ENDPOINT)["effect_count"] == 1
    assert mock.snapshot(ENDPOINT)["running_processes"] == []


@pytest.mark.parametrize("kind", ["foreign", "future"])
def test_provider_refuses_incompatible_database_without_rewriting(
    tmp_path: Path, kind: str
) -> None:
    import hashlib
    import sqlite3

    path = tmp_path / "incompatible.sqlite"
    connection = sqlite3.connect(path)
    if kind == "foreign":
        connection.execute("CREATE TABLE private_source(value TEXT)")
        connection.execute("INSERT INTO private_source VALUES ('must survive')")
    else:
        connection.execute("PRAGMA user_version = 999")
    connection.commit()
    connection.close()
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(MockError):
        MockResponseProvider(path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
