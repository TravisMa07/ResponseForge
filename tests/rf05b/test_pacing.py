"""Lab request pacing preserves the real core limit and original request."""

import asyncio

import httpx

from responseforge.integrations.shuffle import playbook_qualification as qualification


def test_sustained_host_requests_fit_core_minute_budget_without_rewriting(monkeypatch):
    clock = [0.0]
    waits = []

    async def advance(seconds):
        assert 0 < seconds < 2
        waits.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(qualification.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(qualification.asyncio, "sleep", advance)
    request = httpx.Request("POST", "https://127.0.0.1:8443/fixed", content=b"original")
    observed = []
    pacer = qualification._CorePacer()

    async def exercise():
        for _ in range(100):
            await pacer(request)
            observed.append(clock[0])

    asyncio.run(exercise())
    assert observed[0] == 0 and len(waits) == 99
    assert all(sum(t <= value < t + 60 for value in observed) <= 60 for t in observed)
    assert request.method == "POST" and request.content == b"original"
    assert pacer.waited_seconds >= 99


def test_idle_interval_does_not_add_unnecessary_delay(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(qualification.time, "monotonic", lambda: clock[0])

    async def forbidden_sleep(seconds):
        raise AssertionError("Idle request must not be delayed")

    monkeypatch.setattr(qualification.asyncio, "sleep", forbidden_sleep)
    pacer = qualification._CorePacer()

    async def exercise():
        request = httpx.Request("GET", "https://127.0.0.1:8443/fixed")
        await pacer(request)
        clock[0] = 60
        await pacer(request)

    asyncio.run(exercise())
    assert pacer.waited_seconds == 0
