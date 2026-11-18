# ADR 0001: One shared incident core

Status: accepted from the authoritative handoff, 2026-11-18.

Context: ResponseForge must remain substantially smaller than DetectBridge and use existing SOAR and endpoint security platforms.

Decision: one Python package/application with FastAPI, SQLite migrations, replay CLI, policy and provider protocols. Use real Shuffle for orchestration. Wazuh is optional for deployment but a required second-release goal. Share case, evidence, approval and report contracts between both modes.

Alternatives rejected: a custom SIEM/detection engine, a distributed microservice fleet, a second live case implementation, or a mock-only substitute for Shuffle.

Consequences: simple local persistence and fewer deployment units, with single-node concurrency limits to measure. SQLite is not a high-volume raw-log search service. Keep vendor infrastructures in separate profiles. Label simulated responses independently from verified live effects.

Validation: RF-01 through RF-06 must prove shared contracts, durable idempotency, real workflow execution and recovery; RF-08 proves an actual live endpoint uses the same core. No runtime evidence exists yet.
