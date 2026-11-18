# ResponseForge

SOAR-first incident response automation with offline attack replay and an optional live Wazuh endpoint path. ResponseForge connects evidence, analyst approval, response providers and auditable case reports through real Shuffle workflows.

**Status: repository foundation / Phase 0 discovery. No incident API, replay engine, Shuffle workflow or live integration is implemented or qualified yet.**

The public engineering requirements are captured in the [architecture](docs/architecture.md) and acceptance documentation. The [implementation plan](docs/implementation-plan.md) defines bounded delivery packages and parallel-agent ownership; the [acceptance matrix](docs/acceptance.md) keeps implementation separate from verification.

## Planned product

- One Python application: FastAPI, shared contracts/policy, SQLite and a replay CLI.
- Replay: deterministic fixtures and recorded evidence; response effects explicitly labeled `simulated=true`, `verified_live=false`.
- Shuffle: three actual orchestration workflows for process investigation, persistence investigation and host containment.
- Live: opt-in Wazuh alerts and an approved safe action on an authorized, separately supplied VM. Live support requires observed endpoint evidence.

This is deliberately smaller than DetectBridge: no custom SIEM/EDR, stream-processing fleet, dashboard, paid API or AI dependency. DetectBridge is not a runtime dependency.

## Run the foundation checks

Requires Git, Make and Python 3.12+; Docker/Compose are inspected, not installed or started. With an existing `uv`-managed Python:

```bash
git clone https://github.com/TravisMa07/ResponseForge.git
cd ResponseForge
make check PYTHON="uv run --no-project --python 3.12 python"
make doctor PYTHON="uv run --no-project --python 3.12 python"
```

Or use `make check doctor PYTHON=python3` when that interpreter is 3.12+. These commands validate documentation and inspect local prerequisites only. There is no application startup command yet. Doctor returns nonzero if a required tool is unavailable; passing it does not qualify a deployment. No external Python packages are needed for foundation checks.

## Engineering documentation

- [Architecture and decisions](docs/architecture.md)
- [Environment findings](docs/environment.md) and [upstream dependencies](docs/dependencies.md)
- [Roadmap](docs/roadmap.md), [implementation plan](docs/implementation-plan.md) and [acceptance](docs/acceptance.md)
- [Development workflow](docs/sdlc.md), [agent instructions](AGENTS.md) and [implementation ledger](docs/implementation-ledger.md)
- [Security boundaries](docs/security.md), [limitations](docs/limitations.md) and [third-party notices](THIRD_PARTY.md)

## Safety and licensing

No endpoint operation is authorized by cloning this repository. Live operations require explicit administrator authorization, scoped approval and recovery procedures. External telemetry is untrusted data, never executable instructions. Credentials, local evidence and downloaded corpora must stay out of Git.

Public source availability does not grant a software license. The project license remains an owner decision; no open-source license is selected in this foundation. Upstream software and datasets retain their own terms.
