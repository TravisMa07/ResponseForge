# ResponseForge

SOAR-first incident response automation with offline attack replay and an optional live Wazuh endpoint path. ResponseForge connects evidence, analyst approval, response providers and auditable case reports through real Shuffle workflows.

**RF-01–06 are merged with merged-revision checks recorded. RF-06B2 adds five narrowly scoped recorded-observation scenarios through genuine Shuffle workflows. The [RF-06 ledger](docs/rf-06-ledger.md) owns exact qualified revisions, runtime results and outstanding acceptance/merge gates; the [recorded-source operator notes](docs/recorded-runtime.md) explain preparation and reproduction. Effects are simulated and human decisions are test fixtures. Dedicated-VM runtime, live endpoints, analyst savings and release readiness require separate qualification.**

The public engineering requirements are captured in the [architecture](docs/architecture.md) and acceptance documentation. The [implementation plan](docs/implementation-plan.md) defines bounded delivery packages and parallel-agent ownership; the [acceptance matrix](docs/acceptance.md) keeps implementation separate from verification.

## Planned product

- One Python application: FastAPI, shared contracts/policy, SQLite and a replay CLI.
- Replay: deterministic fixtures and recorded evidence; response effects explicitly labeled `simulated=true`, `verified_live=false`.
- Shuffle: three actual orchestration workflows for process investigation, persistence investigation and host containment.
- Live: opt-in Wazuh alerts and an approved safe action on an authorized, separately supplied VM. Live support requires observed endpoint evidence.

This is deliberately smaller than DetectBridge: no custom SIEM/EDR, stream-processing fleet, dashboard, paid API or AI dependency. DetectBridge is not a runtime dependency.

## Run offline core checks

Requires Python 3.12+ and uv (qualified locally with Python 3.12.12 and uv 0.13.6):

```bash
uv sync --locked
make qualify
```

The first dependency install may need network access. Qualification then runs offline: pytest, Ruff, strict typing, schema drift and documentation checks. See [testing](docs/testing.md), the [contract design](docs/rf-01-design.md), [v1 JSON Schemas](schemas/v1), and [examples](examples/contracts-v1.json). These checks exercise the API in process and controlled simulated providers. They do not qualify actual vendor or endpoint execution.

## Replay an original synthetic fixture

```bash
uv run --locked --offline python -m responseforge \
  --replay datasets/fixtures/suspicious.jsonl --source-id rf03-suspicious
```

This uses the authenticated API in process, writes ignored local state/reports and stops for approval. Add `--decision approve` explicitly to apply one **simulated** effect; repeat delivery retains one case/effect. No TCP listener, real Shuffle workflow or endpoint action runs. See the [replay runbook](docs/replay.md) for benign/incomplete cases, denial, recovery, formats and report redaction. The [Shuffle target comparison](docs/shuffle.md) retains Docker Desktop and dedicated-VM options; the [runtime runbook](docs/rf-04-operator.md) owns the authorized pilot.

## Local case API

```bash
uv run --locked --offline python -m responseforge --init-config .local/config.json
uv run --locked --offline python -m responseforge --config .local/config.json
```

This creates separate private credentials and binds the API to `127.0.0.1:8000`. No provider, replay scenario or endpoint action starts automatically. See the [API and recovery runbook](docs/core-api.md) and [internal OpenAPI](schemas/internal-api.json). Internal alerts are normalized ResponseForge contracts; actual Wazuh/Shuffle payload mappings still require their own qualification.

## Run the foundation checks

Requires Git, Make and Python 3.12+; Docker/Compose are inspected, not installed or started. With an existing `uv`-managed Python:

```bash
git clone https://github.com/TravisMa07/ResponseForge.git
cd ResponseForge
make check PYTHON="uv run --no-project --python 3.12 python"
make doctor PYTHON="uv run --no-project --python 3.12 python"
```

Or use `make check doctor PYTHON=python3` when that interpreter is 3.12+. These commands validate documentation and inspect local prerequisites only. For the local API, use the explicit private configuration above. Doctor returns nonzero if a required tool is unavailable; passing it does not qualify a deployment. No external Python packages are needed for foundation checks.

## Engineering documentation

- [Architecture and decisions](docs/architecture.md)
- [Environment findings](docs/environment.md) and [upstream dependencies](docs/dependencies.md)
- [Roadmap](docs/roadmap.md), [implementation plan](docs/implementation-plan.md) and [acceptance](docs/acceptance.md)
- [Development workflow](docs/sdlc.md), [agent instructions](AGENTS.md) and [implementation ledger](docs/implementation-ledger.md)
- [Security boundaries](docs/security.md), [limitations](docs/limitations.md) and [third-party notices](THIRD_PARTY.md)

## Safety and licensing

No endpoint operation is authorized by cloning this repository. Live operations require explicit administrator authorization, scoped approval and recovery procedures. External telemetry is untrusted data, never executable instructions. Credentials, local evidence and downloaded corpora must stay out of Git.

Public source availability does not grant a software license. The project license remains an owner decision; no open-source license is selected in this foundation. Upstream software and datasets retain their own terms.
