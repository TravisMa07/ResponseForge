# Offline contract and policy checks

RF-01 delivers schemas/protocols/pure policy; RF-02 adds an authenticated case API with file-backed SQLite, durable approvals/audit and conservative recovery. Python 3.12.12 and uv 0.13.6 are the qualification baseline. Install the locked dependencies once (network is needed for an uncached first install):

```bash
uv sync --locked
make qualify
uv build --offline --no-build-isolation
```

`make qualify` runs pytest, Ruff, strict mypy, deterministic JSON Schema drift checks and foundation documentation checks. Its uv commands use `--locked --offline`; test execution has no dataset, VM or vendor-service requirement. Dependencies must already be installed or cached. `--locked` rejects stale metadata instead of silently resolving a new set; see [uv lock/sync behavior](https://docs.astral.sh/uv/concepts/projects/sync/). RF-02 offline tests exercise HTTP authentication, temporary-file SQLite durability, concurrency and process-death recovery with controlled simulated providers. They do not qualify actual Shuffle or live Wazuh effects.

[RF-01 expectations](expectations/rf-01.md) were committed before code. Tests derive valid/invalid outcomes from that matrix, including all state pairs and approval scope mutations. The [RF-01 ledger](rf-01-ledger.md) records red/green evidence, exact revisions, failures and limitations.

Published schemas live in [schemas/v1](../schemas/v1). Regenerate intentionally with `uv run --locked --offline python scripts/export_contracts.py`, review the semantic diff, then run `make schemas`. JSON Schema expresses structural constraints; Python model validators enforce additional cross-field invariants listed in the [design](rf-01-design.md). Schema-only validation is insufficient for dispatch authorization. Wire models are immutable scope carriers, not proof of identity or signed approval tokens. Credentials and stored approvals must come from trusted server code.

RF-02 independent tests are under `tests/rf02/`, derived from the [RF-02 freeze](expectations/rf-02.md). They include real child-process `os._exit` before/after a synthetic marker effect, reopened SQLite reservations, verify-only recovery, stale-result races and authenticated HTTP intake→approval→dispatch→restart. The marker files are temporary test data, not endpoint actions. The [RF-02 ledger](rf-02-ledger.md) retains failures/corrections and exact revision attribution. `make schemas` also checks internal OpenAPI; regenerate with `uv run --locked --offline python scripts/export_api.py`.

RF-03 expectations are [frozen separately](expectations/rf-03.md); tests/rf03 covers deterministic bounded parsing/pacing/quarantine, scoped source evidence, production mock persistence/faults/rollback, authenticated API/CLI replay, duplicate invocation and JSON/HTML redaction. `make qualify` also verifies original fixture manifest hashes and the published replay-record schema. See [RF-03 evidence](rf-03-ledger.md). No fixture command is decoded or executed.

RF-04A tests/rf04 derives expectations from [pinned source/freeze](expectations/rf-04.md): exact vendor wire and safe projection, read-only bounded retries, once-only starts, durable reservation/lookup-only restart recovery, full case/run/argument/version/origin/executed-graph binding, report secret integration and blocked default plans. One actual child process exits after a source-shaped stub start; this is persistence evidence, not a real vendor execution. Docker CLI parsing tests are explicitly syntax-only and optional when the CLI is absent; no daemon is started. `make qualify` checks candidate digest/platform pins and safe blocked plans offline.
