# Offline contract and policy checks

RF-01 delivers schemas, provider protocols and pure validation, not a running incident API. Python 3.12.12 and uv 0.13.6 are the qualification baseline. Install the locked dependencies once (network is needed for an uncached first install):

```bash
uv sync --locked
make qualify
uv build --offline --no-build-isolation
```

`make qualify` runs pytest, Ruff, strict mypy, deterministic JSON Schema drift checks and foundation documentation checks. Its uv commands use `--locked --offline`; test execution has no dataset, VM or vendor-service requirement. Dependencies must already be installed or cached. `--locked` rejects stale metadata instead of silently resolving a new set; see [uv lock/sync behavior](https://docs.astral.sh/uv/concepts/projects/sync/). Pure offline tests do not qualify HTTP authentication, SQLite durability, actual Shuffle or live Wazuh effects.

[RF-01 expectations](expectations/rf-01.md) were committed before code. Tests derive valid/invalid outcomes from that matrix, including all state pairs and approval scope mutations. The [RF-01 ledger](rf-01-ledger.md) records red/green evidence, exact revisions, failures and limitations.

Published schemas live in [schemas/v1](../schemas/v1). Regenerate intentionally with `uv run --locked --offline python scripts/export_contracts.py`, review the semantic diff, then run `make schemas`. JSON Schema expresses structural constraints; Python model validators enforce additional cross-field invariants listed in the [design](rf-01-design.md). Schema-only validation is insufficient for dispatch authorization. Wire models are immutable scope carriers, not proof of identity or signed approval tokens. Credentials and stored approvals must come from trusted server code.
