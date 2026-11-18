# RF-02 qualification ledger

Issue [#2](https://github.com/TravisMa07/ResponseForge/issues/2); [design](rf-02-design.md); [frozen expectations](expectations/rf-02.md). Integration owner primary. Storage writer `rf02_storage` owns storage only; core writer `rf02_core` owns core only; independent test writer `rf02_tests` owns tests/rf02 only; reviewer `rf02_review` is read-only. All use exact freeze `ce91caff6c8e92fd051708778a11bb0ac5c56bae` from merged RF-01 main `1e662c115410f64c7a44da9c635f346a36f43ca2`. No overlapping edits or agent commits/pushes.

## Baseline and failures retained

Date 2026-11-18, macOS ARM64, CPython 3.12.12, uv 0.13.6. Main is verified with `make qualify`: RF-01's 278 tests plus Ruff, strict mypy, schema/example and foundation checks pass on its actual merged revision. PR #11 merged; issue #1 closed. RF-02 issue #2 open; clean starting checkout preserved.

After freeze but before append-only implementation, independent test writer ran `uv run --locked --offline pytest tests/rf02/test_storage.py -q --tb=short`: **2 failed, 13 passed**. A usable SQLite transaction incorrectly allowed replacing audit and metric records; tests required rejection. This is behavioral red, not missing imports. Storage writer then added repository guards and raw-SQL update/delete/replacement triggers. Focused suite expanded to **19 passed**.

Storage writer's separate concurrent construction smoke exposed a migration race: pre-lock application/version reads could straddle another initializer's commit and misclassify the database. Moved identity reads under BEGIN IMMEDIATE and bounded WAL-mode contention; repeated 16 simultaneous constructors/writes across ten temp databases: **160/160 passed**. This is temporary-file concurrency evidence only, not a throughput benchmark.

Integration's early mypy attempt while core imports were not yet available reported missing-core/Any errors. This was an incomplete harness/dependency stage, not behavioral red. Initial in-process API smoke accepted health, rejected unauthenticated case access and generated Bearer-protected internal OpenAPI; it did not start a network listener. TestClient emits an upstream Starlette/httpx deprecation warning; the locked version remains functional and is not suppressed.

## Qualification and limitations

Independent review found and reproduced three material boundary gaps: (1) a valid-schema execution from case B stored under proposal A could be returned as A's proof; (2) case listing filtered only endpoint ID while detail reads required full canonical identity; (3) a pending verification with an out-of-window checked_at could be saved and subsequently block recovery. Exact cross-record binding, full canonical list filtering and all-present timestamp validation corrected them. New-result validation prevents corrupt writes; stale results cannot overwrite verified success. Reconciliation also retains the original configured provider version instead of silently selecting a replacement under the same name.

The pending-timestamp regression produced another independent behavioral red: `uv run --locked --offline pytest tests/rf02 -q --tb=short` reported **2 failed, 97 passed**, with past/future pending proofs incorrectly persisted. After the fix both regressions pass and later valid reconciliation succeeds. Pydantic serializer warnings on intentionally malformed model-copy objects could expose raw input; immediate revalidation now avoids raw-value warnings and still rejects invalid scope.

Two intermediate test-harness failures are retained separately: an unconfigured outsider fixture initially expected filtered listing instead of authorization denial; it was registered as an authorized empty-scope analyst to exercise the intended list oracle. A missing TOKENS import caused three NameErrors in newly added tests; the test writer corrected the import. Neither is counted as behavioral red or a production defect. No frozen requirement was weakened.

Read-only independent reviewer inspected the actual production/storage/runtime/API/CLI/lock/export artifacts against the freeze and reran qualification at **379 passing tests**, including all review regressions. No blockers remained. Integration then added and verified one full HTTP intake→triage→investigation→proposal→wrong-role denial→human approval→execute/verify→app recreation/duplicate path, bringing the complete suite to **380 passed** (102 RF-02 + 278 RF-01). Provider call/effect/verify counts remain one after restart and expiry. Reviewer findings were corrected by the assigned writer; shared interface refinements are recorded in the owning design.

| Gate at freeze plus integrated working tree | Exact command / observation | Result |
| --- | --- | --- |
| Offline behavior and regressions | `make qualify` | 380 passed; Ruff and strict mypy (9 source files) pass; 19 v1 schemas, six examples, internal OpenAPI and 23 Markdown docs pass |
| Real process death | `pytest tests/rf02/test_process.py` as part of qualification | Two child processes exit with code 73 after durable reservation, before/after a controlled synthetic marker effect; reopened DB blocks redispatch and verifies original marker only |
| Dependency lock | `uv lock --check --offline` | Consistent; exact direct pins and transitive distribution hashes |
| Package build | `uv build --offline --no-build-isolation` | Wheel and sdist built; archive inspection: 12/74 members, zero private handoff/local DB/log/evidence entries |
| CLI configuration and API export | Temporary private config via `python -m responseforge --init-config`; `--config ... --export-openapi ...` | Actual subprocess commands passed, generated credentials absent from output/OpenAPI, no listener started |
| Hygiene | `git diff --check`; foundation index check | Pass; private materials untracked |

Qualification environment: macOS/Darwin ARM64, CPython 3.12.12, SQLite 3.50.4, uv 0.13.6; FastAPI 0.164.0/Pydantic 2.14.3/Uvicorn 0.54.0; pytest 9.2.0/HTTPX 0.28.1/Ruff 0.17.5/mypy 1.20.2. One upstream Starlette TestClient deprecation warning remains visible. No warning suppression was applied to that upstream notice.

At clean implementation revision `29a425a38d68efe65850180684034e3e1335baac`, integration reran `make qualify` (**380 passed**, Ruff/type/schema/API/docs all pass), `uv lock --check --offline`, `uv build --offline --no-build-isolation`, and `git diff --check`: all passed before push. [PR #12](https://github.com/TravisMa07/ResponseForge/pull/12) targets main, depends on merged RF-01 #11 and closes #2 upon authorized merge. A final documentation-only evidence/status commit follows; no production behavior changes after this qualification.

Hosted CI was pending immediately after publication; its observed result is recorded separately in the PR. Owner acceptance, merge authorization and merged-revision verification remain open. RF-03's bounded next assignment is recorded in the [implementation ledger](implementation-ledger.md); real Shuffle and live endpoint gates remain unchanged. All provider exercises use controlled test adapters with explicit simulated effects. No real Shuffle execution, Wazuh endpoint effect, raw-log ingestion, replay engine, report pipeline, vendor-schema compatibility, release or merge is qualified by this package. No socket mount, agent installation, privileged host change or exposed management service occurred.
