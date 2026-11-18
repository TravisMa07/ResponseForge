# RF-03 qualification ledger

Issue [#3](https://github.com/TravisMa07/ResponseForge/issues/3); [design](rf-03-design.md); [independent expectations](expectations/rf-03.md); [runbook](replay.md). Base main `6fc67660efc46e1a1a71cd193e61b066c12c2ec5` includes merged RF-02 PR #12; issue #2 is closed. The actual merged baseline passes all 380 RF-01/02 tests and tooling checks. Freeze `3a6692feb76b53a74a5ee134990ee4952d83f2c5` precedes RF-03 implementation.

Owners: `rf03_replay` wrote only replay/investigation/fixtures; `rf03_mock` only mock_edr; `rf03_tests` only tests/rf03; `rf03_review` inspected read-only. Primary owns shared replay models, core/API integration, reports/driver/CLI, schema/fixture tooling, locks/CI/shared docs and qualification. No agent commits, pushes, overlapping edits or stack runs.

## Failures, corrections and review

Independent behavioral red: `uv run --locked --offline pytest tests/rf03/test_replay.py -q --tb=short` at the freeze plus a usable parser produced **3 failed, 18 passed**. It retained unsorted JSONL/array order and emitted duplicate/conflicting records; imports, schema parsing and resource checks worked. Parser checkpoint SHA-256 `3613af6b868503e40e0b83d2e01aa37053378478d63a5ef1d65ad34281b903c8`. Only after this red was the writer signaled to implement ordering/dedup. Final replay/evidence module suite: 29 passed. Mock module/core fault tests also passed with actual simulated state/effect counters.

Read-only review reproduced and corrected three further gaps:

1. Case scenario/endpoint equality alone allowed attaching registered dataset A evidence to a forged alert for dataset B. Collection now checks the stored normalized alert against the exact registered source before provider I/O; five source mutation regressions reject with zero provider calls/persisted evidence. Explicit logical receipt variation remains valid when all source facts match.
2. Report denylisting missed auth/env shorthand and unknown future fields. Explicit safe-field projection plus sensitive-name filtering now redacts them in both JSON and HTML, alongside configured secrets/free text; hostile HTML and path identities cannot become markup or filenames.
3. Python's oversized-integer JSON ValueError escaped quarantine. Decoding now catches it safely; a valid neighboring JSONL event survives with the invalid row reported, and malformed whole-array input yields an explicit invalid_json result.

The reviewer fixes landed before the added regressions ran, so no extra red run is claimed for them. An intermediate API test fixture omitted the new trusted replay_batch and received 503; adding the required source registration corrected the harness. Initial CLI tests ran before flags existed and received argparse errors; these are incomplete implementation/harness observations, not behavioral red. No expectation was weakened. A global `reports/` ignore also hid the production source module; anchored it to `/reports/` rather than forcing ignored source into Git.

Read-only reviewer independently observed **452 passing tests**, Ruff, strict mypy, lock/whitespace and v1 schema/example checks; the then-pending OpenAPI drift was regenerated centrally and now passes. No remaining code blocker. Primary subsequently added truthful metric revision/environment attribution and bounded CLI errors/empty-source diagnostics, inspected those small refinements centrally and reran qualification. One upstream Starlette/httpx TestClient deprecation warning remains visible.

## Observed qualification

2026-11-18; macOS/Darwin ARM64, CPython 3.12.12, SQLite 3.50.4, uv 0.13.6. FastAPI 0.164.0/Pydantic 2.14.3/Uvicorn 0.54.0, runtime HTTPX 0.28.1; pytest 9.2.0, Ruff 0.17.5, mypy 1.20.2. HTTPX was promoted from development-only to exact-pinned runtime dependency for ASGI replay; no new package versions introduced.

| Check at freeze plus integrated working tree | Observed outcome / bounded claim |
| --- | --- |
| `make qualify` | 452 tests (72 RF-03 + 380 prior), Ruff, strict typing, v1 schemas/examples, internal API/source schema and documentation checks pass |
| `uv lock --check --offline` | Exact metadata/lock consistency passes |
| `uv build --offline --no-build-isolation` | Wheel/sdist build; final archive/index inspection remains part of committed qualification |
| `scripts/check_fixtures.py` | All three original synthetic fixture bytes match manifest hashes; no corpus fetch or external license assumption |
| Actual CLI on each checked-in fixture twice | Suspicious: one RESOLVED case, one verified simulated effect; benign/incomplete: one RESOLVED case each, zero effects. Each retains two correlated metric events and JSON+HTML reports |
| Fault/recovery and rollback | Production mock + core exercise before-effect failure, committed-effect error/timeout, new provider/core instances, duplicate suppression and explicit approved unisolate; effects remain simulated |
| Report/API security | Source substitution, cross-case/window/mode, authentication/scope, known secrets/free text/raw/auth/env/future fields, markup and path injection regressions pass |

The manual CLI proof used isolated ignored directory `.local/rf03-qualification-2387dffb` (six invocations). Metrics truthfully record `3a6692f...-dirty` and the qualification environment; this is not a benchmark or clean-clone claim. Local raw state/reports stay untracked. Public evidence consists of safe results, exact commands/versions, original fixtures and independent expectations.

At clean implementation revision `12f0f9afada5eff6d019a91fbaeac0c0c546275a`, integration reran `make qualify`, `uv lock --check --offline`, `uv build --offline --no-build-isolation` and `git diff --check`: all pass; **452 tests**. Wheel/sdist inspection found 18/97 members, the production report/mock modules present, zero private/local database/handoff/report artifacts. [PR #13](https://github.com/TravisMa07/ResponseForge/pull/13) targets main and closes #3 only upon authorized merge. Final documentation-only commit records this evidence/status and downstream ownership. Hosted CI was pending immediately after publication; observed result is reported separately in the PR. Owner review/acceptance, merge authorization and merged-revision checks remain open.

RF-04's next bounded investigation consumes the proven revision and must freeze its own design, source/version evidence and expectations before implementation; see [current integration ownership](implementation-ledger.md). Real Shuffle execution, actual endpoint effect, external recorded-data/scenario qualification, Docker/fresh-clone release, performance/analyst savings and vulnerability/license audit remain open downstream gates. No merge, release, deployment, agent install, socket mount, privileged host change or external endpoint action occurred.
