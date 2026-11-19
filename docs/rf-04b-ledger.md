# RF-04B qualification ledger

Issue [#4](https://github.com/TravisMa07/ResponseForge/issues/4); [design](rf-04b-design.md); [frozen expectations](expectations/rf-04b.md); [source findings](shuffle-source-evidence.md). Partial callback transport and deployment safety corrections, not real Shuffle runtime acceptance.

## Base and ownership

Owner authorized RF-04A [PR #14](https://github.com/TravisMa07/ResponseForge/pull/14) merge. Final head `4c2e7e018a0f20331cc894ea621a512de4e06899` had both hosted qualification checks successful, no submitted reviews/unresolved threads and was mergeable. Expected-head guarded merge preserved history as `2e1c95b3af3bb5820859ab31a3646eb54c465a6a`. `make qualify` on that actual merged revision passed all 562 tests, Ruff, strict typing, schema/example/fixture/plan/docs checks. Issue #4 remains open because #14 used Refs #4; no release occurred.

Branch `feat/rf-04-pilot-preflight` starts at that merge. Freeze `585f5f641a6dbdd7da3cdf0fe0f5d87d54b4b862` precedes code. Primary owns integration, source summaries, shared status/tooling/CI and qualification. `rf04b_callback_research` researched source read-only then owns only callback.py; `rf04b_pilot_research` researched source then owns only deployment.py; independent `rf04b_tests` owns only tests/rf04b. All raw downloads/notes are ignored. No overlapping edits, agent commits/pushes or runtime stacks.

## Failures and corrections

- Independent planner red at freeze plus tests: `uv run --locked --offline pytest tests/rf04b/test_deployment_safety.py -q` gives **6 failed, 1 passed**. Four failures expose Swarm run vs empty standalone flag; two expose missing mandatory shared-daemon cleanup blocker despite empty supplied gates/authority flag. Writer proceeds only after this checkpoint.
- Callback scaffold red after importable interfaces: two concrete wire/actual-core tests fail at unimplemented send, not import/setup. Implemented sender passes both. Expanded tests expose bypassed model_copy extra silently discarded by serialization: primary checkpoint **1 failed, 79 passed**, later writer checkpoint **1 failed, 88 passed**. Explicit unknown storage-field/extra checks now reject before I/O; all 89 RF-04B cases pass.
- First integrated `make qualify` passed 651 tests then stopped on one test-owned Ruff import ordering error. Test writer corrected imports/formatting; unchanged behavior then passes all checks. No failing check is waived.
- Independent read-only review ran 89 cases, Ruff, strict mypy21 and whitespace checks against actual artifacts and found no bounded code blocker. It identified an overbroad graph-completion documentation statement: narrowed to coordinator DeliveryRecord attribution and documented callback-reported PlaybookRun status separately. Full workflow reconciliation remains a runtime integration gate.
- Source research initially missed db-connector.go and suspected the CA variable unsupported. Fetching the pinned connector confirmed its exact use; corrected before code. Existing CA variable retained. No runtime failure or red is inferred from that research correction.

## Qualification scope and remaining gates

Environment: macOS ARM64, CPython3.12.12, SQLite3.50.4, uv0.13.6, locked offline dependencies. Sender tests against the actual in-process core establish application HTTP/auth/replay behavior; injected faults are synthetic. Neither an installed Shuffle app, worker credential injection nor genuine workflow is claimed. Candidate Compose parsing establishes syntax only.

Shared-daemon startup is technically blocked by unconditional vendor cleanup until scoped code or an enforced boundary is reviewed and qualified. Socket permission alone cannot repair it. Safe app/SDK/worker logging, pinned app/base image inventory, source/image correlation, CA/secret/bootstrap/private callback routing, scoped engine authority, resource measurements and actual workflow/recovery evidence remain open. Neither deployment choice may weaken common core logic. No image/container/listener/socket/Swarm/host-resource/live-endpoint operation occurred.

## Integrated working-tree evidence

`make qualify` passes **651 tests** (89 RF-04B +562 prior), Ruff, strict mypy21 sourcefiles, v1 schema/examples, internal OpenAPI/replay schema, fixture hashes, candidate pin/default checks and36 Markdown documents. `uv lock --check --offline`, `uv build --offline --no-build-isolation` and `git diff --check` pass. One preexisting Starlette/httpx TestClient deprecation warning remains visible. No dependency lock change.

Both target kinds and both Linux architectures rendered from actual candidate pins under ignored `.local/rf04b-qualification`; `docker compose -f <each-plan> config --no-interpolate --quiet` passes all four. This is parser evidence, not image compatibility/startup. Private artifacts are not staged. Clean implementation revision `b0bf0d675b872f1b73ac35c9c3705f3bb475f1b7` repeats every listed check successfully. [PR #15](https://github.com/TravisMa07/ResponseForge/pull/15) targets main and Refs #4; it does not close runtime acceptance. Archive inspection finds127 sdist members and24 wheel members, callback module present and private/handoff/local/database artifacts absent. Final documentation-only commit adds exact evidence/PR references; hosted checks are reported separately rather than inferred. No permission to merge this successor is inferred from #14 authorization.

## Next bounded runtime work

Before shared Docker Desktop startup, prepare a reviewed immutable execution artifact or enforced boundary that prevents Orborus/worker cleanup of unrelated containers, without suppressing real workflow logic. Keep per-artifact license/source correlation and upstream log-secret review explicit; no unreviewed upstream patch is vendored. Prepare private app credential injection and CA/container bootstrap, then request only the concrete remaining engine/exposure scope. Runtime must reconcile callback-reported status with polled whole-workflow/graph state and capture genuine success/failure/restart/timeout evidence. RF-05 real playbook qualification follows those gates; dataset research may overlap safely.

## Authorized merge and runtime successor

Owner-authorized #15 merge produced `e53002a68e525854da389c13399921fd4ffb39e9` from expected head22105cbd; both hosted checks succeeded with no submitted reviews/unresolved threads. `make qualify` on the actual merged revision passes651 tests and all tooling checks. Issue #4 remains open. The [runtime successor ledger](rf-04-runtime-ledger.md) owns source-built cleanup corrections, private bootstrap, explicit pilot authorization and genuine execution evidence; historical statements above describe RF-04B's bounded checkpoint.
