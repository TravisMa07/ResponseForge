# RF-04A qualification ledger

Issue[#4](https://github.com/TravisMa07/ResponseForge/issues/4); [design](rf-04-design.md); [independent freeze](expectations/rf-04.md); [target comparison/runbook](shuffle.md); [source evidence](shuffle-source-evidence.md). **Partial delivery, real runtime NOT RUN; issue#4 remains open.**

## Authorized merge and baseline

Owner authorized RF-03#13 merge. At expected head6c77f58 both hosted checks passed, no review submissions/unresolved threads, mergeable. Expected-head guarded merge method preserved commits and produced `bc303833d945578014377f4cb4a012a1bd157aca`; issue#3 closed. `make qualify` on that actual merged revision passed452tests/Ruff/strictmypy/schema/fixture/docs checks. No release occurred.

RF-04 starts there; design/oracle freeze `0f95a9f916d3b08bf5b7cedc8daafe0d41e2c282` precedes implementation. Read-only vendor/isolation research used separate ignored paths. Writer `rf04_vendor_contract` owns only client.py; writer `rf04_isolation` only deployment.py; `rf04_tests` only tests/rf04; `rf04_review` read-only. Primary owns models/coordinator/API/config, image lock, planning/check scripts, schema/CI/shared docs/qualification and centrally added report-secret regressions. No overlapping edits, agent commits/pushes or runtime stacks.

## Failures, corrections and review

- Usable streamed MockTransport checkpoint: GET normal/auth/projection passes but unallowlisted UUID reaches network; focused **1 failed,1passed**. Full client writer checkpoint **1failed,63passed**. Added allowlist, final client suite green. Initial prebuffered MockTransport responses raised StreamConsumed; harness/client buffering support corrected before the clean red; not counted as semantic red.
- Independent durable scope regression: schema-valid PlaybookRun with run_id B stored under key A allowed startA, **1failed,101passed**. Shared exact-run checks now cover preflight/reservation/duplicate/reconcile/save; no mutating request on mismatch.
- Independent review found preflight graphA/actual execution graphB could be reported bound to A. Runtime snapshot fingerprint is now exposed safely and required before terminal attribution; missing/changed graphs remain uncertain/running. Positive fixtures corrected to the full vendor WorkflowExecution snapshot shape; added four missing/changed terminal graph regressions. No invented red run is claimed after those fixes landed. Preflight/start remain separate operations; trusted vendor editing and runtime canonicalization remain explicit limitations.
- Config repr exposed private origin/CA; fields now hidden with secret key. Reviewer also found new configured vendor key omitted from default report secret list. Primary reproduced **2failed** JSON/HTML exports retaining synthetic KEY in a valid identifier, added that configured key to redaction, then both passed. No real credential used or logged.
- Read-only reviewer reran the integrated **562 passing tests** (110 RF-04 +452prior), Ruff, strict typing and lock/whitespace checks, then confirmed actual fixes/no remaining RF-04A code blocker. One upstream Starlette/httpx TestClient deprecation warning remains visible.

## Observed preparation evidence

Environment2026-11-18: macOS/DarwinARM64,24GiBhost; CPython3.12.12,SQLite3.50.4,uv0.13.6; Docker29.8.0linux/arm64,Compose5.5.1,buildx0.37.1,15CPUs,8318844928bytesDocker memorylimit. Zero running containers observed; other assets not inventoried. No VM currently supplied/running; owner asked both options evaluated, not a socket/privilege grant.

| Check at freeze plus integrated working tree | Outcome / claim boundary |
| --- | --- |
| `make qualify` | 562tests plusRuff,strictmypy20sourcefiles,v1schemas/examples,OpenAPI/replay-schema,fixturehashes,blockedplanpin/default checks anddocs pass |
| Transport wire/fault tests | Exact inspected routes/auth/stringargument; once-only mutations; bounded read retries/time/bytes; secret projection; no actual vendor connection |
| Real child-process exit73 | Durable reserved workflow start survives process death; duplicate sends no start; original UUID lookup only recovers. Transport/effect markers are synthetic, not Shuffle |
| `docker buildx imagetools inspect` | Five immutable index identities and10Linuxplatform manifests recorded; no pull/start and no release/binary/source compatibility proof |
| `scripts/shuffle_plan.py` for both targets | Real observed pins render ready=false with no authority; generated artifacts private/ignored |
| `docker compose -f <plan> config --no-interpolate --quiet` | Both primary actual-pin plans and four agent synthetic-pin target/flag combinations pass syntax only; no runtime |
| `uv lock --check --offline`, build, diff/index hygiene | Pass on current working tree; exact committed revision/archive inspection follows |

Raw source/manifest research and rendered plans stay local/untracked; public maintained summaries include immutable references and hashes. Failed web resource-text refreshes are recorded, no resource sufficiency claim inferred. Planner DNS aliases were made explicit centrally; read-only roots/capability/TLS/CA/bootstrap still require runtime qualification. The zero-running count does not narrow Docker API authority.

## Remaining gates

Specific execution target and any engine/socket/provisioning/exposure permission; binary/source correlation; pinned/reviewed app inventory and safe callback logging; artifact rights before redistribution; CA/private-secret bootstrap; resource measurements; genuine import/start/executed-snapshot/authenticated callback/restart/timeout/teardown evidence. No vendor, endpoint, management listener, Docker socket mount, privilege/resource/Swarm change or paid infrastructure was started. Full RF-04 and RF-05/06/live/release gates remain open. A partial PR must Refs#4 and cannot close it.

Exact implementation revision and PR reference follow in final evidence. Owner review/merge and any runtime authorization remain separate decisions.
