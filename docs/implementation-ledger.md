# Implementation ledger

## RF-00: repository foundation

Date: 2026-11-18. Integration owner: primary agent. Dependency/data research owner: `dependency_review` agent, owning only `docs/dependencies.md` and `THIRD_PARTY.md`. Initial base: empty directory, no prior revision. User authorized repository creation and public GitHub publication; no application deployment or endpoint operation performed.

Specification: `HANDOFF.md` copied byte-for-byte from the supplied attachment. Environment observations are in [environment](environment.md); upstream source/artifact references and hashes are in [dependencies](dependencies.md).

| Check | Observed result | Qualification scope |
| --- | --- | --- |
| Host, Python and Docker inspection | macOS ARM64; managed Python 3.12 available; Docker daemon and Compose reachable | Prerequisite inventory only |
| Upstream review | Release candidates and documented constraints identified | Not a tested compatible version set |
| Selected Splunk PowerShell artifact inspection | 16 process events; exact revision, content hash and fields recorded | Feasibility only; no replay test or fixture redistribution |
| Foundation local checks | `make check` passed on CPython 3.12.12 (14 Markdown documents); `make doctor` passed prerequisite inventory; both scripts compiled | Documentation integrity only |
| Negative prerequisite check | System Python 3.9.6 correctly rejected by `scripts/check_foundation.py` with exit 1 | Required-version enforcement only |
| Git hygiene | Secret/data/build ignore paths verified; handoff attachment SHA-256 matches `7106492044e15f27aa784db3f33a7de40106c8322918c0ce00898fd8f6df2fa6` | No external telemetry included |
| Publication | [Public repository](https://github.com/TravisMa07/ResponseForge) verified via `gh repo view`; default branch `main`; `git ls-remote` matched seed `2264efd95899cb6581be1c6f7346941671e2016f` | Public repository seed only |
| Hosted CI | Workflow committed; no run returned by `gh run list` immediately after seed push | Hosted CI result not yet verified |

No product tests exist yet: RF-01 introduces the application test harness with independent expectations. Phase 0 full acceptance remains open because vendor runtime/image/security qualification and remaining scenario evidence are not complete. This is intentional scope control for the initial repository request, not a claim that those requirements passed.

Independent read-only review by `dependency_review` found no foundation blockers, re-ran the documentation check and confirmed attachment equality. This is technical review, not owner acceptance of a runtime feature. `git diff --cached --check` reports only the original handoff’s intentional Markdown hard-break whitespace; preserve the source unchanged. Checks excluding that unmodified source pass.

## Ownership and gates

Historical foundation status: RF-01 was next ready for design/expectation freeze; current progress is recorded below. RF-02/03/04 can become independent lanes after RF-01 contracts are integrated at a recorded SHA. The integration owner owns shared contracts, lockfiles, CI and status; migration and runtime tests are serialized. Later assignments must replace planned lane names with actual owners and exact base revisions.

At the foundation checkpoint RF-01 through RF-09 were planned and unimplemented; the RF-01 update below supersedes only its contract/policy status. No releases, branch protection or required status checks are configured or claimed.

Reproduce local checks with `make check doctor PYTHON="uv run --no-project --python 3.12 python"` and `uv run --no-project --python 3.12 python -m py_compile scripts/check_foundation.py scripts/doctor.py`. Evidence applies to the foundation artifact containing this record; the initial Git commit identifies the exact files. Remote CI results, if available, are recorded separately after publication.

Seed revision: `2264efd95899cb6581be1c6f7346941671e2016f`. This follow-up ledger entry records publication evidence without rewriting that revision. Local foundation checks were rerun for this documentation update.

## Publication correction: local handoff policy

The initial seed incorrectly included the owner's handoff. Removed `HANDOFF.md` from the index while preserving the local file. Public docs no longer link to or require it. Added ignore rules and an automated index check rejecting handoff filenames and `docs/private/` content. Important maintained engineering docs remain public.

Validation: the new check first failed on the tracked handoff, then passed after removal. This proves the publication guard detects already-tracked handoff files even when ignore rules exist. At the time of this correction, historical seed commits still contained the original file. The owner subsequently authorized the history rewrite recorded below. The earlier inclusion/review records above describe that historical state, not the current publication policy.

## Authorized history cleanup

The owner authorized rewriting published history to remove `HANDOFF.md` from every commit on `main`. Rewritten foundation seed: `8876d49`; rewritten publication record: `e75c41d`; rewritten local-only policy correction: `797467a`. Earlier SHA references above are historical evidence identifiers and no longer identify commits reachable from published `main`.

Validation: inspected every rewritten commit tree for handoff filenames, confirmed no handoff history remains on `main`, and reran foundation checks. The original handoff remains an ignored local file. Publication uses an explicit force-with-lease against the previously observed remote head to avoid overwriting concurrent changes. Removing Git reachability does not guarantee deletion of cached GitHub objects or copies already cloned elsewhere.

## Analyst effort measurement

The owner requested tracking hands-on analyst time saved per eligible case. RF-01 defines the case readiness events and RF-09 collects the evidence using the [measurement plan](implementation-plan.md#measure-analyst-time-saved). A timed lab comparison is preferred. A documented estimate is an acceptable fallback and stays labeled as estimated. Collection is planned.

## RF-01 kickoff

Verified PR #10 merged on 2026-11-18; base `b6a44d6` on main. RF-01 branch `feat/rf-01-contracts`. [Design](rf-01-design.md) and [independent expectations](expectations/rf-01.md) freeze before code. Contracts/provider writer, policy writer and independent test writer have disjoint paths; primary owns tooling, CI, shared docs and qualification. No deployment or live action authorized or performed. RF-02/03 implementation and RF-04 investigation await proven contracts.


## RF-01 local qualification and next ownership

[PR #11](https://github.com/TravisMa07/ResponseForge/pull/11), issue [#1](https://github.com/TravisMa07/ResponseForge/issues/1), targets main because PR #10 already merged. Freeze `402ebb7`; implementation/proven contract base `6d8b4ecb025f254d1809eb5e53730bbc3973eacc`. Contracts/protocol writer `contracts`, policy writer `policy`, independent test writer `tests`; read-only artifact reviewer `review`. Primary owns integration, lock, CI, schemas/examples and status. Agent edits were disjoint and centrally reviewed.

At clean implementation revision `6d8b4ec`, `make qualify`, `uv lock --check --offline`, `uv build --offline --no-build-isolation` and `git diff --check` passed on macOS ARM64 / CPython 3.12.12 / uv 0.13.6. **278 tests pass**. Red failures, correction, review scope and limitations are in the [RF-01 ledger](rf-01-ledger.md). No API/storage/replay/provider runtime is qualified. Owner acceptance, merge authorization and merged-revision qualification remain open; no release performed. Issue #1 stays open until the authorized merge.

RF-02/03 implementation and RF-04 investigation have [prepared bounded assignments](next-packages.md) from that proven revision. Their actual agents are not assigned yet; their own designs/expectations and cross-lane durable interfaces must freeze before code. Real RF-04 runtime still depends on RF-02/03 and approved execution isolation. License, infrastructure and endpoint decisions do not block these offline design lanes.

## RF-02 kickoff and RF-01 merged verification

PR #11 was merged by the owner as `1e662c115410f64c7a44da9c635f346a36f43ca2`; issue #1 is closed. On that clean merged revision, `make qualify` passed: 278 tests, Ruff, strict typing, schemas/examples and documentation/index checks (macOS ARM64, Python 3.12.12, uv 0.13.6). RF-01 merged-revision verification is now observed, not transferred from its prior PR head.

RF-02 branch `feat/rf-02-durable-core` starts from that revision. [Owning design](rf-02-design.md) and [independent expectations](expectations/rf-02.md) freeze before code. Storage writer owns storage only, core writer owns core only, test writer owns tests/rf02 only; primary owns API/runtime/auth, locks, CI, shared docs and integration. No live action or deployment is part of RF-02.


## RF-02 integrated qualification

[PR #12](https://github.com/TravisMa07/ResponseForge/pull/12) targets main and closes issue #2 only after an authorized merge. Freeze `ce91caf`; clean implementation revision `29a425a38d68efe65850180684034e3e1335baac`. Storage writer `rf02_storage`, core writer `rf02_core`, independent test writer `rf02_tests`, read-only reviewer `rf02_review`; primary integration owner authored runtime/config/auth/API, OpenAPI/tooling, locks and shared docs. Edits were disjoint and centrally integrated.

On clean `29a425a`, `make qualify` passed **380 tests** (102 RF-02, 278 RF-01), Ruff, strict mypy, schema/example/OpenAPI drift and foundation/index checks. `uv lock --check --offline`, `uv build --offline --no-build-isolation`, and `git diff --check` passed on macOS ARM64 / CPython 3.12.12 / SQLite 3.50.4 / uv 0.13.6. Package archives contain no private material. One upstream Starlette TestClient deprecation warning remains visible. The [RF-02 ledger](rf-02-ledger.md) retains red/green evidence, review findings/corrections, test-harness failures and limitations.

Local runtime claims cover authenticated in-process HTTP and temporary-file SQLite, including actual child-process termination before/after a synthetic effect, restart/delivery suppression and verify-only recovery. These are simulated adapter effects, not real Shuffle or endpoint proof. No deployment, agent enrollment, endpoint action, merge or release performed. Hosted CI result, owner acceptance/merge authorization and merged-revision checks remain separate gates.

RF-03 is the next implementation package. It consumes the proven core/API at `29a425a` (or this branch's final documentation-only head), targets this branch if #12 is still open, and retargets main after authorized merge. Its adapter must match exact registered provider/version/mode/action, deterministic `exec-<proposal_id>`, original-idempotency query semantics and timestamp intervals. RF-03 owns replay/evidence/mock/reports; API/storage/contracts/locks/status remain integration-owned. Its own design/independent freeze precedes code. RF-04 discovery can overlap but real qualification waits for integrated core/replay and approved isolation. No RF-03/04 implementation is claimed here.

## RF-03 kickoff / RF-02 merged verification

RF-02 PR #12 merged as `6fc67660efc46e1a1a71cd193e61b066c12c2ec5`; issue #2 is closed. `make qualify` on that actual clean merged revision passes all 380 tests, Ruff, strict typing, schemas/examples/OpenAPI and foundation/index checks (macOS ARM64, CPython 3.12.12, uv 0.13.6). RF-03 branch `feat/rf-03-offline-replay` starts there.

[RF-03 design](rf-03-design.md) and [independent expectation matrix](expectations/rf-03.md) freeze before code. Planned owners: replay/evidence writer owns replay/investigation/fixtures; mock writer owns mock_edr; independent tests own tests/rf03; primary owns shared replay types, reports/driver/CLI, API/core/store registration, dependencies/CI/shared status and qualification. No downloaded corpus or live/SOAR runtime claim is authorized by this package.


## RF-03 integrated qualification

[PR #13](https://github.com/TravisMa07/ResponseForge/pull/13), issue #3, targets main (RF-02 #12 already merged). Freeze `3a6692f`; proven implementation revision `12f0f9afada5eff6d019a91fbaeac0c0c546275a`. Writers `rf03_replay` (replay/evidence/fixtures), `rf03_mock` (durable simulated provider), `rf03_tests` (independent tests); reviewer `rf03_review` read-only. Primary owns shared types, reports/driver/CLI, core/API/runtime, schemas/fixture checker, locks/CI and shared status. No overlapping edits or agent commits.

Clean `12f0f9a` passes **452 tests** (72 RF-03, 380 previous), Ruff, strict typing, schema/example/API/source artifacts, original fixture hashes and documentation/index hygiene. `uv lock --check --offline`, `uv build --offline --no-build-isolation` and `git diff --check` pass on macOS ARM64 / Python 3.12.12 / SQLite 3.50.4 / uv 0.13.6. Archive inspection confirms no private state/materials and includes production reports/mock modules. [RF-03 ledger](rf-03-ledger.md) preserves red/green/review corrections and limitations. Actual CLI reruns of all three original fixtures produce stable one-case outcomes: suspicious one simulated effect, benign/incomplete zero; two correlated metric events and JSON/HTML exports each. No genuine Shuffle/live claim follows.

RF-03 owner review/merge, hosted final-head CI observation and merged-revision verification remain distinct gates. No merge/release or vendor deployment performed. Issue #3 stays open until authorized merge.

## Next bounded package: RF-04

Start from [issue #4](https://github.com/TravisMa07/ResponseForge/issues/4), verified main after #13 merges or explicitly dependent local RF-03 revision `12f0f9a` while open. Read the owning design/ledger and capture exact base before assigning writers. The next integration owner owns contracts, callback persistence/auth, shared dependencies/image lock, CI and qualification; bounded investigation can own `docs/rf-04-design.md`, `docs/rf-04-ledger.md`, `deploy/shuffle/**`, `scripts/shuffle/**` and `src/responseforge/integrations/shuffle/**` after its own freeze. Independent expectation/review ownership must remain disjoint.

Concrete preparation: inspect official tagged Shuffle source, every backend/frontend/worker/app image manifest/digest and platform; recheck Docker allocation (last observed ~7.75 GiB ARM64). Produce an isolation/credential/loopback/TLS review packet before startup. Do not copy mutable upstream images or default host Docker socket mounts into an implicitly authorized deployment. No privileged/socket/paid/exposed action is authorized here. The proven replay path can qualify core contracts and internal callback replay rejection only; real transport acceptance must import/trigger a genuine workflow and correlate its run/case/action across restart and failure. No synthetic callback can close that gate. Source/transport compatibility refinements require central review rather than silently changing RF-01/02 contracts.

## Authorized RF-03 merge and RF-04 kickoff

Owner explicitly authorized merge of RF-03 #13. Verified final head `6c77f58`, both hosted checks pass, no review submissions/unresolved review threads, mergeable. Merged with expected-head guard using merge method (preserves freeze history) as `bc303833d945578014377f4cb4a012a1bd157aca`; issue #3 closed. `make qualify` on actual merged revision passes all 452 tests/tooling/schema/fixture/docs checks.

RF-04 branch `feat/rf-04-shuffle-transport` starts there. Read-only research owners `rf04_vendor_contract` and `rf04_isolation` examined pinned official source into separate ignored local notes; no upstream code vendored or services started. Host recheck: Docker29.8.0 linux/arm64, Compose5.5.1,15CPUs,8,318,844,928bytes (~7.75GiB). Registry manifest metadata shows LinuxAMD64/ARM64 for candidate frontend/backend/orborus/worker/OpenSearch; binary/source correlation and runtime unverified.

User has no running dedicated VM and requests both Docker Desktop and dedicated-VM routes be evaluated. [RF-04A design](rf-04-design.md)/[expectations](expectations/rf-04.md) freeze bounded transport/durable suppression/deployment preparation before code. Full RF-04 runtime remains open; partial PR must Refs #4. No engine/socket/privilege/exposure grant inferred. Primary owns shared models/coordinator/API, pins/locks/CI/docs/qualification; bounded transport and pure deployment planner writers and independent tests have disjoint paths.

## RF-04A integrated qualification

[PR #14](https://github.com/TravisMa07/ResponseForge/pull/14) targets main and uses Refs #4. Clean implementation revision `b3a9bb6df11fb34025a5e4867c576308c00a5f04` passes `make qualify` (562 tests, Ruff, strict mypy and schema/example/fixture/plan/docs checks), `uv lock --check --offline`, `uv build --offline --no-build-isolation` and `git diff --check` on macOS ARM64 / CPython 3.12.12 / SQLite 3.50.4 / uv 0.13.6. Wheel/sdist inspection found 23/120 members, production Shuffle client/coordinator present and no private/handoff/local/database artifacts. Final documentation-only commit adds references and repeats qualification; hosted CI is reported separately.

Both actual-pin target plans parse with Compose; no services were started. A dedicated disposable guest is recommended for separating engine authority; Docker Desktop remains an explicitly authorized pilot option. Neither target/engine grant is authorized. Source/image/app correlation, safe callback logging, CA/bootstrap, measured resources and genuine workflow/recovery evidence remain gates. Issue #4 remains open; merge/release requires owner authorization.

## Owner-selected pilot target

On 2026-11-18 the owner selected Docker Desktop for the pilot while requiring both deployment options remain viable and core tool logic remain identical. [ADR0002](decisions/0002-shuffle-execution-boundary.md) records the accepted target and invariant behavior. Workflow definitions, policy/authentication, evidence, durable recovery and effect verification must not be weakened for either host. Configuration, resources, networking and operational recovery differ; each target needs its own real-runtime proof. This target selection does not itself mount a socket or resolve the separately scoped shared-daemon execution grant and technical gates.

## RF-04A authorized merge / RF-04B kickoff

Owner authorized #14 merge at final head `4c2e7e018a0f20331cc894ea621a512de4e06899`; both hosted checks succeeded, no submitted reviews/unresolved threads. Expected-head guarded merge produced `2e1c95b3af3bb5820859ab31a3646eb54c465a6a`. `make qualify` on that actual merged revision passes 562 tests and all tooling checks. Issue #4 remains open for real runtime.

RF-04B [design](rf-04b-design.md), [independent expectations](expectations/rf-04b.md) and [ledger](rf-04b-ledger.md) own callback transport and shared-daemon safety corrections from freeze `585f5f6`. Callback writer owns only callback.py; planner writer only deployment.py; tests only tests/rf04b. Primary owns shared docs/scripts/CI/qualification. Source review found unconditional vendor cleanup beyond project scope and Swarm startup selected by the old candidate. No startup/socket/privilege change occurs; a scoped execution image/boundary must precede runtime, even with owner engine permission.

## RF-04B committed qualification

[PR #15](https://github.com/TravisMa07/ResponseForge/pull/15), Refs #4, targets main after #14 merge. Clean implementation `b0bf0d675b872f1b73ac35c9c3705f3bb475f1b7` passes `make qualify` with651 tests (89new), Ruff, strict mypy21, schemas/examples/fixtures/plans/docs; offline lock/build and whitespace checks pass. Four actual-pin target/architecture plans pass Compose syntax only. Wheel/sdist24/127 members contain the callback module and no private material. Independent review found no bounded code blocker; callback-reported vs graph-verified status documentation was corrected. The [owning ledger](rf-04b-ledger.md) retains red/green evidence and remaining scoped-cleanup/app/CA/runtime gates. No deployment, socket mount, privilege change, live action, release or successor merge occurred.
