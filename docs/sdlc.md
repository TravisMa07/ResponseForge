# Development workflow

Use the agentic SDLC with bounded packages in the [plan](implementation-plan.md). Owner requirements take precedence over derived documentation. Original handoff documents and private working notes remain local and untracked; publish only maintained project documentation. Public checks and clone instructions must work without local handoffs.

1. **Ready:** owning design states behavior, exclusions, interfaces, dependencies, failure modes, security invariants and observable independent expectations. Resolve consequential architecture changes with the owner and an ADR.
2. **Freeze:** commit substantive schema/state/security expectations before implementation. Derive oracles from requirements and source evidence, never from the implementation's outputs.
3. **Implement:** focused behavioral red → green → refactor. Harness failures do not count as behavioral red. Add unit/contract/integration coverage appropriate to the change.
4. **Qualify:** run offline tests with no VM/network; separately run real Shuffle and explicitly gated live suites. Preserve failures, artifact hashes, commands, versions and limitations in the owning ledger.
5. **Review:** independent inspection of actual changes and expectations. Passing CI is not owner acceptance. Only mark a feature qualified when its acceptance tests pass.
6. **Integrate:** short-lived branches, normally 1–3 cohesive commits, PR review packet and explicit merge authorization. No unrequested release. The owner-authorized initial public repository seed is the bootstrap exception.

Track planned, implemented, locally verified, runtime-qualified, owner-accepted, merged and merged-revision verification separately. Keep architecture, design, roadmap, ledgers and runbooks consistent. Do not manufacture empty test suites or passing CI to imply progress.

## Parallel work

Assign base revision and file ownership; freeze shared contracts before parallel implementation. Integration owner exclusively owns contracts, lockfiles, CI, shared documentation and merges. Agents must report changed files, tested revision, commands/results, objections and remaining gates. Serialize Docker integration runs and database migration integration. Review agents inspect artifacts read-only. See the plan for independent lanes.

## Checks by stage

Foundation: `make check` validates local Markdown links and required populated documents; `make doctor` inventories prerequisites without installing anything. These are documentation/tooling checks only.

RF-01 introduces locked Python dependencies, pytest, Ruff and typing. RF-02/03 add offline behavioral tests; RF-04 adds `docker compose config` and real runtime smoke tests. RF-05/06 add exported workflow regression and all scenario acceptance tests. RF-07/08 add captured Wazuh contracts and separately authorized VM tests. Run relevant tests for every change and required broader gates before integration.
