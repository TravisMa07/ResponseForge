# ADR0002: Shuffle execution authority

Status: **Docker Desktop selected for the pilot; dedicated VM remains supported. Scoped execution permission granted for the reviewed pilot; runtime qualification is recorded separately.** Date2026-11-18. Context/source evidence: [target packet](../shuffle.md), [inspected source](../shuffle-source-evidence.md).

Shuffle backend/Orborus/workers need Docker execution-plane authority or an equivalent Kubernetes control plane. A remote DOCKER_HOST, another context or broad socket proxy does not by itself reduce that authority. No source-proven working zero-authority runtime was found; that is not a proof one is impossible. The compact MVP remains one ResponseForge Python package/SQLite plus external Shuffle; Kubernetes/sensors/custom dashboard are not adopted.

Both deployment options remain viable:

- Existing Docker Desktop: least setup, current engine available (~7.75GiB memorylimit,15CPUs,0running at inspection), but granting its socket controls that daemon's other assets and accessible mounts. A consciously authorized isolated lab pilot is possible; no permission inferred from engine availability.
- Dedicated disposable Linux VM/daemon: extra setup/resource budget, but Docker authority can be contained in a separate guest with no development-host shares. Proposed local budget4vCPU/8GiB/40GiB is an experiment to review and measure, not a vendor minimum, existing VM or install/provision permission.

Recommend dedicated guest for repeated orchestration experiments; accept Docker Desktop as a candidate if the owner explicitly chooses its broader authority. Neither option removes app/source/image/secret/TLS/resource/runtime gates. No new tool, guest, Swarm mode, resource setting, public/LAN API or Docker-socket use has been authorized by this ADR.

A future execution proposal must bind the actual selected engine, permitted named services/worker/app creation, exact image/app artifacts, secret/CA paths, UI loopback or authenticated tunnel, egress, resource ceiling, unrelated workload preservation and teardown. No physical endpoint response or developer-host directory mounts are included. Any exception needed for capabilities/seccomp/networking must return for specific authorization rather than silently copying upstream defaults. Plans are render-only and always blocked until runtime qualification; labels are not an isolation mechanism.

The owner selection below amends the target recommendation; execution authorization and observed runtime evidence remain open. RF-04A partial PR stays Refs#4; full real-SOAR acceptance cannot close on stubs/config checks.

## Owner pilot selection, 2026-11-18

Owner selected the Docker Desktop container pilot, conditional on preserving full tool logic and keeping both deployment options viable. This accepts the pilot target, not a reduced-function product variant. Both targets must run the same ResponseForge core, Shuffle workflow definitions, authenticated contracts, approval/capability checks, durable delivery/reconciliation and effect-verification requirements. Differences belong to deployment configuration: engine/network addresses, TLS/secret bootstrap, architecture-specific images, resources, persistence and recovery.

No Docker Desktop-specific bypass or simulated substitute may weaken acceptance. Moving to a dedicated guest must not require rewriting domain logic or workflows; topology and platform compatibility still require real testing on each target. The selected pilot does not qualify a later VM automatically. Shared-daemon socket authority remains the separately scoped execution permission described above; no socket mount or startup occurred with this documentation update.

## Concrete pilot authorization

The owner explicitly authorized reviewed backend/Orborus/worker socket mounts on the existing Docker Desktop daemon, lab/generated test resources and UI/core exposure only on127.0.0.1:3443/8443. No Swarm, privileged containers, host settings, live endpoint actions or unrelated deletion. The [runtime ledger](../rf-04-runtime-ledger.md) records implementation, engine-bound evidence and remaining gates. This scoped grant supersedes historical statements above that permission was outstanding; broad socket authority remains unchanged.
