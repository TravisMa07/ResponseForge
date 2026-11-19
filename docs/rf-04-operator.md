# RF-04 pilot operator runbook

This runs the real Shuffle transport qualification lab on the selected Docker daemon. It uses the same ResponseForge application and policy core for Docker Desktop and a dedicated Linux VM. The [runtime design](rf-04-runtime-design.md) defines the controls; the [runtime ledger](rf-04-runtime-ledger.md) owns actual tested revisions, results and failures. A successful source build or startup is not qualification. The ledger records five actual Docker Desktop ARM64 scenarios passing at87ac23a; a dedicated VM and other architectures still require their own qualification. The pilot was stopped after verification with volumes/images retained.

The lab exercises a single callback action with bounded success, failure, delay and lost-acknowledgement scenarios. It does not install the three RF-05 domain playbooks, enroll an endpoint, run a host sensor or perform an endpoint response action. Replay cases and absence of endpoint effects remain explicit.

## Prerequisites and execution scope

Use Python3.12+, the locked uv environment, Docker/Compose, OpenSSL and `htpasswd` with bcrypt support. First run `uv sync --locked` and `make qualify`. Initial dependency and source/image acquisition requires network access; offline unit tests require no daemon, VM or network.

The execution target must be an explicit existing Docker context whose exact engine ID, Linux architecture and inactive Swarm state are verified before mutations. Commands do not switch the active context or enable Swarm. Docker Desktop and VM contexts may use different resources and addresses; each requires its own runtime evidence.

Startup requires a separately recorded owner grant for the chosen daemon, the lab's backend/Orborus socket access, dynamic worker/app creation, private generated-file mounts and the two loopback operator ports. `--authorize-engine` records acknowledgement of that grant; it does not obtain permission or enforce a restricted Docker API. A shared-daemon socket still has broad authority. The reviewed source patches and ownership checks preserve unrelated workloads within the tested lab; they are not a general Docker security sandbox. Do not broaden the grant to host directories, privileged containers, public/LAN APIs, host settings or live actions.

The reviewed layout is:

- Frontend UI/API: `https://127.0.0.1:3443`, forwarding to Shuffle backend on the private bridge.
- ResponseForge core API: `https://127.0.0.1:8443`, with the same authentication and policy controls as the local core.
- Backend, OpenSearch, Orborus and worker/app execution: private bridge only; no backend/indexer management ports are published.
- Frontend and core also attach to a gateway-enabled access bridge so Docker Desktop can forward the loopback ports. They do not publish additional interfaces.
- Callback credentials/configuration and CA live on the exact named private callback volume, mounted read-only into the reviewed app. They are never workflow parameters.

No container uses privileged or unconfined mode. Service roots are read-only with explicit writable state/tmpfs locations. OpenSearch has a named writable configuration volume for its keystore/startup state, with the generated configuration, administrator definition, CA and node certificate/key bound read-only over the required paths. This does not expose the host's Docker or system configuration.

## Build source-bound images

Choose the actual context; `desktop-linux` is an example, not an automatic target selection:

```bash
rf04_context=desktop-linux
rf04_engine_id=$(docker --context "$rf04_context" info --format '{{.ID}}')

uv run --locked --offline python scripts/shuffle_runtime.py build \
  --context "$rf04_context" --engine-id "$rf04_engine_id" \
  --work .local/rf04-build
```

The last JSON output names the generated `images.json` inventory. Keep its absolute path for preparation. Builds use the source-tree fingerprint in their output directory and image labels; raw build logs stay private there. A changed source/build input requires a new inventory rather than reuse of stale proof.

`sources.lock.json` pins individual source URLs and hashes. Preparation verifies them before applying exact-anchor patches and fails on drift. Backend/worker source is Shuffle `473cc335e5fcc663006d8e5ca16af5ee71fefa68`; Orborus is the licensed Shuffle monorepo revision `9ad57e0631a6ea4eb41e5b22b114d215be63dfdc`, under that repository's AGPL terms. The pinned SDK file is a build input, not a broad new core dependency. Upstream source is downloaded into ignored build contexts, not vendored into Git.

Resolved Go module files and their hashes are recorded under `deploy/shuffle/runtime/modules/` and `modules.lock.json`; builds check them rather than silently tidying/upgrading modules. Builder/runtime/Python base images are digest-pinned. Backend, worker, Orborus and core/app images are recorded by local immutable image ID; frontend/OpenSearch use architecture-specific registry digests. This is a source-pinned tested composition when the ledger proves it, not a claim that every component came from one vendor v2.3 release bundle. Source/image identity and qualification apply to the recorded engine/platform.

## Prepare private state without starting anything

Set `rf04_inventory` to the absolute inventory path printed by the build, then choose a new absolute state path. This example prepares an unapproved inspection plan:

```bash
rf04_inventory=/absolute/path/from/build/images.json
rf04_plan="$PWD/.local/rf04-inspection"

uv run --locked --offline python scripts/shuffle_runtime.py prepare \
  --inventory "$rf04_inventory" --state "$rf04_plan"
```

Preparation generates separate role credentials, a random OpenSearch administrator password/hash, a private CA and short-lived SAN-matched service certificates, configuration files and concrete Compose JSON. It creates no containers. Without `--authorize-engine`, the plan contains no socket binds or published ports and lifecycle mutations are rejected.

Preparation refuses an existing state directory or symlink path; it does not rotate or overwrite secrets in place. The parent state directory is private. Files mounted into non-root containers are individually readable inside those containers, while the private parent prevents other host users from traversing to them. Keep the CA private key, credentials, raw state, journals and logs untracked. Do not copy generated Compose/configuration or build inventories into public reports without review.

To execute after the owner has granted the concrete scope, prepare a **different new state directory** with acknowledgement:

```bash
rf04_state="$PWD/.local/rf04-pilot"

uv run --locked --offline python scripts/shuffle_runtime.py prepare \
  --inventory "$rf04_inventory" --state "$rf04_state" --authorize-engine
```

Do not toggle permission fields manually or add arbitrary Compose overrides. Each lifecycle mutation compares the selected engine and private Compose topology with the reviewed renderer, checks source-built image IDs and refuses fixed-name resource collisions that lack the project ownership label.

## Start and inspect

```bash
uv run --locked --offline python scripts/shuffle_runtime.py up --state "$rf04_state"
uv run --locked --offline python scripts/shuffle_runtime.py status --state "$rf04_state"

curl --fail --cacert "$rf04_state/pki/ca.pem" \
  https://127.0.0.1:8443/healthz
```

`up` acquires the two exact frontend/OpenSearch digests, seeds the exact labelled callback/core volumes with a short-lived helper, then starts the reviewed services. The helper has no Docker socket; its CHOWN capability applies inside its own container to the lab state volume, not a host directory. Existing unrelated assets are not reset or pruned.

Status prints safe service/state/health summaries. Its `runtime_qualified=false` is intentional: running services alone are not real workflow acceptance. Review private startup logs when readiness fails; a failing live/vendor operation does not fall back to mock success.

Use the generated CA explicitly with `curl --cacert` or the application's CA-file settings. Do not install the lab CA into the macOS system Keychain or use blanket TLS verification bypasses. Browser UI access must trust the specific lab certificate appropriately; administrator credentials are in the private `secrets.env`, not public documentation or command arguments. Close the loopback listener with `down` when the pilot is not needed.

## Run genuine qualification

```bash
uv run --locked --offline python scripts/shuffle_runtime.py qualify --state "$rf04_state"
```

This is a stateful integration test against the actual vendor and core APIs, not offline CI. It registers callback metadata with authenticated native `PUT /api/v1/apps`, imports reviewed nonempty workflows through the genuine API, records assigned IDs and graph fingerprints, seeds the private allowlist, and restarts core with those bindings. It does not invoke the vendor's app-build/remote-download activation path. The SDKless action uses the reviewed worker/native streams protocol and the same application image.

The harness requires agreement between actual vendor terminal execution/graph, the exact native callback action result and the core's authenticated callback audit. A callback-reported terminal `PlaybookRun` alone is insufficient. It exercises success, failure, callback acknowledgement timeout, core restart, lost start acknowledgement, duplicate intake/start, forged/unauthenticated/stale/replayed callbacks, vendor restart, exports, configured-secret log scanning, scoped teardown and persisted state after startup again. Bounded post-commit delay faults are confined to this opt-in pilot entrypoint and recorded in the audit; they do not waive normal authentication or policy.

An independently labelled sentinel matching the old broad cleanup heuristics must survive workload execution, vendor restarts and project teardown unchanged. The harness removes only its exact recorded sentinel after verifying ownership. A post-scenario resource snapshot is an observation, not a peak-capacity test or benchmark.

Private evidence is recorded in `qualification-journal.json`, imported `workflow-*.json` files and `qualification-summary.json`. Successful qualification prints the aggregate summary with `runtime_qualified=true`, `verified_live=false`, no endpoint effect and zero RF-05 domain workflows qualified. Any missing scenario, correlation, graph, callback audit, preservation or recovery evidence fails the run; the ledger must retain failures rather than infer success from a container exit code.

Do not delete a journal merely to force another start. It binds evidence to source/images/engine and preserves uncertain import/start identities. On an uncertain creation acknowledgement, inspect original vendor state before deciding how to proceed; there is no blind retry or automatic new execution identity. Runtime code/configuration changes require rebuilding and newly bound state/evidence.

## Stop without deleting state

```bash
uv run --locked --offline python scripts/shuffle_runtime.py down --state "$rf04_state"
```

`down` enumerates project-labelled containers, verifies each exact ID still carries the ownership label and removes only those IDs. Core, indexer, callback, apps/files and OpenSearch configuration volumes remain; images and networks are not broadly deleted. A subsequent `up` uses that persisted state. The qualification harness itself performs down/up to test persistence.

Do not substitute `docker system prune`, volume prune, broad image/name cleanup, daemon reset, Swarm changes or unrelated-container deletion. Full destruction of retained volumes, private credentials and CA material is a separate explicit retention/teardown decision, not part of this command.

The pinned vendor sanitizes UI diagram coordinates and native result app_id. Execution hashing excludes only top-level action diagram position; nested parameters remain bound. Native receipts must match the unique graph node ID, app name/version and function. Missing/empty sanitized app_id is allowed only with those bindings; a conflicting nonempty ID is rejected. Historical terminal delivery records lacking native proof fail409 and require inspection; they are not silently certified by a newer runtime.

For the optional RF-05B three-domain extension, use the current source-bound build and [native playbook operator notes](playbooks.md#native-shuffle-lab). Its separate `qualify-playbooks` command and source-bound domain journal do not inherit RF-04 callback-only qualification. Retain the same engine authorization and lifecycle limits.
