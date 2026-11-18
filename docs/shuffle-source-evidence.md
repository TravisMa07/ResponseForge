# Shuffle RF-04 source and manifest evidence

Observed2026-11-18, research only. Raw selected downloads and private working notes remain ignored/untracked; no platform source or image is vendored. The maintained facts below are independently usable without those notes.

## Pinned source

| Artifact | Revision and exact SHA-256 |
| --- | --- |
| [Shuffle Compose](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/docker-compose.yml) | source473cc335e5fcc663006d8e5ca16af5ee71fefa68; b613e692c6fcebb4444e590f55ad8f12514d7b87c9ea39be82d6708ccefd8e39 |
| [Backend routes/main.go](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/backend/go-app/main.go) | f1dd87c2013ce853580843dd2794cb345e869546148696afb6bfb95090b8b40e |
| [Backend execution/walkoff.go](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/backend/go-app/walkoff.go) | a14e17c667e6bab1fc2975db44a3836455c0d32acf0e01cf05e4446c14bffd53 |
| [Required shared module](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/backend/go-app/go.mod) | requires shuffle-sharedv1.3.22/f81e48ec7dfdd9fd0b94c207fb6b58535ed52a90; go.mod14739b99fb3149d9067516527e0656a8916ed5dda30bf05c8ad0e8bed10a6667 |
| [Shared execution logic](https://github.com/Shuffle/shuffle-shared/blob/f81e48ec7dfdd9fd0b94c207fb6b58535ed52a90/shared.go) | 184edc35032d0629011fdcf20f69644d85394e96b57102a43d951c191cc55f63 |
| [Shared wire structs](https://github.com/Shuffle/shuffle-shared/blob/f81e48ec7dfdd9fd0b94c207fb6b58535ed52a90/structs.go) | bcfdecbbb26c60662cbf431732224003d1de8f364a79f94369e6ae40158e5d5d |
| [Worker source](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/functions/onprem/worker/worker.go) | 4d0e7805460dec3bd82f73176e66d97e3a4df42580555e55d837f58f01a2b053 |
| [Orborus separate v2.3.0](https://github.com/Shuffle/orborus/blob/adcc814cb355b7f4b6cb869e0d8d5eed3c6baa95/orborus.go) | 38064c3840bf8416f55eab528067afd57d33a2bb113e45e6651efbbbbbfdc178 |
| [HTTP app1.4.0](https://github.com/Shuffle/python-apps/blob/4a3d72091be4eb4f0c1e01fbbf62e4183d6dcc6d/http/1.4.0/src/app.py) | d6f1c61c3c129a32e0e694343bc02e5a6522e1158a01f1650faf2f79191e73ce; independent app-source observation, not a qualified runtime image |

## API and safety facts

Backend main.go6565 and6642–6665 bind the specific lookup and workflow create/GET/start routes. Shared.go6865–6925 assigns a fresh UUID on create. PrepareWorkflowExecution26327–26409 accepts a client UUID, while27400–27430 does not establish existing-ID deduplication; backend walkoff1063–1225 saves/enqueues. Thus a correlation UUID is useful for lookup, not permission to retry a possibly accepted POST. Shared structs ExecutionRequest150–164 and WorkflowExecution1632–1663 establish string execution_argument and returned status/correlation fields.

Backend walkoff490–620 accepts execution_id lookup with API Bearer same-org fallback, avoiding retention of the sensitive per-execution authorization value. Raw results/actions/authentication may still appear in the vendor body; the adapter projects safe fields only. Terminal workflow snapshots are checked against the reviewed graph; actual snapshot normalization is unqualified.

Compose backend/Orborus mount Docker sockets; Orborus disables seccomp by default and services publish management ports. Worker/Orborus source requires Docker service/container discovery/creation or corresponding Kubernetes authority. DOCKER_HOST changes transport, not authority. Kubernetes is not a zero-authority shortcut. The inspected [Helm values](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/functions/kubernetes/charts/shuffle/values.yaml) warn predeployed-worker choices may still require object creation. Rootless/proxy alternatives remain unqualified, not declared impossible.

HTTP app source49–54 logs header strings;72–79 makes omitted verification unsafe. Its [API schema](https://github.com/Shuffle/python-apps/blob/4a3d72091be4eb4f0c1e01fbbf62e4183d6dcc6d/http/1.4.0/api.yaml) supports header/body/timeouts, but these source facts are not real transport/callback execution evidence. Do not supply a callback Bearer to that stock logging path.

## Registry metadata

`docker buildx imagetools inspect <reference> --format '{{json .Manifest}}'` inspected frontend/backend/orborus/worker latest and OpenSearch3.2.0 indexes and LinuxAMD64/ARM64 children. The resulting immutable index/platform references and observation instant are in [images.lock.json](../deploy/shuffle/images.lock.json). Only manifests/config metadata were read, no image pull/container startup. Backend ARM64 config had no OCI source-revision labels. Mutable-tag observations cannot establish binary equivalence to the source tag or a tested compatible set.

Host read-only commands: docker version/info/compose/buildx version, sysctl hw.memsize; current memorylimit8318844928bytes,15DockerCPUs,linux/aarch64,0runningcontainers,24GiBhost. No allocation/context/Swarm/kernel change occurred. Web documentation fetches later timed out during a resource-text refresh; no new resource minimum is inferred from that failed fetch. The candidate guest budget is explicitly an engineering proposal.

Shuffle root LICENSE is AGPL-3.0. Separate Orborus tagged tree has no LICENSE and GitHub reports license=null; do not infer separate-artifact terms or redistribution permission from another repository. Images/app/SDK dependency rights and notices remain a release gate. No upstream scripts were executed.

## RF-04B source corrections and callback boundary

Further inspection of the same pinned Orborus source found that `SHUFFLE_SWARM_CONFIG=run` selects Swarm, not ordinary standalone containers. Startup lines2826–2850 call `checkSwarmService`, whose lines2047–2095 include SwarmInit. The RF-04A candidate plan had this setting and must not be executed unchanged. Explicit empty config selects the source-default standalone branch. CLEANUP=false and SHUFFLE_CONTAINER_AUTO_CLEANUP=false disable optional cleanup, while SHUFFLE_SKIP_PIPELINES=true and SHUFFLE_PIPELINE_ENABLED=false avoid the inspected pipeline opt-in. SHUFFLE_AGENT_MODE=false keeps agent mode disabled.

These settings do **not** make shared Docker authority safe: `zombiecheck` is invoked at startup, periodically and shutdown (2473,2859,3311). Lines4674–4765 scan all containers using broad image/command/label matches, then stop/remove aged matches with Force and RemoveVolumes. It does not consult CLEANUP. A reviewed scoped implementation or proven enforcement boundary is required before Docker Desktop startup; merely granting permission does not preserve unrelated workloads. RF-04B therefore retains a mandatory shared-daemon cleanup blocker, even when target authority is recorded.

Additional independently inspected artifacts:

| Artifact | Revision / file SHA-256 |
| --- | --- |
| [Shuffle SDK](https://github.com/Shuffle/app_sdk/blob/abe5f4a14f876b68d2a82274dc033a99eca2f409/shuffle_sdk/shuffle_sdk.py) | abe5f4a14f876b68d2a82274dc033a99eca2f409 / 8cb06e8fd2275dc2ebbf1398db9dd92e38226330114d002f784b897c78d28409 |
| [Shared database connector](https://github.com/Shuffle/shuffle-shared/blob/f81e48ec7dfdd9fd0b94c207fb6b58535ed52a90/db-connector.go) | f81e48ec7dfdd9fd0b94c207fb6b58535ed52a90 / 2807ce5efd71c7e2f15fa5da20e59b071e76d9940d2518468211bec01b206dab |

SDK send_result690–742 preserves action parameters and captured logs in persisted results; parameter-resolution debug paths4177–4180 can also log values. Callback credentials must stay out of workflow/action parameters and execution arguments. Pinned worker5133 logs execution authorization in normal environment mode, and3053 logs expected/received authorization on mismatch. A credential-safe ResponseForge sender does not repair those upstream logs or SDK transport. Upstream runtime logs remain private and credential handling remains a qualification gate. No SDK is installed or vendored by RF-04B.

Database connector712–730 reads SHUFFLE_OPENSEARCH_CERTIFICATE_FILE into CACert; that existing setting is valid. The missing work is CA/server certificate provisioning and a reviewed read-only mount with matching SANs. SHUFFLE_CERT_DIR in shared.go is a separate external-client trust path. An initial incomplete source search missed the connector file; research corrected the finding before implementation, and no invalid environment rename was made.
