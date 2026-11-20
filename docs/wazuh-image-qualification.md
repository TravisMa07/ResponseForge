# Controlled image qualification packet

[RF-07C4 design](rf-07c4-design.md), [expectations](expectations/rf-07c4.md) and [ledger](rf-07-ledger.md) own this gate. The current implementation prepares and checks a private execution packet. Actual image build and isolated fixture execution require a separate owner grant. Neither a PR merge nor CLI flags supply that grant. The existing Shuffle pilot grant does not extend to Wazuh images.

The concrete proposed grant covers one pull of the [locked ARM64 parent](../deploy/wazuh/image-qualification/source.lock.json), one local FROM/COPY-only image build, and one ephemeral Node TLS fixture on the reviewed Docker Desktop engine. The entrypoint is the primary bundled Linux Node, never the dashboard entrypoint. The fixture uses uid/gid1000:1000, network none, a read-only rootfs, ALL capabilities dropped, no-new-privileges, no healthcheck,1GiB memory,2 CPUs,128 PIDs and a64MiB noexec/nosuid/nodev private tmpfs. There are no host mounts, Docker socket, published ports, devices or external listeners. Only owned fixture cleanup is allowed; retain the local image and private diagnostics. No push, prune, manager/dashboard startup, host privilege change, enrollment, live action or release is included.

## Prepare and inspect without mutation

Use the reviewed [C3 bundle](wazuh-packaged-client.md). Keep all paths below private and untracked. Create a mode0600 target JSON containing the reviewed local context, Unix socket endpoint and engine ID; obtain these through read-only Docker context/engine inspection. The packet binds these identities, the Docker executable, source revision/fingerprint, reviewed input bytes, fresh run/nonce and a24-hour expiry.

```sh
node tools/wazuh-image/prepare.cjs \
  --bundle .local/packaged-bundle --output .local/image-fixture
uv run --locked --offline python scripts/wazuh_image.py prepare \
  --bundle .local/packaged-bundle --fixture .local/image-fixture/fixture.json \
  --target .local/image-target.json --output .local/image-run
uv run --locked --offline python scripts/wazuh_image.py preflight \
  --run-dir .local/image-run
```

Preparation uses host OpenSSL for original loopback fixture certificates. Preflight only inspects context and engine; both return qualified:false and execution_authorized:false. Review the generated plan, exact two-file context, source hashes and target before authorization. A clean reviewed source revision is mandatory for native execution. Changed source, inputs, expiry or target requires fresh preparation; never edit/reseal a plan to bypass a refusal.

After an explicit owner grant for this exact scope only:

```sh
uv run --locked --offline python scripts/wazuh_image.py execute \
  --run-dir .local/image-run --allow-image-build --allow-isolated-fixture
```

The controller independently validates executable bytes, snapshots the exact two-file build archive and fixture/bootstrap before mutation, and durably reserves execution. Docker receives the retained archive on stdin, not a mutable filesystem directory. Parent and derived image config/layers must pass before container creation. The unstarted container must pass containment inspection before attached execution. The retained runtime stdin binds run/nonce/immutable image ID. Logs record input size/hash rather than keys. Keys still exist in private fixture/runtime files: never publish the run directory.

The fixture verifies the primary Linux Node binary/license, installed corrected client and other296 selected files before vendor code executes. All13 actual TLS observations, strict source/image/session identities, exit0 and exact cleanup are required. Missing/failed/skipped observations or an injected Docker test double cannot qualify an image. Offline tests use original synthetic data and harmless child processes; they download and start nothing. Optional loader vectors run with `node tests/rf07c4/bootstrap.test.cjs` and also cannot qualify an image.

## Interrupted execution

An existing execution reservation prevents automatic retry even if a Docker CLI times out. Killing that CLI does not prove that the image build/container stopped. Inspect private execution/image/container intent, logs and result. After separately authorized cleanup of only the reserved fixture:

```sh
uv run --locked --offline python scripts/wazuh_image.py recover \
  --run-dir .local/image-run --allow-owned-cleanup
```

Recovery checks the exact engine, persisted CID (or the reserved name after a lost create reply), image and all ownership labels. It never starts/rebuilds/requalifies anything, deletes an image or cleans a foreign matching prefix. Unknown Docker failures are not interpreted as resource absence. Cleanup failure retains an uncertain, unqualified result.

No actual image run has passed at this implementation stage. The bundled Linux Node version remains unobserved. Even a later passing Node fixture leaves full plugin/frontend/platform bootstrap, whole-image licensing/security/source-offer review, private credentials/certificates/security-index/capacity, real manager capture, Windows and live endpoint proof open. Deployment readiness remains false.
