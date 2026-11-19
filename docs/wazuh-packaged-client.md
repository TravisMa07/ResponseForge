# Verified shipped dashboard client overlay

[RF-07C3 design](rf-07c3-design.md) follows the source/component work by inspecting the actual immutable ARM64 dashboard package. It prepares a private correction and build context. No Docker build, image startup, manager operation, endpoint action or deployment readiness follows from these commands.

The reviewed image manifest is `sha256:83560991be21e1cc50f396bd2c8281f903b9a6a33918632057294b2300cfea65`. Its RPM-derived payload contains the reviewed client: embedded TypeScript matches the pinned source, map-stripped JavaScript matches C2 emission, and actual Axios1.18.1 uses a nested dependency layout. C3 preserves297 exact files across30 dependency roots instead of substituting the C2 workspace. The [source lock](../deploy/wazuh/packaged-client/source.lock.json) records compressed hashes, complete uncompressed DiffIDs, selected paths/hashes, source correspondence, dependency graph and terms.

From the repository root, explicitly acquire the selected payload and three small later layers:

```sh
uv run --locked --offline python scripts/wazuh_packaged.py fetch \
  --output .local/packaged-cache --allow-download
uv run --locked --offline python scripts/wazuh_packaged.py prepare \
  --cache .local/packaged-cache --source-bundle .local/wazuh-tls-bundle \
  --output .local/packaged-bundle
```

The source bundle is the reviewed [C1 prepared bundle](wazuh-tls-source.md), including original/patched TypeScript, cookie helper and GPL license. Fetch defaults off; it uses only the fixed public Docker pull scope, removes registry authorization before an allowlisted CDN redirect, and checks exact lengths/hashes before private no-replace publication. Cache/output directories must be new. It downloads292,316,941 bytes across four blobs, not the entire image. No Docker daemon is contacted and no image is imported.

Preparation verifies each compressed blob through the same owned no-follow descriptor used for streaming inspection. It verifies the full gzip stream/DiffID, bounds expansion/member counts/selected bytes, and never extractall or materializes archive links/ownership. Actual payload expansion is1,074,185,216 bytes, so the2GiB cap deliberately exceeds1GiB. Traversal/control paths, whiteouts, selected links/duplicates/ancestor replacements, relevant later-layer directory overrides, changed/missing files and malformed streams fail closed. Both hashing and decompression read passes stop a concurrently growing compressed file after at most declared size+one byte. This is a closed selected-artifact profile, not a general OCI extraction engine.

Prepared outputs include:

- `root/`: original client/helper and exact actual dependency files in archive-relative directories, including nested package copies and terms.
- `patched/server-api-client.js`: exact corrected compiled constructor, dated modification notice and no stale inline source map. The unchanged original/map and corresponding source remain separate.
- `build-context/`: digest-pinned FROM plus one COPY of the corrected client, with original/patched source, GPL license, actual platform LICENSE/NOTICE and change notice.
- `manifest.json`: artifact hashes with ready/runtime/image-built/image-executed/full-plugin flags all false.

The original packaged NOTICE is1,423,978 bytes; source NOTICE is a different artifact. All30 selected package roots contain MIT terms:28 LICENSE files and two README sections. The plugin is GPLv2-or-later, separately from platform Apache terms. Retain original notices and source provenance. Raw vendor source, JavaScript/maps, modules, layers, certificates, credentials and build output stay private/untracked. A complete image redistribution/source-offer/license/security review remains a separate gate.

With the separately verified private Darwin Node18.19.0 executable from the [C2 runbook](wazuh-platform-client.md), execute only the shipped component against original loopback fixtures:

```sh
"$RF_PLATFORM_NODE" tools/wazuh-packaged/qualify.cjs \
  --bundle .local/packaged-bundle --state-dir .local/packaged-native
```

No npm/Yarn install or compiler is needed for C3. The wrapper verifies every original and corrected artifact, retains verified buffers and copies them into fresh private state. It preserves nested dependency paths. The parent process does not execute shipped Axios; package versions come from verified metadata and are checked against real Axios in every guarded child. Each child permits only the snapshotted shipped files, generated client/helper and Node builtins. Ambient packages cannot execute. Setup/load errors cannot count as TLS refusal.

The native matrix reproduces original insecure certificate acceptance, then checks both authentication and requests for trusted success, actual chain/name refusals, global TLS-disable resistance, HTTP/userinfo/control URL refusal, redirects and hostile proxies. Results are component proof on the Darwin fixture Node. They cannot establish execution of the bundled Linux Node, an image, full dashboard/plugin/frontend or a real manager.

Optional original-module/profile checks retain negative setup evidence:

```sh
"$RF_PLATFORM_NODE" tests/rf07c3/guard.test.cjs .local/packaged-guard
"$RF_PLATFORM_NODE" tests/rf07c3/profile.test.cjs \
  --node24 "$(command -v node)" --bundle .local/packaged-bundle \
  --state-root .local/packaged-profile
```

The profile check needs a separate Node24 executable for wrong-version refusal. It also runs all13 real artifact scenarios with hostile ambient lookalikes; original fixtures must not execute an outside sentinel module. Default Python CI uses synthetic archives/source only and performs no downloads.

The generated context is review material for a separately authorized image build. Full platform bootstrap's Node18 engine conflict, whole-image/runtime compatibility, complete dependency/license inventory, private credential/certificate/security-index bootstrap, capacity, captured manager data, native Windows and live endpoint proof remain open. Deployment stays ready=False.
