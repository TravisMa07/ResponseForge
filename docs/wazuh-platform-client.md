# Platform-bound dashboard client check

[RF-07C2 design](rf-07c2-design.md) qualifies the complete client using the pinned dashboard platform's Node/Babel/Axios component environment. It does not build a full plugin or image, resolve deployed wazuh-core hoisting, start Wazuh, enroll an endpoint or enable deployment readiness. [C1 source preparation](wazuh-tls-source.md) remains the source of the original/corrected client bundle.

The platform pin requires Node18.19.0/Yarn1.22.19 and locks Axios1.18.1/Babel7.23.3. C1's Node24/TypeScript/Axios1.17 result stays separately attributed. Both actual upstream presets and the server helper options are used unchanged, including preset target Node14, CommonJS and inline source maps. Babel success is not semantic TypeScript checking.

Prepare reviewed platform inputs explicitly; default fetch refuses network:

```sh
uv run --locked --offline python scripts/wazuh_platform.py fetch \
  --output .local/platform-source --allow-download
uv run --locked --offline python scripts/wazuh_platform.py prepare \
  --source .local/platform-source --output .local/platform-inputs
```

These commands publish new private directories only. Eleven exact platform members, Apache LICENSE/NOTICE and original root package/Yarn lock are preserved. The added minimum manifest is authored from reviewed original selectors. All vendor files, emitted JavaScript/maps, modules, binaries and reports remain local/untracked.

For the qualified macOS ARM64 host, acquire the private portable Node binary at the URL in [source lock](../deploy/wazuh/platform-client/source.lock.json). It is a 40,660,307-byte archive with SHA256 `8907c42a968765b77730fb319458d63ec4ed009265f8012097c3a052407aa99b`. Verify that digest before safe extraction into a private directory. Retain its original LICENSE. No system Node installation is changed. Other platform artifacts and Linux image execution need separate qualification.

With `RF_PLATFORM_NODE` set to that private Node18.19.0 executable, install pinned Yarn/parser tooling and the minimum component dependency graph explicitly:

```sh
mkdir -m 700 -p .local/platform-yarn .local/platform-toolchain
chmod 700 .local/platform-yarn .local/platform-toolchain
cp tools/wazuh-platform/yarn/package.json tools/wazuh-platform/yarn/package-lock.json .local/platform-yarn/
npm ci --ignore-scripts --no-audit --fund=false --prefix .local/platform-yarn
cp .local/platform-inputs/package.json .local/platform-inputs/yarn.lock .local/platform-toolchain/
"$RF_PLATFORM_NODE" .local/platform-yarn/node_modules/yarn/bin/yarn.js install \
  --cwd .local/platform-toolchain --frozen-lockfile --ignore-scripts \
  --non-interactive --no-progress --no-default-rc
NODE_PATH="$PWD/.local/platform-toolchain/node_modules:$PWD/.local/platform-yarn/node_modules" \
  "$RF_PLATFORM_NODE" tools/wazuh-platform/qualify.cjs \
  --bundle .local/wazuh-tls-bundle --state-dir .local/platform-native \
  --platform-source .local/platform-inputs
```

The wrapper verifies all platform source hashes before executing verified preset snapshots, checks selected dependency versions and actual paths inside the audited private toolchain, and compares the installed graph to the unchanged original root lock. A controlled private node_modules link binds preset and emitted-client resolution to that tree. Parser tooling is separately pinned; its actual private bootstrap manifest/lock, installed metadata and loaded entry/package paths are checked before parser execution. No lifecycle scripts or engine checks are bypassed. Do not update the source lock or install a fresh dependency graph merely to make a failed check pass.

The first attempt with all54 root resolutions refused an unused serialize-javascript package requiring Node20+. The minimum manifest retains seven applicable root constraints; the audit ensures omitted constraints do not match installed packages, selected lock URLs/integrities match the original root lock, and installed versions belong to that selected graph. Older upstream SHA1 integrity entries remain visible in the report alongside SHA512; this is reproduction evidence, not full supply-chain clearance. Full platform bootstrap remains unqualified.

The native report includes genuine original insecure acceptance and all13 corrected trust/name/URL/redirect/proxy cases, actual emitted/preset/dependency/harness identities and compiler options. Node18 proxy tests establish Axios environment-variable behavior; they cannot establish Node24's newer global proxy mode. Setup/compiler errors fail separately and cannot satisfy a TLS refusal. No operating-system trust store changes occur.

Optional native negative checks use only original synthetic metadata and private copies of prepared inputs:

```sh
NODE_PATH="$PWD/.local/platform-toolchain/node_modules:$PWD/.local/platform-yarn/node_modules" \
  "$RF_PLATFORM_NODE" tests/rf07c2/audit.test.cjs
NODE_PATH="$PWD/.local/platform-toolchain/node_modules:$PWD/.local/platform-yarn/node_modules" \
  "$RF_PLATFORM_NODE" tests/rf07c2/profile.test.cjs \
  --node24 "$(command -v node)" --bundle .local/wazuh-tls-bundle \
  --platform-source .local/platform-inputs --state-root .local/platform-negative
```

The second command requires a separate Node24 executable for its wrong-version refusal. Default `make qualify` runs44 new offline Python cases without vendor downloads or Node installs. After shared-harness changes, run the original C1 command separately under its Node24/toolchain as a regression check.

The [C3 shipped-client overlay](wazuh-packaged-client.md) separately verifies the actual packaged dependency layout and prepares a private compiled-client correction. It does not transfer C2 component proof into an image runtime claim.
