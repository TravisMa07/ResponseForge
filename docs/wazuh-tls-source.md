# Private dashboard TLS source correction

[RF-07C1 design](rf-07c1-design.md) covers source preparation and a bounded native component check. It does not enable the optional deployment profile: full plugin build, deployed dependency resolution, image/runtime, credential/certificate bootstrap and real manager/endpoint gates remain open. No service starts through these commands.

The pinned dashboard client's HTTPS agent disables certificate verification. Preparation corrects that exact reviewed constructor and refuses all other source identities. It retains original source, cookie helper, GPL license and an explicit modification notice in private output. Keep these vendor sources, emitted JavaScript, certificates and dependency installs local and untracked. Do not redistribute them as a built product without a separate licensing/build review.

From the repository root, opt into bounded source acquisition, then prepare a new private output directory:

```sh
uv run --locked --offline python scripts/wazuh_tls.py fetch \
  --output .local/wazuh-tls-source --allow-download
uv run --locked --offline python scripts/wazuh_tls.py prepare \
  --source .local/wazuh-tls-source --output .local/wazuh-tls-bundle
```

Neither operation overwrites an existing output. The CLI has no alternate repository/revision/lock option. Fetch uses only the fixed reviewed HTTPS source members, refuses redirects and environment proxies, and verifies each exact size/hash before publishing. `--allow-download` is required; the Python environment itself stays locked/offline. Preparation is offline.

The native check requires Node 24.21.0, npm and OpenSSL; its dependencies are an explicitly selected component-test candidate, not evidence of the deployed wazuh-core resolution. Install only in private state, with package lifecycle scripts disabled:

```sh
mkdir -p .local/wazuh-tls-node
cp tools/wazuh-tls/package.json tools/wazuh-tls/package-lock.json .local/wazuh-tls-node/
npm ci --ignore-scripts --no-audit --fund=false --prefix .local/wazuh-tls-node
NODE_PATH="$PWD/.local/wazuh-tls-node/node_modules" node tools/wazuh-tls/qualify.cjs \
  --bundle .local/wazuh-tls-bundle --state-dir .local/wazuh-tls-native
```

The independent harness verifies the fixed original/corrected/helper hashes and transpiles the complete class and real cookie helper. It uses real Axios and loopback HTTP/TLS servers, with fresh children for startup trust policy; it does not replace Axios or TLS checks with success fixtures. Ephemeral fixture keys and emitted vendor code remain under private state. Listeners are stopped after the check. Its original-source baseline must demonstrate the known insecure HTTP exchange before corrected-client refusals count as evidence.

Python unit tests use independently authored synthetic text. Default CI does not fetch vendor source or install Node dependencies. Native component results are reported separately. Transpilation does not perform semantic TypeScript checking; upstream duplicate private `_axios` declarations remain, and a complete dashboard/plugin build is still required before image integration. Additional CA trust uses Node startup `NODE_EXTRA_CA_CERTS` and never modifies the operating-system trust store.
