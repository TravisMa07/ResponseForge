# RF-07C1: verified manager TLS source preparation

Issue [#7](https://github.com/TravisMa07/ResponseForge/issues/7). Base `4f16cfd7cc6679d9ab6e9cd8c53e7544f315642d`; independent [expectations](expectations/rf-07c1.md).

## Bounded outcome

Produce a private, deterministic correction of the reviewed Wazuh dashboard client and qualify the complete transpiled component with real Axios and Node HTTPS. Preserve all original source outside the constructor correction, including upstream notices, cookie parsing and authorization rules. Retain original source and GPL license privately alongside an explicit modification notice. No third-party source is redistributed in Git.

The HTTPS agent explicitly verifies certificates and names, forbids redirects and environment proxies, and rejects non-HTTPS, control-character, credential-bearing or fragment-bearing URLs before transport. Trust uses Node startup NODE_EXTRA_CA_CERTS; no explicit agent CA replaces the normal roots. NODE_TLS_REJECT_UNAUTHORIZED cannot weaken the explicit agent policy. No manager/container/endpoint is started by preparation.

## Frozen contracts

`tls_source.py`: frozen SourceMember(path,name,size,sha256), SourceLock(revision,members,patched_sha256); load_source_lock() reads the reviewed public lock. patch_client(raw,expected_sha256) verifies bounded original bytes and one exact constructor anchor. fetch_tls_source(output,lock,allow_download=False,transport=None) explicitly opts into fixed raw.githubusercontent.com/wazuh/wazuh-dashboard-plugins revision/member URLs; transport is a trusted test injection. prepare_tls_source(source,output,lock) verifies all members and the expected corrected hash before no-replace private publication. Python callers can supply trusted lock vectors for offline synthetic tests; the CLI accepts no alternate lock or source URL.

Inputs are three exact members named upstream-server-api-client.ts, cookie.ts and LICENSE, bounded at 32 KiB each. Prepared output retains those and adds server-api-client.ts, RESPONSEFORGE_CHANGES.txt and manifest.json. Existing outputs, unsafe descriptors, partial/wrong content, redirects and encoded bodies fail closed. Fetch verifies status 200, identity encoding, bounded bytes and fixed hash; no environment proxy is used. Outputs are private and never overwritten.

Native tools use pinned Axios 1.17.0 and TypeScript 5.5.2 installed explicitly with lifecycle scripts disabled in ignored private state. Independent qualify.cjs --bundle DIR --state-dir DIR verifies source hashes against the public lock, transpiles complete original/corrected modules and the actual cookie helper, then exercises fresh Node child processes against ephemeral loopback TLS fixtures. NODE_PATH resolves only the explicitly installed private toolchain. Original insecure acceptance must produce an actual HTTP exchange; import/setup failure is not red. Node 24.21.0 is the qualification environment, separately reported from Python CI.

## Remaining gates and ownership

Root owns integration contracts, source lock, production preparation/CLI, dependency lock and status. Independent expectation agent owns tests/rf07c and tools/wazuh-tls/qualify.cjs. Final independent review inspects actual private sources, emitted modules and observed results. Source correction/component tests are not a semantic TypeScript or full plugin build: upstream duplicate _axios declarations remain. Candidate dependency versions do not establish deployed wazuh-core resolution. Full image/build, certificate/bootstrap, capacity, real manager capture and native Windows/endpoint gates remain; deployment ready stays false.

RF-07A actual main merge 74a6e59 passed 2,562 tests. RF-07B actual feature-branch merge 4f16cfd passed 2,739 tests, with identical tree to reviewed 93ed2eb. Promotion [#24](https://github.com/TravisMa07/ResponseForge/pull/24) remains a separate owner merge and actual-main qualification gate.

## Observed C1 result

Implementation edc5e06 passes32 independent offline tests and13 complete-source native TLS scenarios; the [ledger](rf-07-ledger.md) and [aggregate](evidence/rf-07c1-component.json) attribute exact artifacts, genuine original-source red, corrected transport outcomes and limitations. Full repository qualification passes2,771 tests/all checks. Full plugin/image/runtime gates remain unchanged.
