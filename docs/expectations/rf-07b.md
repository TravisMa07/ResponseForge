# RF-07B independent expectations

Issue [#7](https://github.com/TravisMa07/ResponseForge/issues/7); [owning RF-07 design](../rf-07-design.md); [operator boundary](../wazuh.md). Dependent base: RF-07A head `75e10f7249fbbe46edd117f70b8e119139784c78`. At kickoff GitHub still reports #22 open despite the owner's merge report; this document does not claim merged-revision qualification. Integration owns exact interfaces and records the final freeze before test/production GO.

These expectations derive from the owner requirements, existing RF-07A source/auth/provenance contracts and independent review of pinned Wazuh sources. They are not generated from implementation output. RF-07B supplies a configured native sender, an upstream-derived gated deployment plan and an administrator-executed Windows bundle. Preparing an artifact does not grant authority to start a manager, expose management/enrollment ports, change host settings or install/enroll an endpoint. Runtime, native Windows and actual sensor/Shuffle/action/effect evidence remain separately attributable gates.

## Source basis and claims

Wazuh v4.14.10 source commit `6e7835b4880c3210ef30e855a6bb43432be792e1` and Docker source `76ddb88b9c8b618a254a287f2684f93d3c5ac2f4` underpin the supported contract. The pinned [Integrator](https://github.com/wazuh/wazuh/blob/6e7835b4880c3210ef30e855a6bb43432be792e1/src/os_integrator/integrator.c) writes a temporary JSON alert delivery and passes arguments to the custom integration. It can reserialize source data and expose arguments/options in debug output. Thus credentials/destinations must come from fixed private operator configuration; api_key/hook_url arguments and alert metadata cannot become authority.

The pinned [single-node deployment](https://github.com/wazuh/wazuh-docker/blob/76ddb88b9c8b618a254a287f2684f93d3c5ac2f4/single-node/docker-compose.yml) has a manager, indexer and dashboard with separate persistent state. Source review found broad published interfaces, example credentials, demo internal users, disabled or partial hostname checks and enrollment defaults unsuitable for automatic adoption. Registry-advertised platform manifests establish immutable metadata only, not image-byte/runtime compatibility or a working secure deployment. Configuration completeness and actual TLS identity/credential bootstrap must be independently proven rather than guessed.

The [official Windows installer guidance](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html), [deployment variables](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html) and [package list](https://documentation.wazuh.com/current/installation-guide/packages-list.html) establish upstream package/enrollment interfaces. Published checksum text is not a downloaded binary hash, valid Authenticode signature, trusted publisher certificate, actual enrollment or Windows/ARM proof. The package's actual signature/publisher must be compared against independently supplied reviewed trust pins before installation, never learned from the untrusted file being approved.

## Configured native sender

| Boundary or scenario | Independent expected observable behavior |
| --- | --- |
| Default invocation / dry-run | Validate supported local inputs and produce a bounded safe plan/result, with no HTTP request, manager operation, file mutation or false delivery/endpoint success |
| Explicit send under valid private configuration | At most one request to the fixed configured HTTPS native intake endpoint, with verified CA/hostname and existing Bearer source credential; raw body is the exact source delivery bytes |
| URL/userinfo/query/fragment/path override, unsupported scheme or credential injection | Reject unsupported destination/configuration. Alert fields, command-line hook/api_key arguments, response bodies and environment proxies cannot change trusted destination, token, CA, method or API path |
| Caller-supplied `approved`, provider, mode, workflow, executable, command or callback fields | Remain inert telemetry; source mapper and receiver authority stay server-configured; no response or installer action follows |
| Source outside allowed agent/full endpoint binding | Reject before network I/O, preserving exact native ID/leading zeros/name and manager namespace rather than rewriting them |
| Private configuration or credential file has unsafe type/path/ownership/access | Refuse symlinks, device/FIFO/directory and unsupported permissions/owner; do not echo contents or silently loosen access |
| Alert file escapes configured root, is a symlink/hardlink/nonregular file, changes while read, is oversized or has untrusted owner/write access | Refuse rather than following links, truncating, accepting a partial file or reading arbitrary manager/host material |
| Valid bounded alert file with original whitespace | Byte sequence and SHA match RF-07A received-delivery contract; no JSON reserialization changes duplicate identity |
| Request timeout, disconnect, unknown acknowledgement or untrusted/malformed response | Preserve failure/uncertainty without automatic replay or simulated success; do not adopt a response-selected retry target or execution instruction |
| Redirect, TLS failure, proxy environment, HTTP error, oversized/invalid JSON response | No redirect or insecure verification fallback; fixed safe error/result, no raw credential/body leakage; the request is not silently retried |
| New-case response201 / exact-duplicate response200 | Validate bounded typed receipt identity and matching duplicate semantics. A syntactically valid unrelated/missing/inconsistent receipt cannot establish accepted delivery |
| Error/log/result/report rendering | No Bearer token, private config, alert body, native command text or raw response body is exposed; outputs distinguish dry-run, acknowledged delivery and uncertain/failed delivery |

Response limits apply during streamed consumption, before an eager HTTP buffer or decompression can expand untrusted data. Unsupported compressed responses reject. Controlled original synthetic byte streams should prove that consumption stops at the configured bound; a post-buffer length assertion is insufficient. Receipt identity/status fields are validated data, not a reason to print arbitrary response text or follow response instructions.

The native Integrator removes its temporary alert after the custom integration returns. Explicit sending therefore first preserves exact raw bytes and bound source/configuration in a private bounded outbox, rather than assuming alerts.json can later reproduce the same bytes. New delivery directories publish atomically before network I/O; only private owned regular files and protected directories are accepted. An exclusive POSIX lock prevents concurrent same-source submissions from racing; outbox capacity is bounded and existing content is never reset to make a retry pass.

The sender result vocabulary is dry_run/accepted/duplicate/cached/uncertain/rejected, with exact SHA/byte count, optional canonical UUID receipt identities and verified_live=false. HTTP4xx is rejected; timeout, unknown acknowledgement, redirect, oversized/compressed/malformed response and5xx remain uncertain.

A durable dispatching reservation is flushed before the HTTP mutation. Successful original receipts can return cached without another request. Dispatching/uncertain state remains uncertain after crash/restart and needs explicit scoped operator resume plus retry authorization to resubmit the preserved original bytes. Changed source bytes, receipt/configuration binding or authority conflicts refuse; token rotation alone may preserve an otherwise unchanged binding. A dry-run resume neither writes state nor sends. These controls establish delivery retry safety, not response-action authorization or cryptographic sensor proof.

Source authentication and durable receiver idempotency are not cryptographic sensor attestation. A successful mocked or loopback sender test establishes only its tested transport/receiver behavior, not actual Wazuh manager delivery. A repeated operator delivery may safely reach RF-07A's original receipt, but the sender must not blindly launch retries after unknown acknowledgement.

## Upstream-derived deployment plan

| Boundary or scenario | Independent expected observable behavior |
| --- | --- |
| Valid pinned platform metadata and supported target | Render only the reviewed manager/indexer/dashboard topology with exact per-platform digest references, isolated named state/network and documented upstream paths |
| Missing component, mutable tag, wrong repository/platform, malformed digest or conflicting source identity | Reject rather than silently selecting latest, another architecture, stock image name or first matching entry |
| Default host publication | Management/UI/enrollment bindings remain loopback; no wildcard/all-interface, public endpoint, source-selected destination or automatic firewall/routing change |
| Unapproved nonloopback binding | Refuse or retain an explicit blocked plan; a target descriptor is not a grant to expose a host or a VM |
| Socket/privilege/host change | No Docker socket, privileged flag, host network/PID/device access, broad host mount, host sysctl mutation, service start/pull or secret logging occurs during planning |
| Credentials/TLS/bootstrap requirements | No stock passwords, demo internal users/certs, disabled hostname verification, insecure certificate override or invented secure setting is presented as ready. Missing reviewed private bootstrap/TLS artifacts remain named blockers |
| Existing Shuffle resources | No OpenSearch reuse, conflicting default host port or deletion/mutation of old cases/images/volumes/services; Wazuh remains optional and separately scoped |
| Resources/architecture/host support | A resource descriptor or advertised ARM64 manifest does not claim measured combined capacity, macOS vendor support or actual image compatibility |
| Plan result / CLI | `ready=false` and concrete remaining qualification/authority gates remain until genuine secure configuration/runtime acceptance. No automatic `up`, pull, cert generation, privileged host change or false success flag |

Pinned dashboard plugin source hardcodes an API HTTPS agent with rejectUnauthorized=false. The plan must name that source-patch/new-image trust blocker; inventing an unsupported wazuh.yml CA key cannot close it. Stock demo-user, security-index and hostname/bootstrap limitations remain visible even after Compose environment fields change.

A pure plan can be functionally correct as a blocked artifact. Documentation must clearly distinguish that from a runnable, qualified deployment. If upstream cannot support a required TLS/security setting without a reviewed source change, keep the blocker visible instead of injecting unsupported configuration keys.

## Windows-first integrity/enrollment bundle

| Boundary or scenario | Independent expected observable behavior |
| --- | --- |
| Valid private target/configuration | Generate a bounded deterministic installation plan/manifest and reviewed PowerShell artifact into a new private output directory, without installing, starting a service, enrolling an agent or fetching a binary by default |
| Existing conflicting output or partially prepared bundle | Refuse overwrite, retain original diagnostics/material, publish complete artifacts atomically where supported and clean only newly owned temporary state |
| Default script execution | Dry-run only. No download, MSI invocation, host ACL/config/service/certificate change or enrollment action; output does not claim verified binary/signature/enrollment |
| Explicit install request | Require separately authorized administrator execution on the exact intended Windows x64 target with all fixed manifest, artifact and trust checks satisfied before any installer/service effect |
| Unsupported OS/architecture, nonadministrator or wrong target machine | Fail closed before download/installer/service mutation; WindowsARM64 and emulation are not silently accepted as qualified x64 |
| MSI absent, wrong source/version, altered/truncated/oversized bytes or digest mismatch | Refuse; exact official pinned SHA512 is rechecked locally immediately before use, not trusted from mutable download metadata or a filename |
| Unknown/invalid Authenticode, mismatched signer thumbprint/subject/publisher or missing independent trust pin | Refuse installation; never skip signature validation, learn trust from the same file, or treat successful SHA alone as publisher verification |
| Manifest/script/material tampering or symlink/path escape | Reject missing/conflicting source identity/material hashes and unsafe file placement. Untrusted configuration stays data rather than interpolated PowerShell or shell code |
| CA/client certificate/private key material | Hash-bind exact reviewed material, keep private files out of Git/logs/argv, use source-supported certificate-based registration and restrictive local access; no default plaintext enrollment password property |
| MSI command construction | Fixed executable/action and source-supported property names; values passed safely as data with no Invoke-Expression, arbitrary executable/command, credential text or alert-driven argument |
| Installation reservation/failure/restart | Persist a private original attempt state before mutation; unknown or prior attempted installation suppresses blind rerun. A failed/partial MSI or service step remains failed/uncertain and requires inspection rather than automatic uninstall/retry |
| MSI success / service start | Distinguish installer result from service status, agent registration, sensor delivery and verified endpoint effect. MSI0 alone cannot become `enrolled=true` or `verified_live=true` |
| Verification/recovery/operator notes | Declare prerequisites, out-of-band access, private material provisioning/rotation, actual enrollment checks and teardown limits. No fabricated signing identity, installed agent, supported Windows platform or rollback proof |

Certificate/key parsing must not prompt interactively for an encrypted key or fall back to a default passphrase. Unsupported encrypted material refuses safely without logging contents.

The exact package/manifest interfaces and allowed source-supported MSI properties are integration-owned. Independent tests will freeze those interfaces before production GO. A cross-platform generic digest test may use original synthetic bytes and a trusted test vector, but it must be labeled as generic integrity behavior rather than a real MSI signature/install result.

## Independent qualification and red/green

Before substantive implementation, preserve the final design and this independent expectation freeze. Focused intended reds must demonstrate missing valid sender behavior, missing valid gated profile and missing valid bundle preparation against importable fail-closed scaffolds. An import/setup/network failure is not behavioral red. Original synthetic inputs and test CA/material fixtures keep default CI offline and independent of downloads.

Test negative, failure/recovery and success behavior at actual public boundaries, including malformed configuration, path/permission/race defenses, exact request bytes and no-I/O defaults, TLS/redirect/status/response uncertainty, profile blockers and nonmutating generation/integrity behavior. Static generated-script checks or PowerShell AST parsing do not substitute for executing native Windows hash/signature/ACL/MSI/enrollment behavior. If native Windows is unavailable, state that gate as unverified instead of supplying mock positive native proof.

Record exact revision, command, environment and artifact hash with each bounded result. Independent actual-artifact review must inspect generated sender/profile/bundle outputs and their private/redacted evidence, not only an author-written summary. Passing offline checks, published source inspection, actual manager runtime, captured endpoint contracts, Windows execution, owner acceptance, merge authorization and merged-revision verification remain distinct gates. Full issue#7 and RF-08 remain open while required later evidence is absent; use Refs#7 for partial delivery.
