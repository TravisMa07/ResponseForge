# Wazuh sender and enrollment preparation

[RF-07B design](rf-07b-design.md), [independent expectations](expectations/rf-07b.md) and [ledger](rf-07-ledger.md) own exact behavior and evidence. These tools prepare artifacts; they grant no manager, endpoint or host authority. RF-07A [intake](wazuh.md) remains live-mode/no-provider/no-dispatch. Preparation and sender filesystem operations are qualified on POSIX hosts; the generated installer targets a separately authorized Windows x64 VM.

## Inspect the optional deployment plan

Use a private0600 JSON DeploymentTarget matching the [schema](../schemas/wazuh-deployment-target.json). For example, architecture=arm64,kind=docker-desktop,manager_id=lab-manager selects advertised ARM64 platform digests; it does not qualify that deployment. Render to a NEW file under a private directory:

```bash
mkdir -m 700 .local/wazuh-plans
uv run --locked --offline python scripts/wazuh_prepare.py plan \
  --target .local/wazuh-target.json --output .local/wazuh-plans/plan.json
```

The output contains a Compose object and explicit blockers/requirements. All three services are behind rf07-runtime-unqualified; ready and runtime_qualified are always false. Management is loopback-only55001/9201/9443, agent ports default loopback1514/1515, data volumes/network are isolated from Shuffle and no Docker socket/host network/privileged/sysctl is supplied. Nonloopback enrollment publication requires a separately authorized matching private lab target descriptor. A descriptor is not permission to start anything.

The private configuration tree, unique credentials, all stock demo users/security-index initialization, CA/SAN/node/admin/API identities, sender Python placement and resource/sysctl budget still need reviewed preparation and actual qualification. Required environment placeholders have no example-password fallback. Stock configurations must not be copied unchanged.

A pinned dashboard plugin hardcodes TLS certificate verification off on the manager API leg. A CA file or environment variable does not override that code. The plan therefore requires a separately reviewed source correction/new image and TLS/runtime qualification. Do not invoke its profile as a workaround. Registry metadata establishes advertised manifests only, not image-layer/source/runtime compatibility. No startup command is provided by this preparation CLI.

## Prepare the native sender

Store [SenderConfig](../schemas/wazuh-sender.json) as a private0600 file owned by the sender UID, with enabled=false initially. Copy the exact WazuhConfig manager/agent/source-actor binding from the receiving core; provide an absolute fixed HTTPS native-intake destination, CA, private token file, Integrator alert_root/alert_uid and private outbox_dir. Token file is32..512 URL-safe ASCII characters, with an optional final newline. No credentials or destination come from alert fields or upstream argv.

Private state must have trusted non-group/world-writable ancestry, except root-owned sticky temporary ancestors; final private directories are0700. Symlink ancestors, devices/FIFOs, hard links, wrong owners/modes, oversized/growing/changed source files and ambiguous JSON reject. Alert files must be direct children matching the pinned custom-responseforge-<digits>-<digits>.alert name. Dry-run checks inputs and source without creating even the outbox or a lock:

```bash
uv run --locked --offline python scripts/wazuh_prepare.py deliver \
  --config .local/wazuh-sender.json --alert /approved/alert-root/custom-responseforge-1-1.alert
```

The path above illustrates the required shape; it is not a real captured alert. After separate delivery authorization, enabled=true AND --send permit one attempt. Transport verifies the configured CA/hostname, ignores environment proxies, refuses redirects/compression, bounds response bytes/time and validates original UUID/status/duplicate receipts. Safe output exposes only delivery status and no source/token. It never launches a response action.

The native module entry point `python -m responseforge.integrations.wazuh.sender` reads only argv[1] and fixed `/var/ossec/etc/responseforge-sender.json`; hook/key/options/debug/retry arguments cannot override configuration. A reviewed manager image must contain the pinned Python3.12 package/interpreter and a fixed custom-responseforge entry point before installation. Host-side tests do not qualify the stock manager Python environment. Do not place tokens in upstream api_key/hook_url or enable raw debug logging.

## Recover without losing the original bytes

Wazuh unlinks its temporary alert after the integration exits. Before POST, the sender atomically publishes exact payload.bin plus receipt.json under its private outbox/<identitySHA>. Stage/files/parent entry and dispatch reservation are synced before sending. Outbox is limited to1024 retained deliveries; it never deletes history to make room. Unknown material/full state refuses before network. Token and raw bytes are not printed; payload.bin is sensitive private retained evidence.

State is prepared→dispatching→accepted/duplicate/rejected/uncertain. Repeating an acknowledged delivery returns cached with no new HTTP request. Unknown ACK/transport/malformed proof remains uncertain; ordinary repeat does not retry. Inspect the original receiver case before an explicit retry, using the opaque directory ID:

```bash
uv run --locked --offline python scripts/wazuh_prepare.py resume \
  --config .local/wazuh-sender.json --delivery-id <retained-identity-SHA>
```

Default resume is read-only dry-run. With separate authorization, --send --retry-uncertain permits one retained-byte attempt; --send --retry-rejected permits one known-refusal attempt after correcting token/rate-limit conditions. Token rotation does not change source binding; a changed destination/CA/source binding conflicts with old proof. Missing/tampered payload/receipt, pending write diagnostics or an unsafe path is never repaired/reset from a new alert. CLI/operator retry is explicit, not automatic backoff or a live effect claim. Local consistency checks are not cryptographic anti-rollback proof against same-UID or administrator replacement.

## Prepare the private Windows package

Use [WindowsBundleConfig](../schemas/wazuh-windows-bundle.json) with the exact target machine name, agent name, manager host, independently reviewed signing certificate Subject/thumbprint and private CA/client-certificate/key files. These are operator-authorized inputs, not alert fields. Obtain the signer expectation through a trusted administrative review; never populate it automatically from an untrusted installer or copy synthetic test identities. Certificate-based enrollment avoids a registration password in argv/logs. Source files must be regular and private key owner-only; matching copied key/certificate and CA parsing are checked without an interactive passphrase prompt.

Default preparation downloads nothing:

```bash
uv run --locked --offline python scripts/wazuh_prepare.py windows-bundle \
  --config .local/windows-bundle.json --output .local/windows-package
```

A NEW private directory contains the manifest, original installer script and three hash-bound private certificate/key files. It must remain private during transfer to the authorized VM. Existing directories refuse, including concurrent publication. The manifest hash is embedded in the script; preserve a trusted copy of generated script/manifest hashes outside the transferred package. Hashes are integrity checks, not signatures over an arbitrary substituted script/package.

Acquire the fixed official MSI separately only with explicit opt-in:

```bash
uv run --locked --offline python scripts/wazuh_prepare.py fetch-msi \
  --output .local/windows-msi --allow-download
```

The only permitted URL/version and published SHA512 are pinned. TLS, exact received hash, size/no-redirect/no-encoded-body and no-overwrite publication are enforced. This verifies downloaded bytes only; it does not establish Authenticode, publisher, platform, install or enrollment. Add --msi with that exact local file when preparing a NEW package; never overwrite a prior package.

## Native Windows execution stays separately gated

Default `Install.ps1` is read-only dry-run: no download, ACL change, reservation, process, service or network operation. -Install requires matching -TargetName, actual native Windows x64/admin/local machine identity, exact MSI SHA512, valid Authenticode and exact independently selected signer Subject/thumbprint BEFORE installation mutation. ARM/emulation is unqualified. Script/manifest/material/MSI handles remain read-locked; linked members are rejected, including native handle link-count checks before ACL hardening.

Only after those checks does the script restrict package ACLs to owner/Administrators/SYSTEM, persist dispatching state and invoke the fixed native msiexec with validated certificate-based properties. It passes neither arbitrary commands nor enrollment passwords and changes no global trust store. A prior reservation refuses automatic retry. Installer0/3010 means installed_enrollment_unverified; failures/unknown outcomes remain uncertain. MSI may change/create/start services itself; absence of a separate Start-Service call is not proof that no service effect occurred. Retain the private certificate files at their configured paths.

Real Windows hash/signature/ACL/installer/enrollment behavior and endpoint recovery remain NOT VERIFIED without separately authorized Windows tests. Portable macOS PowerShell parsing/dry-run/refusal and C# layout checks establish only those actual tested paths. Source/published metadata, synthetic loopback HTTPS, MSI byte acquisition and generated-package checks never replace real Wazuh capture, native live Shuffle or endpoint-effect proof. Full issue#7 and RF-08 remain open until their required evidence passes.

The next bounded correction is [RF-07C1 private TLS source preparation](wazuh-tls-source.md). Source/component checks do not enable manager startup or make the deployment ready.
