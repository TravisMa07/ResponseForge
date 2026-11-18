# Dependency and dataset discovery

Reviewed 2026-11-18. This is a source-verification record, **not a tested compatible deployment lock**. No Shuffle, Wazuh, or Velociraptor service was started during this review. Image digests, runtime compatibility, vulnerability scans, workflow imports, and live endpoint behavior remain unverified. Phase 0's full dependency qualification gate remains open.

## Candidate version set

| Component | Inspected release / immutable source | Role and qualification |
| --- | --- | --- |
| Python | 3.12.12 selected for local foundation and RF-01 qualification | One application/package, replay CLI and tests. Host system Python 3.9.6 is below target. |
| FastAPI / Pydantic / SQLite tooling | FastAPI 0.164.0 / Pydantic 2.14.3 locked for RF-01; SQLite integration pending | API/contracts and local case state; no external application database. |
| Shuffle | [v2.3.0](https://github.com/Shuffle/Shuffle/releases/tag/v2.3.0), source `473cc335e5fcc663006d8e5ca16af5ee71fefa68` | Published 2026-09-28; candidate for real SOAR qualification. Source tag does not pin its container set. |
| Shuffle OpenSearch | `opensearchproject/opensearch:3.2.0` in tagged upstream Compose | Vendor dependency only; never use it as a custom ResponseForge SIEM. Digest and runtime pending. |
| Wazuh Docker | [v4.14.10](https://github.com/wazuh/wazuh-docker/releases/tag/v4.14.10), source `76ddb88b9c8b618a254a287f2684f93d3c5ac2f4` | Published 2026-11-05; manager/indexer/dashboard images each use `4.14.10`. Live phase only; agent version compatibility must be verified. |
| Velociraptor | [v0.77.3](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3) observed, not selected | Deferred optional read-only collection; no MVP dependency or compatibility claim. |

Release metadata and source files were read from official GitHub repositories over HTTPS. Versions are candidates identified at review time, not claims that these releases are safe or mutually compatible. See [third-party review](../THIRD_PARTY.md).

## Deployment feasibility and security conflicts

The [Shuffle v2.3.0 Compose source](https://github.com/Shuffle/Shuffle/blob/473cc335e5fcc663006d8e5ca16af5ee71fefa68/docker-compose.yml) uses mutable `latest` images for security, frontend, backend and Orborus, mounts `/var/run/docker.sock` into backend and Orborus, and publishes OpenSearch port 9200. Copying it unchanged would violate the handoff's reproducibility and default socket/network restrictions. **Do not start it as ResponseForge's default stack.** Before Phase 2, resolve and record tested immutable image digests (including workers/apps), reduce published ports, set loopback bindings and credentials, and decide how to isolate the orchestration execution plane. A dedicated lab VM/daemon or a verified restricted execution configuration is a proposal, not an accepted exception. Do not assume a socket proxy alone is sufficient. Record an ADR and obtain authorization for privileged deployment where required.

[Shuffle onboarding](https://shuffle.security/docs/onboarding) documents Linux or Windows/WSL2 and at least 4 GB RAM for lab testing. [Configuration guidance](https://shuffle.security/docs/configuration) lists a lab baseline of 2 vCPU, 4 GB RAM and 30 GB disk. Workflow import/export, HTTP nodes and webhook triggers are documented in [workflows](https://shuffle.security/docs/workflows); authentication and callback behavior still require a test against the chosen deployment. Do not execute copied `sudo`, swap or kernel-setting instructions automatically.

[Wazuh Docker requirements](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) currently list Linux/Windows and AMD64/ARM64 for central components, with a single-node minimum of 4 CPU cores, 8 GB RAM and 50 GB storage. The Linux Docker host requires `vm.max_map_count` of at least 262144. Mac Docker Desktop is not listed as a supported host in that page; running an ARM64 Docker daemon is not proof of end-to-end macOS support. The same page distinguishes a containerized agent from an agent that monitors the actual host. Install endpoint agents inside an explicitly supplied, authorized VM. [Enrollment](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html) and host/guest routes require separate verification.

Upstream Wazuh Compose publishes manager, indexer and dashboard interfaces and ships example credentials. Future overrides must restrict management access, replace defaults, preserve TLS verification, and expose enrollment/event ports only to the authorized lab subnet. Do not reuse Shuffle's OpenSearch instance for Wazuh or expose both stacks' default port 9200 on the same host.

| Target | Pure-Python replay | Shuffle | Wazuh central stack / endpoint |
| --- | --- | --- | --- |
| macOS ARM64 development host | Planned; Python >=3.12 required | Image manifest, worker/app architecture, Docker networking and socket isolation unverified | Central stack on macOS unqualified; endpoint VM architecture/OS support must be checked independently |
| Linux AMD64 | Planned CI target | Upstream-documented host type; ResponseForge runtime unverified | Upstream-documented central target; ResponseForge and endpoint action unverified |
| Linux ARM64 | Planned additional target | No architecture compatibility claim until every execution image is checked | Current upstream central Docker docs support ARM64; ResponseForge unverified |
| Windows endpoint VM | Not required for replay | Not an orchestrator dependency | Prioritized live target; installer, Sysmon compatibility, alert and safe action evidence pending |

Resource figures above are upstream minimums for separate products, not a measured combined budget. Reserve capacity for the application, worker bursts, indexers and a separate endpoint VM; the combined workload has no qualified minimum yet. Docker VM allocation, not total host RAM alone, gates feasibility.

## Minimum dataset inventory

No external telemetry is checked into this repository by this review. One small artifact was fetched into memory, parsed as data, and hashed; no payloads or upstream scripts were executed. Synthetic benign fixtures will be the offline CI default, with independent expected results. Recorded-source claims require a licensed, checksum-pinned artifact and separate acceptance evidence.

### Inspected PowerShell candidate

- Repository: [Splunk Attack Data](https://github.com/splunk/attack_data), commit `eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c`.
- [Metadata](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1059.001/trickbot_cmd_powershell/data.yml) labels T1059.001 and the `XmlWinEventLog` sourcetype. The metadata says it was automatically categorized; that label is not independent detection evidence.
- [Source path](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1059.001/trickbot_cmd_powershell/windows-sysmon.log): `datasets/attack_techniques/T1059.001/trickbot_cmd_powershell/windows-sysmon.log`.
- Actual LFS content: 46,116 bytes, SHA-256 `7ba1d02c6b44d877cfef9f4c690515ae04edb2347581ea93bb9657cb864aeec7`, matching the Git LFS pointer.
- In-memory XML parse found 16 Sysmon Event ID 1 records. Present fields include UTC time, computer, record ID, process GUID/PID, image, command line, parent GUID/PID/image/command line, user and hashes. This is raw XML event text, not JSON or EVTX; a bounded XML-export adapter or attributed normalized transformation is required.
- Observable suspicious signal: process command line invoking hidden, encoded PowerShell. Treat command lines as inert evidence. No decoding or execution is necessary for the first rule.
- It does not establish file-encryption effects, network connection telemetry, LSASS access or complete process lineage. Those require other records. Original timestamps and parent references must be retained; absent parents remain unavailable.
- Root [LICENSE](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/LICENSE) and README state Apache-2.0. Recursive source-tree inspection found no separate license file in this dataset directory. Before redistribution retain the license, attribution and transformation notices and review content for sensitive identifiers. This review establishes a feasible candidate, not an imported/qualified scenario.

The [upstream README](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/README.md) supports selective Git LFS acquisition and warns against pulling the entire corpus by default. Future fetch tooling must opt in, pin exact paths/commits, cap sizes and verify hashes before use.

### Remaining scenario candidates

The following metadata paths were located in that same Splunk commit; their data fields, hashes and artifact-specific rights have **not** yet been qualified. Phase 3 must inspect them before claiming scenario support.

| Intended scenario | Candidate metadata below `datasets/attack_techniques/` | Required next check |
| --- | --- | --- |
| Credential access | `T1003.001/atomic_red_team/atomic_red_team.yml` | LSASS target access plus correlated process records |
| Scheduled task | `T1053.005/atomic_red_team/atomic_red_team.yml` | Task and actor/process evidence, not merely a technique label |
| Ransomware-like indicator | `T1486/bitlocker_sus_commands/bitlocker_sus_commands_old.yml` | Narrow to observed command indicators unless actual file effects exist |
| Suspicious communication | `T1071/zeek_http_unusual_method/zeek_http_unusual_method.yml` | Network evidence; process association may be absent, so narrow claims |

[OTRF Security Datasets](https://github.com/OTRF/Security-Datasets/tree/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87) was reviewed at commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`: root LICENSE is MIT, while README's final license section says GPL-3.0. Do not infer per-artifact rights from either alone; use Splunk or original fixtures until artifact-level rights are resolved. Atomic-EVTX and EVTX Attack Samples remain unreviewed optional fallbacks; no acquisition is needed for Phase 1.

## Qualification work still required

1. RF-01 locks Python/application dependencies in `uv.lock`; [offline test setup](testing.md) and [qualification evidence](rf-01-ledger.md) cover contracts/policy only. Runtime and vulnerability/license scans remain separate gates.
2. Inspect image manifests for each selected architecture; pin digests and worker/app versions. Resolve the Shuffle socket boundary with a reviewed ADR.
3. Run dependency/image vulnerability and license scans; triage findings against official advisories. Release existence is not a security clearance.
4. Run Compose configuration checks, isolated startup, authenticated real workflow import/trigger/callback, restart and teardown tests. Capture exact versions, commands, logs and limitations.
5. Create a dataset manifest for imported artifacts with hashes, fields, provenance, rights and independent golden expectations; qualify all supported scenarios.
6. Separately verify live agent enrollment, sensor alert, approved safe effect and recovery on an authorized VM. Optional [Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) collection remains deferred.

RF-01 development versions: pytest 9.2.0, Ruff 0.17.5, mypy 1.20.2, Hatchling 1.33.0; uv 0.13.6. Direct dependencies and build backend are exact-pinned in `pyproject.toml`; the lock records transitive versions/hashes. No license decision is implied by these pins.
