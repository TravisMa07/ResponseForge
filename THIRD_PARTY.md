# Third-party software and data

This repository currently records integration plans and source references. No third-party telemetry or platform source is vendored by the Phase 0 dependency review. This inventory is not a license for ResponseForge itself and is not a complete runtime bill of materials. See [dependency evidence](docs/dependencies.md) for candidate versions and qualification gaps.

| Project | Reviewed terms / evidence | Intended use and obligations to resolve |
| --- | --- | --- |
| Shuffle | [AGPL-3.0 source license at v2.3.0](https://github.com/Shuffle/Shuffle/blob/v2.3.0/LICENSE) | Separate SOAR platform. Preserve notices and comply with applicable source obligations if modified/distributed; enumerate image/app dependencies before packaging. |
| Wazuh Docker | [GPL version 2 license and linking exception text](https://github.com/wazuh/wazuh-docker/blob/v4.14.10/LICENSE) | Optional live deployment recipes. Individual central components and bundled dependencies need their own inventory. |
| OpenSearch | [Apache-2.0](https://github.com/opensearch-project/OpenSearch/blob/3.2.0/LICENSE.txt) | Shuffle's upstream storage dependency; no custom ResponseForge search product. Verify bundled notices for selected images. |
| Splunk Attack Data | [Apache-2.0 root license](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/LICENSE) | Small selected recorded fixtures only after attribution/privacy review; preserve source commit, raw hash, license and transformation notes. No dataset is redistributed yet. |
| OTRF Security Datasets | [MIT root LICENSE](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE); [README says GPL-3.0](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/README.md) | Not selected for redistribution; resolve artifact-specific rights first. |
| Velociraptor | [Upstream source](https://github.com/Velocidex/velociraptor/tree/v0.77.3) | Optional future integration; license and dependency review deferred before adoption. |

Foundation CI uses `actions/checkout` v4.2.2 at commit `11bd71901bbe5b1630ceea73d27597364c9af683` under its [MIT license](https://github.com/actions/checkout/blob/11bd71901bbe5b1630ceea73d27597364c9af683/LICENSE). Python packages, base images and workflow apps must be added when selected. Do not assume a repository license covers every imported artifact, trademark, image dependency or dataset. Downloading public data does not authorize executing commands found within it.

RF-04A references inspected Shuffle/shared/Orborus/HTTP app source and registry metadata in [maintained evidence](docs/shuffle-source-evidence.md); raw source/images are not redistributed. Candidate plans are source-derived with upstream attribution and remain unqualified. Separate Orborus v2.3.0 tree lacks a LICENSE and GitHub license metadata; per-artifact terms must be resolved before redistribution rather than inferred from Shuffle rootAGPL. No stock HTTP app is vendored/patched/shipped by this PR.

## RF-04 source-built pilot

The runtime builder selects the licensed [Shuffle monorepo Orborus source at9ad57e0](https://github.com/Shuffle/Shuffle/tree/9ad57e0631a6ea4eb41e5b22b114d215be63dfdc/functions/onprem/orborus), under that commit's root AGPL-3.0 license. It does not use the later separate unlicensed tree. Backend/worker473cc335 and sharedf81e48ec7 are also exact locked Shuffle sources; the pinned SDK is a backend build input only, not the callback app runtime. [Source and module locks](deploy/shuffle/runtime) plus the published patch tool reproduce local modified contexts with preserved upstream LICENSE files and patch hashes. Raw upstream source and built images are not committed/published. Source redistribution obligations must remain satisfied if modified images are later distributed; no image release is included here.

The callback app is original ResponseForge Python code, installed from this same package; it uses the native wire protocol without a vendor SDK dependency. Base/frontend/OpenSearch identities are immutable platform pins. Go module sums and Python requirement hashes support reproducibility, not a complete legal or vulnerability clearance. Project license selection and release-time full transitive license/security inventory remain open. See the [runtime ledger](docs/rf-04-runtime-ledger.md) for the actually tested source/image binding and limitations.


## RF-06A dataset metadata

[Catalog](datasets/catalog.json) records a reviewed Splunk Attack Data Event1 XML artifact at the exact upstream revision above. RF-06A selectively acquires it only on explicit request and retains unchanged telemetry, LICENSE and manifest privately; no raw or normalized third-party telemetry is included in source distributions. The adapter is original ResponseForge code, and CI XML records are original synthetic test data. [Dependency review](docs/dependencies.md#rf-06a-reviewed-metadata-and-projection) describes root/per-artifact inspection, hash and attribution differences. Any later redistribution needs preserved terms, author/source attribution and transformation notices; source access and hashes are not independent legal clearance.


RF-06B1 adds reviewed catalog metadata for five Windows observation sources; [dataset review](docs/dependencies.md#rf-06b1-five-recorded-observation-sources) records exact paths/hashes, author attribution and limits. Raw telemetry and derivatives remain ignored/private; checked-in XML is original synthetic data. Windows/task projection and recorded rules are original Python code, with no vendored dataset tooling. Project license and release obligations remain unchanged.

## RF-07C1 dashboard client source

The opt-in [TLS source tool](docs/wazuh-tls-source.md) acquires only the exact ServerAPIClient, cookie helper and root LICENSE at Wazuh dashboard plugins commit `5005c3e2213abeb5c7798f489a7304a6abb7c6d1`; the [source lock](deploy/wazuh/tls-client/source.lock.json) identifies each artifact by path, size and SHA256. Both source headers state GPL version2 or later; the retained root license contains GPLv2. Private prepared output preserves original notices/license/source and a modification notice. This repository carries original preparation/test code and metadata, not those vendor source files or their emitted JavaScript. Full-plugin/image redistribution and its complete notices/dependency inventory remain separate gates.

The optional native component-test tool pins Axios1.17.0 and TypeScript5.5.2 with npm integrity locks; their installed packages remain private. Axios is MIT licensed and TypeScript Apache-2.0 licensed; transitive installed package licenses are retained by npm. These are component-test candidate dependencies, not a claim about deployed wazuh-core resolution or a complete product SBOM. Default offline CI does not install them.

## RF-07C2 platform compiler inputs

The exact [Wazuh dashboard platform](https://github.com/wazuh/wazuh-dashboard/tree/4a81e59ee597c0014e1d72666aa32423a964ba27) supplies Apache-2.0 preset/helper files, root LICENSE.txt/NOTICE.txt and build metadata. [Source lock](deploy/wazuh/platform-client/source.lock.json) pins each selected artifact; all originals and notices stay private. No upstream preset, inline source map or full emitted module is vendored. Node's official portable distribution/license, Yarn1.22.19 and @yarnpkg/lockfile1.1.0 (BSD-2-Clause), and actual installed dependency notices remain private. Babel tooling is MIT licensed; this inventory is not full plugin/image redistribution or vulnerability clearance. The original root lock contains both SHA1/SHA512 integrity entries; compatibility evidence does not upgrade those source artifacts' assurance.

## RF-07C3 shipped client artifacts

The [packaged-client source lock](deploy/wazuh/packaged-client/source.lock.json) binds an immutable Wazuh dashboard ARM64 manifest, payload/later-layer compressed hashes and DiffIDs,297 selected actual file hashes and30 nested Axios dependency roots. Original packaged platform LICENSE/NOTICE and GPL-noticed client/helper remain private. Source-map contents/body correspond exactly to reviewed C1/C2 sources/emission; no full vendor module is committed. Corrected private output retains original source/map, GPL terms and dated modification notice while removing its stale map. All30 selected MIT package terms are located:28 standalone LICENSE files and two full README sections, independently compared to exact npm/source revisions. README terms are already packaged; no missing-license waiver is asserted. Full-image redistribution/source-offer/security/license inventory remains separate. Context generation is not an image release or runtime proof.
