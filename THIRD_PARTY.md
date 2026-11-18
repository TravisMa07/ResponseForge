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
