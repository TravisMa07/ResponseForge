# Development environment

Observed 2026-11-18 during Phase 0; host inventory, not a supported-platform certification.

| Item | Observation |
| --- | --- |
| Host | macOS 26.5.1, Darwin ARM64, 15 CPUs, 24 GiB RAM |
| Available filesystem space | Approximately 774 GiB at inspection |
| Git | 2.50.1 (Apple Git-155) |
| Default Python | 3.9.6, insufficient for project baseline |
| Managed Python | uv lists CPython 3.12.12, 3.13.15 and 3.14.10 installed |
| uv | 0.13.6 |
| Docker | Desktop 4.92.0; client/server Engine 29.8.0 reachable |
| Compose | v5.5.1 |
| Docker Linux VM | aarch64, 15 CPUs, 8,318,844,928 bytes (~7.75 GiB) memory |
| GitHub | CLI authenticated; target account TravisMa07 |
| Repository at start | Empty directory; no Git history or remote |
| Endpoint VM | None supplied or inspected; no enrollment authorized |

Commands: `uname -sm`, `sw_vers`, `sysctl -n hw.memsize hw.ncpu`, `df -h .`, `git --version`, `python3 --version`, `uv --version`, `uv python list --only-installed`, `docker version`, `docker compose version`, filtered `docker info`, `gh auth status` (credentials excluded from committed evidence).

## Portability boundaries

macOS ARM64 is available for Python foundation checks and a Linux ARM64 Docker engine. Shuffle/Wazuh images and worker execution are not yet runtime-qualified here. Linux AMD64 is the proposed integration reference platform, not a tested platform. Apple Silicon does not establish Windows x64 guest/agent compatibility. Do not assume an ARM guest or emulated container is vendor supported.

The Docker VM memory budget is smaller than host RAM and leaves little room for heavy vendor stacks. Record vendor minimums in [dependencies](dependencies.md), then measure each profile. Do not launch Wazuh alongside Shuffle on this host without a reviewed resource allocation. No resource settings, kernel parameters, virtualization settings or services were changed.

## RF-04 read-only recheck

2026-11-18: Docker29.8.0linux/arm64,Compose5.5.1,buildx0.37.1;15CPUs and8318844928-byte(~7.75GiB) Docker memorylimit unchanged; host25769803776bytes(24GiB),0runningcontainers. This is capacity/availability inventory only, not measured Shuffle headroom or proof the daemon has no other assets. Owner has no dedicated VM running and asked both execution routes evaluated; no allocation/context/Swarm/privilege/service change performed. See [decision packet](shuffle.md).
