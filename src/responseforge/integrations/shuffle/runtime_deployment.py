"""Pure rendering of the explicit RF-04 pilot topology; never starts Docker."""

import re
from pathlib import Path
from typing import Any

_PROJECT = "responseforge-rf04"
_COMPONENTS = frozenset({"backend", "worker", "orborus", "frontend", "opensearch", "core", "app"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._:/-]*\Z")


def _immutable(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if _DIGEST.fullmatch(value):
        return True
    repository, separator, digest = value.partition("@")
    return bool(
        separator
        and _DIGEST.fullmatch(digest)
        and _REPOSITORY.fullmatch(repository)
        and "://" not in repository
        and all(part not in {"", ".", ".."} for part in repository.split("/"))
    )


def _mount(source: Path, target: str) -> dict[str, Any]:
    return {"type": "bind", "source": str(source), "target": target, "read_only": True}


_FRONTEND_NGINX = """worker_processes 1;
pid /var/run/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 256; }
http {
    include /etc/nginx/mime.types;
    access_log off;
    client_max_body_size 2m;
    client_body_temp_path /var/cache/nginx/client_temp;
    proxy_temp_path /var/cache/nginx/proxy_temp;
    server {
        listen 443 ssl;
        server_name shuffle-frontend localhost;
        ssl_certificate /etc/nginx/fullchain.cert.pem;
        ssl_certificate_key /etc/nginx/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        server_tokens off;
        location / {
            root /usr/share/nginx/html;
            try_files $uri /index.html;
        }
        location ~ ^/api/v[12](?:/|$) {
            proxy_pass http://shuffle-backend:5001;
            proxy_http_version 1.1;
            proxy_buffering off;
            proxy_connect_timeout 10s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }
}
"""

_OPENSEARCH_CONFIG = """cluster.name: responseforge-rf04
node.name: shuffle-opensearch
network.host: 0.0.0.0
discovery.type: single-node
node.store.allow_mmap: false
plugins.security.ssl.transport.pemcert_filepath: rf-opensearch.pem
plugins.security.ssl.transport.pemkey_filepath: rf-opensearch-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: rf-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: true
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: rf-opensearch.pem
plugins.security.ssl.http.pemkey_filepath: rf-opensearch-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: rf-ca.pem
plugins.security.nodes_dn:
  - CN=shuffle-opensearch
plugins.security.authcz.admin_dn:
  - CN=responseforge-rf04-admin
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.restapi.roles_enabled:
  - all_access
  - security_rest_api_access
"""


def render_runtime(
    images: dict[str, str],
    state_dir: Path,
    *,
    engine_authorized: bool = False,
    playbooks_enabled: bool = False,
    ui_port: int = 3443,
    core_port: int = 8443,
) -> dict[str, Any]:
    """Render the same pilot topology for either explicitly selected daemon."""
    if (
        not isinstance(images, dict)
        or set(images) != _COMPONENTS
        or any(not _immutable(value) for value in images.values())
        or not isinstance(state_dir, Path)
        or not state_dir.is_absolute()
        or ".." in state_dir.parts
        or any(ord(character) < 32 or ord(character) == 127 for character in str(state_dir))
        or type(playbooks_enabled) is not bool
        or type(engine_authorized) is not bool
        or any(type(port) is not int or not 1 <= port <= 65535 for port in (ui_port, core_port))
        or ui_port == core_port
    ):
        raise ValueError("Invalid immutable pilot images, private state directory or port settings")

    labels = {"responseforge.project": _PROJECT}

    def service(component: str, memory: str) -> dict[str, Any]:
        return {
            "image": images[component],
            "container_name": _PROJECT + "-" + component,
            "hostname": "responseforge-core" if component == "core" else "shuffle-" + component,
            "labels": dict(labels),
            "networks": {
                "private": {
                    "aliases": [
                        "responseforge-core" if component == "core" else "shuffle-" + component
                    ]
                }
            },
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": ["/tmp"],
            "mem_limit": memory,
            "cpus": "2.0" if component == "opensearch" else "1.0",
            "restart": "no",
            "logging": {
                "driver": "json-file",
                "options": {"max-size": "5m", "max-file": "2"},
            },
        }

    common_environment = {
        "ENVIRONMENT_NAME": "ResponseForge",
        "TZ": "UTC",
        "SHUFFLE_SKIPSSL_VERIFY": "false",
        "SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY": "false",
        "SHUFFLE_AUTO_IMAGE_DOWNLOAD": "false",
        "SHUFFLE_PASS_WORKER_PROXY": "false",
        "SHUFFLE_PASS_APP_PROXY": "false",
        "SHUFFLE_SKIP_PIPELINES": "true",
        "SHUFFLE_PIPELINE_ENABLED": "false",
        "SHUFFLE_AGENT_MODE": "false",
        "SHUFFLE_AGENT_SENSOR_MODE": "false",
        "SHUFFLE_STATS_DISABLED": "true",
        "SHUFFLE_LOGS_DISABLED": "true",
        "SHUFFLE_SWARM_CONFIG": "",
        "IS_KUBERNETES": "false",
        "CLEANUP": "false",
        "SHUFFLE_CONTAINER_AUTO_CLEANUP": "false",
        "RF_PROJECT": _PROJECT,
        "RF_CALLBACK_IMAGE": images["app"],
        "RF_CALLBACK_VOLUME": _PROJECT + "-callback",
        "DOCKER_API_VERSION": "1.44",
    }

    backend = service("backend", "1536m")
    backend["env_file"] = [str(state_dir / "secrets.env")]
    backend["environment"] = common_environment | {
        "BACKEND_HOSTNAME": "shuffle-backend",
        "BASE_URL": "http://shuffle-backend:5001",
        "SHUFFLE_APP_HOTLOAD_FOLDER": "/shuffle-apps",
        "SHUFFLE_APP_DOWNLOAD_LOCATION": "",
        "SHUFFLE_DOWNLOAD_WORKFLOW_LOCATION": "",
        "SHUFFLE_APP_FORCE_UPDATE": "false",
        "SHUFFLE_FILE_LOCATION": "/shuffle-files",
        "SHUFFLE_OPENSEARCH_URL": "https://shuffle-opensearch:9200",
        "SHUFFLE_OPENSEARCH_USERNAME": "admin",
        "SHUFFLE_OPENSEARCH_CERTIFICATE_FILE": "/run/responseforge/ca.pem",
        "SHUFFLE_HEALTHCHECK_DISABLED": "true",
    }
    backend["volumes"] = [
        "apps:/shuffle-apps",
        "files:/shuffle-files",
        _mount(state_dir / "pki/ca.pem", "/run/responseforge/ca.pem"),
    ]
    backend["depends_on"] = ["opensearch"]

    orborus = service("orborus", "512m")
    orborus["env_file"] = [str(state_dir / "secrets.env")]
    orborus["environment"] = common_environment | {
        "ORBORUS_CONTAINER_NAME": _PROJECT + "-orborus",
        "BASE_URL": "http://shuffle-backend:5001",
        "SHUFFLE_WORKER_IMAGE": images["worker"],
        "SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY": "1",
        # Deliberately short housekeeping age for the preservation test. Broad
        # cleanup is removed; this is not an application/approval timeout.
        "SHUFFLE_ORBORUS_EXECUTION_TIMEOUT": "2",
        "SHUFFLE_APP_REPLICAS": "1",
    }
    orborus["depends_on"] = ["backend"]
    if engine_authorized:
        socket = "/var/run/docker.sock:/var/run/docker.sock:rw"
        backend["volumes"].append(socket)
        orborus["volumes"] = [socket]

    frontend = service("frontend", "128m")
    frontend["user"] = "101:101"
    frontend["sysctls"] = {"net.ipv4.ip_unprivileged_port_start": "0"}
    frontend["entrypoint"] = ["nginx", "-g", "daemon off;"]
    frontend["tmpfs"] += [
        "/var/cache/nginx:uid=101,gid=101,mode=0770",
        "/var/run:uid=101,gid=101,mode=0770",
    ]
    frontend["volumes"] = [
        _mount(state_dir / "frontend-nginx.conf", "/etc/nginx/nginx.conf"),
        _mount(state_dir / "pki/frontend.pem", "/etc/nginx/fullchain.cert.pem"),
        _mount(state_dir / "pki/frontend-key.pem", "/etc/nginx/privkey.pem"),
    ]
    frontend["depends_on"] = ["backend"]

    opensearch = service("opensearch", "2g")
    opensearch["environment"] = {
        "DISABLE_INSTALL_DEMO_CONFIG": "true",
        "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI": "true",
        "OPENSEARCH_JAVA_OPTS": "-Xms1g -Xmx1g",
    }
    opensearch["tmpfs"] += ["/usr/share/opensearch/logs:uid=1000,gid=1000,mode=0770"]
    opensearch["volumes"] = [
        "database:/usr/share/opensearch/data",
        "opensearch-config:/usr/share/opensearch/config",
        _mount(state_dir / "opensearch.yml", "/usr/share/opensearch/config/opensearch.yml"),
        _mount(
            state_dir / "internal_users.yml",
            "/usr/share/opensearch/config/opensearch-security/internal_users.yml",
        ),
        _mount(state_dir / "pki/ca.pem", "/usr/share/opensearch/config/rf-ca.pem"),
        _mount(state_dir / "pki/opensearch.pem", "/usr/share/opensearch/config/rf-opensearch.pem"),
        _mount(
            state_dir / "pki/opensearch-key.pem",
            "/usr/share/opensearch/config/rf-opensearch-key.pem",
        ),
    ]

    core = service("core", "512m")
    core["user"] = "1000:1000"
    core["entrypoint"] = ["python", "-m", "responseforge.integrations.shuffle.pilot", "server"]
    core["environment"] = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "RF_PILOT_CONTAINER": "1",
    }
    core["volumes"] = [
        "core-state:/var/lib/responseforge",
        _mount(state_dir / "core.json", "/run/responseforge/core.json"),
        _mount(state_dir / "fault.json", "/run/responseforge/fault.json"),
        _mount(state_dir / "pki/ca.pem", "/run/responseforge/pki/ca.pem"),
        _mount(state_dir / "pki/core.pem", "/run/responseforge/pki/core.pem"),
        _mount(state_dir / "pki/core-key.pem", "/run/responseforge/pki/core-key.pem"),
    ]
    if playbooks_enabled:
        core["volumes"].append(
            _mount(state_dir / "replay.jsonl", "/run/responseforge/replay.jsonl")
        )
    if engine_authorized:
        frontend["ports"] = [f"127.0.0.1:{ui_port}:443"]
        core["ports"] = [f"127.0.0.1:{core_port}:8000"]
    # Docker Desktop needs a gateway-enabled interface for port forwarding.
    # Execution/backend/indexer remain only on the private data bridge.
    frontend["networks"]["access"] = {}
    core["networks"]["access"] = {}

    return {
        "compose": {
            "name": _PROJECT,
            "services": {
                "backend": backend,
                "orborus": orborus,
                "frontend": frontend,
                "opensearch": opensearch,
                "core": core,
            },
            "networks": {
                "private": {
                    "name": _PROJECT + "-private",
                    "internal": True,
                    "labels": dict(labels),
                },
                "access": {"name": _PROJECT + "-access", "labels": dict(labels)},
            },
            "volumes": {
                _PROJECT + "-" + name if name == "callback" else name: {
                    "name": _PROJECT + "-" + name,
                    "labels": dict(labels),
                }
                for name in (
                    "apps",
                    "files",
                    "database",
                    "core-state",
                    "callback",
                    "opensearch-config",
                )
            },
        },
        "frontend_nginx": _FRONTEND_NGINX,
        "opensearch_config": _OPENSEARCH_CONFIG,
    }
