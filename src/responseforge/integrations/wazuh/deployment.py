"""Pure immutable upstream-derived planning; unresolved TLS blocks runtime."""

import hashlib
import re
from typing import Any

from responseforge.integrations.wazuh.preparation_models import DeploymentPlan, DeploymentTarget
from responseforge.integrations.wazuh.security import PreparationError

SOURCE = "76ddb88b9c8b618a254a287f2684f93d3c5ac2f4"
BLOCKERS = (
    "dashboard-manager-tls-hardcoded-rejectUnauthorized-false-source-patch-required",
    "private-credentials-demo-users-and-security-index-bootstrap-unqualified",
    "ca-san-node-admin-api-identities-and-all-tls-legs-unqualified",
    "image-source-runtime-and-manager-profile-unqualified",
    "resource-sysctl-and-combined-capacity-unqualified",
    "native-sender-placement-and-authenticated-manager-capture-unqualified",
    "endpoint-network-publication-enrollment-and-windows-runtime-unqualified",
    "owner-runtime-authorization-required",
)
FILES = (
    "root-ca.pem",
    "root-ca-manager.pem",
    "wazuh.manager.pem",
    "wazuh.manager-key.pem",
    "wazuh.indexer.pem",
    "wazuh.indexer-key.pem",
    "admin.pem",
    "admin-key.pem",
    "wazuh.dashboard.pem",
    "wazuh.dashboard-key.pem",
    "wazuh_manager.conf",
    "wazuh.indexer.yml",
    "internal_users.yml",
    "opensearch_dashboards.yml",
    "wazuh.yml",
)


def _secret(name: str) -> str:
    return "${" + name + ":?Private reviewed credential required}"


def build_plan(target: DeploymentTarget, lock: dict[str, Any]) -> DeploymentPlan:
    try:
        scoped = DeploymentTarget.model_validate(target.model_dump(mode="json"))
        if (
            set(lock) != {"schema_version", "source_revision", "images", "runtime_qualified"}
            or lock["schema_version"] != "1.0"
            or lock["source_revision"] != SOURCE
            or lock["runtime_qualified"] is not False
            or set(lock["images"]) != {"manager", "indexer", "dashboard"}
        ):
            raise ValueError
        images = {}
        for component in ("manager", "indexer", "dashboard"):
            pin = lock["images"][component]
            if (
                set(pin) != {"repository", "index_digest", "platforms"}
                or pin["repository"] != "wazuh/wazuh-" + component
                or set(pin["platforms"]) != {"amd64", "arm64"}
                or any(
                    re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                    for item in [pin["index_digest"], *pin["platforms"].values()]
                )
            ):
                raise ValueError
            images[component] = pin["repository"] + "@" + pin["platforms"][scoped.architecture]
        project = (
            "responseforge-wazuh-" + hashlib.sha256(scoped.manager_id.encode()).hexdigest()[:12]
        )
        private = "${RF_WAZUH_PRIVATE_DIR:?Reviewed private configuration required}"

        def mount(source: str, destination: str) -> dict[str, Any]:
            return {
                "type": "bind",
                "source": private + "/" + source,
                "target": destination,
                "read_only": True,
                "bind": {"create_host_path": False},
            }

        manager_volumes = [
            {"type": "volume", "source": name, "target": destination}
            for name, destination in (
                ("wazuh_api_configuration", "/var/ossec/api/configuration"),
                ("wazuh_etc", "/var/ossec/etc"),
                ("wazuh_logs", "/var/ossec/logs"),
                ("wazuh_queue", "/var/ossec/queue"),
                ("wazuh_var_multigroups", "/var/ossec/var/multigroups"),
                ("wazuh_integrations", "/var/ossec/integrations"),
                ("wazuh_active_response", "/var/ossec/active-response/bin"),
                ("wazuh_agentless", "/var/ossec/agentless"),
                ("wazuh_wodles", "/var/ossec/wodles"),
                ("filebeat_etc", "/etc/filebeat"),
                ("filebeat_var", "/var/lib/filebeat"),
            )
        ]
        services: dict[str, Any] = {}
        for name in images:
            services["wazuh." + name] = {
                "image": images[name],
                "platform": "linux/" + scoped.architecture,
                "hostname": "wazuh." + name,
                "profiles": ["rf07-runtime-unqualified"],
                "restart": "no",
                "networks": ["wazuh-private"],
                "labels": {
                    "responseforge.project": project,
                    "responseforge.runtime-qualified": "false",
                },
                "security_opt": ["no-new-privileges:true"],
            }
        manager = services["wazuh.manager"]
        manager["ports"] = [
            f"{scoped.endpoint_bind_ip}:1514:1514",
            f"{scoped.endpoint_bind_ip}:1515:1515",
            "127.0.0.1:55001:55000",
        ]
        manager["ulimits"] = {
            "memlock": {"soft": -1, "hard": -1},
            "nofile": {"soft": 655360, "hard": 655360},
        }
        manager["environment"] = {
            "INDEXER_URL": "https://wazuh.indexer:9200",
            "INDEXER_USERNAME": "rf07-manager-indexer",
            "INDEXER_PASSWORD": _secret("RF_WAZUH_MANAGER_INDEXER_PASSWORD"),
            "FILEBEAT_SSL_VERIFICATION_MODE": "full",
            "SSL_CERTIFICATE_AUTHORITIES": "/etc/ssl/root-ca.pem",
            "SSL_CERTIFICATE": "/etc/ssl/filebeat.pem",
            "SSL_KEY": "/etc/ssl/filebeat.key",
            "API_USERNAME": "rf07-dashboard-api",
            "API_PASSWORD": _secret("RF_WAZUH_DASHBOARD_API_PASSWORD"),
        }
        manager["volumes"] = manager_volumes + [
            mount("root-ca-manager.pem", "/etc/ssl/root-ca.pem"),
            mount("wazuh.manager.pem", "/etc/ssl/filebeat.pem"),
            mount("wazuh.manager-key.pem", "/etc/ssl/filebeat.key"),
            mount("wazuh_manager.conf", "/wazuh-config-mount/etc/ossec.conf"),
        ]
        indexer = services["wazuh.indexer"]
        indexer["ports"] = ["127.0.0.1:9201:9200"]
        indexer["environment"] = {"OPENSEARCH_JAVA_OPTS": "-Xms1g -Xmx1g"}
        indexer["ulimits"] = {
            "memlock": {"soft": -1, "hard": -1},
            "nofile": {"soft": 65536, "hard": 65536},
        }
        indexer["volumes"] = [
            {"type": "volume", "source": "wazuh-indexer-data", "target": "/var/lib/wazuh-indexer"}
        ] + [
            mount(source, "/usr/share/wazuh-indexer/config/" + destination)
            for source, destination in (
                ("root-ca.pem", "certs/root-ca.pem"),
                ("wazuh.indexer.pem", "certs/wazuh.indexer.pem"),
                ("wazuh.indexer-key.pem", "certs/wazuh.indexer.key"),
                ("admin.pem", "certs/admin.pem"),
                ("admin-key.pem", "certs/admin-key.pem"),
                ("wazuh.indexer.yml", "opensearch.yml"),
                ("internal_users.yml", "opensearch-security/internal_users.yml"),
            )
        ]
        dashboard = services["wazuh.dashboard"]
        dashboard["ports"] = ["127.0.0.1:9443:5601"]
        dashboard["depends_on"] = ["wazuh.indexer"]
        dashboard["environment"] = {
            "INDEXER_USERNAME": "rf07-dashboard-indexer",
            "INDEXER_PASSWORD": _secret("RF_WAZUH_DASHBOARD_INDEXER_PASSWORD"),
            "WAZUH_API_URL": "https://wazuh.manager",
            "DASHBOARD_USERNAME": "rf07-dashboard-server",
            "DASHBOARD_PASSWORD": _secret("RF_WAZUH_DASHBOARD_SERVER_PASSWORD"),
            "API_USERNAME": "rf07-dashboard-api",
            "API_PASSWORD": _secret("RF_WAZUH_DASHBOARD_API_PASSWORD"),
        }
        dashboard["volumes"] = [
            mount(source, "/usr/share/wazuh-dashboard/" + destination)
            for source, destination in (
                ("wazuh.dashboard.pem", "certs/wazuh-dashboard.pem"),
                ("wazuh.dashboard-key.pem", "certs/wazuh-dashboard-key.pem"),
                ("root-ca.pem", "certs/root-ca.pem"),
                ("opensearch_dashboards.yml", "config/opensearch_dashboards.yml"),
                ("wazuh.yml", "data/wazuh/config/wazuh.yml"),
            )
        ] + [
            {"type": "volume", "source": source, "target": destination}
            for source, destination in (
                ("wazuh-dashboard-config", "/usr/share/wazuh-dashboard/data/wazuh/config"),
                (
                    "wazuh-dashboard-custom",
                    "/usr/share/wazuh-dashboard/plugins/wazuh/public/assets",
                ),
            )
        ]
        names = {
            item["source"]
            for service in services.values()
            for item in service["volumes"]
            if item["type"] == "volume"
        }
        compose = {
            "name": project,
            "services": services,
            "networks": {"wazuh-private": {"internal": True}},
            "volumes": {
                name: {"name": project + "-" + name, "labels": {"responseforge.project": project}}
                for name in sorted(names)
            },
        }
        return DeploymentPlan(
            target=scoped, compose=compose, blockers=BLOCKERS, source_requirements=FILES
        )
    except (ValueError, TypeError, AttributeError, KeyError):
        raise PreparationError("Invalid pinned upstream deployment plan") from None
