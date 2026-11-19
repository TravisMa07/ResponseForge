"""Source-neutral fixed native app registration and authenticated lab reads."""

import json
from pathlib import Path
from typing import Any

import httpx

from responseforge.integrations.shuffle.models import canonical_uuid
from responseforge.integrations.shuffle.qualification import _request, _save


class NativeSession:
    state: Path
    vendor: httpx.AsyncClient
    core: httpx.AsyncClient
    env: dict[str, str]
    roles: dict[str, str]
    journal: dict[str, Any]
    path: Path

    def save(self) -> None:
        _save(self.path, self.journal)

    async def app(self, name: str, org: str) -> str:
        apps = await _request(
            self.vendor, "GET", "/api/v1/apps", token=self.env["SHUFFLE_DEFAULT_APIKEY"]
        )
        matches = [
            item for item in apps if item.get("name") == name and item.get("app_version") == "1.0.0"
        ]
        if not matches:
            key = "app-reserved-" + name
            if self.journal.get(key):
                raise ValueError(
                    "App creation acknowledgement uncertain; inspect original vendor identity"
                )
            self.journal[key] = True
            self.save()
            steps = (
                ("callback",)
                if name == "responseforge_callback"
                else ("prepare", "gate", "dispatch")
            )
            await _request(
                self.vendor,
                "PUT",
                "/api/v1/apps",
                token=self.env["SHUFFLE_DEFAULT_APIKEY"],
                body={
                    "name": name,
                    "app_version": "1.0.0",
                    "description": "Original RF05 native fixed actions",
                    "contact_info": {"name": "ResponseForge"},
                    "reference_org": org,
                    "public": False,
                    "sharing": False,
                    "authentication": {"required": False},
                    "actions": [
                        {
                            "name": step,
                            "description": "Bound " + step,
                            "parameters": [
                                {
                                    "name": key,
                                    "description": "",
                                    "required": False,
                                    "schema": {"type": "string"},
                                }
                                for key in (
                                    ("outcome", "delay_seconds") if step == "callback" else ()
                                )
                            ],
                        }
                        for step in steps
                    ],
                },
            )
            apps = await _request(
                self.vendor, "GET", "/api/v1/apps", token=self.env["SHUFFLE_DEFAULT_APIKEY"]
            )
            matches = [
                item
                for item in apps
                if item.get("name") == name and item.get("app_version") == "1.0.0"
            ]
        if len(matches) != 1:
            raise ValueError("Native app registration is ambiguous")
        return canonical_uuid(matches[0]["id"])


    async def audit(self, incident: str) -> list[dict[str, Any]]:
        return list(
            await _request(
                self.core,
                "GET",
                "/v1/incidents/" + incident + "/audit",
                token=self.roles["analyst"],
            )
        )


    def secret_values(self) -> list[str]:
        config = json.loads((self.state / "core.json").read_text())
        return list(config["credentials"]) + list(self.env.values())

