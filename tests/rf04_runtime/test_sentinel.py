"""The unrelated-resource preservation fixture must not inherit lab ownership."""

import json
from pathlib import Path

from responseforge.integrations.shuffle.operations import LABEL, PROJECT
from responseforge.integrations.shuffle.qualification import _sentinel


def test_sentinel_overrides_inherited_lab_image_ownership(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []
    identity = "a" * 64
    journal = {"sentinel_key": "test-key"}

    class Runtime:
        def _verified(self, **kwargs: object) -> dict:
            return {}

        def _raw(self, state: dict, args: tuple[str, ...]) -> str:
            calls.append(args)
            if args[0] == "run":
                return identity
            return json.dumps(
                {
                    "Config": {
                        "Labels": {
                            "responseforge.sentinel": "test-key",
                            LABEL: "unrelated-rf04-sentinel",
                        }
                    },
                    "State": {"Running": True},
                }
            )

    _sentinel(Runtime(), journal, tmp_path / "journal.json", "sha256:" + "b" * 64)
    args = calls[0]
    assert LABEL + "=unrelated-rf04-sentinel" in args
    assert LABEL + "=" + PROJECT not in args
