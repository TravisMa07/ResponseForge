"""Export the internal API description without starting a server or loading credentials."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from responseforge.api import create_app
from responseforge.runtime import Settings

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="responseforge-schema-") as directory:
        app = create_app(Settings(database_path=Path(directory) / "schema.sqlite3"))
        content = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    path = ROOT / "schemas" / "internal-api.json"
    if args.check:
        if not path.exists() or path.read_text() != content:
            print("FAIL: internal API artifact drift; regenerate scripts/export_api.py and review")
            return 1
        print("PASS: internal OpenAPI matches routes and Bearer authentication")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print("Exported internal OpenAPI (no vendor compatibility claim)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
