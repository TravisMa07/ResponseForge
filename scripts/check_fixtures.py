"""Check original synthetic fixture provenance; never fetch an external corpus."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "datasets" / "fixtures"


def main() -> int:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    fixtures = manifest["fixtures"]
    if not fixtures:
        raise ValueError("empty fixture manifest")
    sources = set()
    for item in fixtures:
        path = (ROOT / item["path"]).resolve()
        if (
            not path.is_relative_to(ROOT.resolve())
            or not path.is_file()
            or path.stat().st_size > 1024 * 1024
            or item["origin"] != "original-synthetic"
            or not item["redistribution_note"]
            or item["source_id"] in sources
        ):
            raise ValueError("invalid original fixture manifest scope")
        sources.add(item["source_id"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("fixture bytes differ from manifest")
    print(f"PASS: {len(fixtures)} original synthetic fixture hashes and provenance entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
