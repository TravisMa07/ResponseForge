"""Export deterministic v1 JSON Schemas; --check detects contract artifact drift."""

import argparse
import inspect
import json
from pathlib import Path

from responseforge import contracts

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "schemas" / "v1"
    expected = {}
    for name, model in inspect.getmembers(contracts, inspect.isclass):
        if issubclass(model, contracts.Contract) and model is not contracts.Contract:
            expected[f"{name}.json"] = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
    if args.check:
        actual = {path.name: path.read_text() for path in destination.glob("*.json")}
        if actual != expected:
            print("FAIL: schema artifacts differ; run scripts/export_contracts.py and review changes")
            return 1
        print(f"PASS: {len(expected)} v1 JSON Schemas match contracts")
    else:
        destination.mkdir(parents=True, exist_ok=True)
        for name, content in expected.items():
            (destination / name).write_text(content)
        print(f"Exported {len(expected)} v1 JSON Schemas")
    examples = json.loads((ROOT / "examples" / "contracts-v1.json").read_text())
    for example in examples["examples"]:
        model = getattr(contracts, example["model"])
        model.model_validate(example["value"])
    print(f"PASS: {len(examples['examples'])} illustrative examples validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
