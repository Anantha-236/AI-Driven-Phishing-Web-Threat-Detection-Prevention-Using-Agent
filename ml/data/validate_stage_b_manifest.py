"""Validate Stage B source manifests and the split contract from the command line."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.data.stage_b_manifest import validate_manifest_set, validate_split_contract


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+", type=Path, help="Source manifest JSON files")
    parser.add_argument("--split-contract", type=Path, required=True)
    args = parser.parse_args()

    source_data = [json.loads(path.read_text(encoding="utf-8")) for path in args.manifests]
    manifests = validate_manifest_set(source_data)
    split = validate_split_contract(json.loads(args.split_contract.read_text(encoding="utf-8")))
    print(json.dumps({
        "status": "PASS",
        "source_manifest_count": len(manifests),
        "dataset_ids": sorted(manifests),
        "split_schema": split["schema_version"],
        "final_test_locked": split["final_test_locked"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
