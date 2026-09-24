"""CLI for constructing leakage-resistant Stage B four-way partitions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_splitting import construct_stage_b_splits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Task 3 reconciled JSON")
    parser.add_argument("--split-contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    reconciled = json.loads(args.input.read_text(encoding="utf-8"))
    contract = json.loads(args.split_contract.read_text(encoding="utf-8"))
    result = construct_stage_b_splits(reconciled, contract)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "PASS",
        "schema_version": result["schema_version"],
        "partitions": {
            name: payload["sample_count"] for name, payload in result["partitions"].items()
        },
        "final_test_locked": result["audit"]["final_test_locked"],
        "strict_forward_test": result["audit"]["strict_forward_test"],
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
