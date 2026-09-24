"""CLI for reconciling Stage B ingestion batches before split construction."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_reconciliation import reconcile_ingestion_batches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True,
                        help="Stage B ingestion batch JSON; repeat for multiple sources")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    batches = [json.loads(path.read_text(encoding="utf-8")) for path in args.input]
    reconciled = reconcile_ingestion_batches(batches)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(reconciled, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "inputs": len(batches),
        "canonical_records": reconciled["stats"]["canonical_records"],
        "quarantined_groups": reconciled["stats"]["quarantined_groups"],
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
