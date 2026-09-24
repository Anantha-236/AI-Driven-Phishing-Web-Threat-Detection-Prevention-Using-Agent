"""CLI for local Stage B source snapshot ingestion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_ingestion import ingest_source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--adapter", required=True, choices=["phishtank_csv", "openphish_text", "tranco_csv"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    batch = ingest_source(manifest, args.input, adapter=args.adapter)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(batch, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "dataset_id": batch["dataset_id"],
        "adapter": batch["adapter"],
        "accepted_records": batch["stats"]["accepted_records"],
        "rejected_records": batch["stats"]["rejected_records"],
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
