from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_archive_replay import validate_archive_replay_plan


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a local Stage B archive replay plan.")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--normalized-output", type=Path)
    args = parser.parse_args()

    data = json.loads(args.plan.read_text(encoding="utf-8"))
    result = validate_archive_replay_plan(data, args.archive_root)

    if args.normalized_output:
        args.normalized_output.parent.mkdir(parents=True, exist_ok=True)
        args.normalized_output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(json.dumps({
        "status": "PASS",
        "schema_version": result["schema_version"],
        "plan_id": result["plan_id"],
        "items": len(result["items"]),
        "collection_provenance": result["collection_provenance"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
