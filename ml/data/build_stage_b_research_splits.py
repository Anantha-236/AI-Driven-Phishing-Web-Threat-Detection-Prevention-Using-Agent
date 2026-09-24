from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_research_splitting import construct_research_archive_splits


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build research-only Stage B splits from a normalized Task-16 archive plan."
    )
    parser.add_argument("--archive-plan", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    archive_plan = json.loads(args.archive_plan.read_text(encoding="utf-8"))
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    result = construct_research_archive_splits(archive_plan, contract)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "PASS",
        "schema_version": result["schema_version"],
        "research_only": result["audit"]["research_only"],
        "deployment_authorized": result["audit"]["deployment_authorized"],
        "partitions": {
            name: payload["sample_count"]
            for name, payload in result["partitions"].items()
        },
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
