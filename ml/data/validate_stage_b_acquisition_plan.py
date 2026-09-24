"""Validate a local Stage B acquisition plan against locked splits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_acquisition import validate_acquisition_plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--splits", type=Path, required=True)
    parser.add_argument("--normalized-output", type=Path)
    parser.add_argument("--allow-live-passive", action="store_true")
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    splits = json.loads(args.splits.read_text(encoding="utf-8"))
    normalized = validate_acquisition_plan(
        plan,
        splits,
        allow_live_passive=args.allow_live_passive,
    )
    if args.normalized_output:
        args.normalized_output.parent.mkdir(parents=True, exist_ok=True)
        args.normalized_output.write_text(
            json.dumps(normalized, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps({
        "status": "PASS",
        "plan_id": normalized["plan_id"],
        "sample_count": len(normalized["items"]),
        "live_passive_enabled": bool(args.allow_live_passive),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
