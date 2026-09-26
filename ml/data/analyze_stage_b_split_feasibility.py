from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_split_feasibility import (
    SplitFeasibilityError,
    analyze_strict_forward_readiness_feasibility,
)


def load(path: Path):
    if not path.is_file():
        raise SplitFeasibilityError(f"required file not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SplitFeasibilityError(f"JSON root must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze strict-forward Stage B research split readiness feasibility."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--readiness-policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-results", type=int, default=25)
    args = parser.parse_args()

    try:
        result = analyze_strict_forward_readiness_feasibility(
            load(args.plan),
            load(args.readiness_policy),
            max_results=args.max_results,
        )
    except (SplitFeasibilityError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": result["status"],
        "candidate_samples": result["candidate_samples"],
        "candidate_labels": result["candidate_labels"],
        "connected_components": result["connected_components"],
        "cutoffs_examined": result["cutoffs_examined"],
        "aggregate_feasible_cutoffs": result["aggregate_feasible_cutoffs"],
        "feasibility": result["feasibility"],
        "best_candidates": result["best_candidates"][:5],
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
