from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_connectivity_attribution import (
    ConnectivityAttributionError,
    analyze_connectivity_attribution,
)


def load(path: Path):
    if not path.is_file():
        raise ConnectivityAttributionError(f"required file not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ConnectivityAttributionError(f"JSON root must be object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Attribute Stage B split infeasibility to connectivity keys.")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--readiness-policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = analyze_connectivity_attribution(
            load(args.plan),
            load(args.readiness_policy),
        )
    except (OSError, ValueError, json.JSONDecodeError, ConnectivityAttributionError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    compact = {
        "status": result["status"],
        "candidate_samples": result["candidate_samples"],
        "candidate_labels": result["candidate_labels"],
        "requirements": result["requirements"],
        "conclusion": result["conclusion"],
        "modes": {
            name: {
                "connected_components": data["connected_components"],
                "phishing_components": data["label_component_counts"]["phishing"],
                "feasibility": data["strict_forward"]["feasibility"],
                "feasible_cutoffs": data["strict_forward"]["feasible_cutoffs"],
                "best_candidates": data["strict_forward"]["best_candidates"][:3],
                "largest_component": data["largest_components"][0] if data["largest_components"] else None,
            }
            for name, data in result["modes"].items()
        },
        "output": str(args.output),
    }
    print(json.dumps(compact, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
