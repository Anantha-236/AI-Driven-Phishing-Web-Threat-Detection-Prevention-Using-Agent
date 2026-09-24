from __future__ import annotations

import argparse
import json

from ml.evaluation.stage_b_controlled_shadow import evaluate_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate controlled Stage B shadow fixtures without touching the locked final test."
    )
    parser.add_argument("input")
    parser.add_argument("--output", default=".runtime/stage-b-controlled-shadow-evaluation.json")
    args = parser.parse_args()
    report = evaluate_file(args.input, args.output)
    print(json.dumps({
        "status": report["status"],
        "promotion_decision": report["promotion_decision"],
        "case_counts": report["case_counts"],
        "stage_b_primary_coverage": report["stage_b_primary_coverage"],
        "disagreement_analysis": report["disagreement_analysis"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
