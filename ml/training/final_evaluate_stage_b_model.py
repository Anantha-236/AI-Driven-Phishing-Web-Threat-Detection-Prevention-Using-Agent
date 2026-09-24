"""CLI for the locked Stage B final-test evaluation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ml.training.stage_b_final_evaluation import final_evaluate_stage_b_model


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("feature_dataset", type=Path)
    parser.add_argument("readiness_audit", type=Path)
    parser.add_argument("benchmark_report", type=Path)
    parser.add_argument("calibration_report", type=Path)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("ml/training/manifests/stage-b-calibration-policy.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--acknowledge-final-test", action="store_true")
    args = parser.parse_args()

    if not args.acknowledge_final_test:
        parser.error(
            "final test remains locked; rerun with --acknowledge-final-test only after Tasks 7-9 are frozen"
        )
    if args.output.exists():
        parser.error("refusing to overwrite an existing final-evaluation report")

    result = final_evaluate_stage_b_model(
        _load(args.feature_dataset),
        _load(args.readiness_audit),
        _load(args.benchmark_report),
        _load(args.calibration_report),
        _load(args.policy),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "selected_candidate": result["selected_candidate"],
        "test_samples": result["data_usage"]["test_samples"],
        "deployment_threshold_authorized": result["fixed_operating_point"]["calibration_deployment_authorized"],
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
