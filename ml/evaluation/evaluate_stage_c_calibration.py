from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_calibration_evaluation import (
    StageCCalibrationEvaluationError,
    evaluate_stage_c_calibration,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Evaluate frozen Stage-C calibration scores and freeze low-FPR "
            "threshold analysis without selecting a threshold."
        )
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--score-dataset", type=Path, required=True)
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()
    try:
        result = evaluate_stage_c_calibration(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            score_dataset_path=a.score_dataset,
            authorization_path=a.authorization,
            output_root=a.output_root,
        )
    except (OSError, ValueError, StageCCalibrationEvaluationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
