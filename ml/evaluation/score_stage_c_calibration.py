from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_calibration_score_generation import (
    StageCCalibrationScoringError,
    score_stage_c_calibration,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Generate frozen selected-candidate probabilities on the authorized "
            "Stage-C calibration features with labels locked."
        )
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--candidate-root", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        result = score_stage_c_calibration(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            authorization_path=a.authorization,
            candidate_root=a.candidate_root,
            output_root=a.output_root,
        )
    except (OSError, ValueError, StageCCalibrationScoringError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
