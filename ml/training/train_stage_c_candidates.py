from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_candidate_training import (
    StageCCandidateTrainingError,
    train_stage_c_candidates,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Fit frozen Stage-C candidates on the Task-11 authorized TRAIN subset."
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        result = train_stage_c_candidates(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            authorization_path=a.authorization,
            output_root=a.output_root,
        )
    except (OSError, ValueError, StageCCandidateTrainingError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
