from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_selection_evaluation import (
    StageCSelectionEvaluationError,
    evaluate_stage_c_selection,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Compute frozen Stage-C selection metrics without model selection."
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--score-dataset", type=Path, required=True)
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        result = evaluate_stage_c_selection(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            score_dataset_path=a.score_dataset,
            authorization_path=a.authorization,
            output_root=a.output_root,
        )
    except (OSError, ValueError, StageCSelectionEvaluationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
