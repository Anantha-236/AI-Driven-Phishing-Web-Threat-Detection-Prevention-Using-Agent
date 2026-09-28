from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_selection_label_evaluation_authorization import (
    StageCSelectionEvaluationAuthorizationError,
    frozen_write_json,
    issue_selection_label_evaluation_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Authorize controlled evaluation of frozen Stage-C selection scores."
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--score-dataset", type=Path, required=True)
    p.add_argument("--score-manifest", type=Path, required=True)
    p.add_argument("--experiment-contract", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_selection_label_evaluation_authorization(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            score_dataset_path=a.score_dataset,
            score_manifest_path=a.score_manifest,
            experiment_contract_path=a.experiment_contract,
        )
        output = a.output_root / "selection-label-evaluation-authorization-v1.json"
        state = frozen_write_json(output, auth)
    except (OSError, ValueError, StageCSelectionEvaluationAuthorizationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "selection_sample_count": auth["evaluation_scope"]["selection_sample_count"],
        "selection_label_counts": auth["evaluation_scope"]["selection_label_counts"],
        "selection_label_vector_sha256": auth["evaluation_scope"][
            "selection_label_vector_sha256"
        ],
        "score_row_count": auth["evaluation_scope"]["score_row_count"],
        "score_dataset_sha256": auth["evaluation_scope"]["score_dataset_sha256"],
        "evaluation_input_sha256": auth["evaluation_scope"][
            "evaluation_input_sha256"
        ],
        "selection_metric_computation_authorized": auth[
            "selection_metric_computation_authorized"
        ],
        "selection_metrics_computed": auth["selection_metrics_computed"],
        "model_selection_authorized": auth["model_selection_authorized"],
        "candidate_selected": auth["candidate_selected"],
        "calibration_fitting_authorized": auth[
            "calibration_fitting_authorized"
        ],
        "threshold_selection_authorized": auth[
            "threshold_selection_authorized"
        ],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
