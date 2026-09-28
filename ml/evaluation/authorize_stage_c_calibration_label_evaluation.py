from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_calibration_label_evaluation_authorization import (
    StageCCalibrationLabelEvaluationAuthorizationError,
    frozen_write_json,
    issue_calibration_label_evaluation_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Authorize controlled evaluation of frozen Stage-C calibration "
            "scores against the exact frozen calibration labels."
        )
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--score-dataset", type=Path, required=True)
    p.add_argument("--score-manifest", type=Path, required=True)
    p.add_argument("--experiment-contract", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_calibration_label_evaluation_authorization(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            score_dataset_path=a.score_dataset,
            score_manifest_path=a.score_manifest,
            experiment_contract_path=a.experiment_contract,
        )
        output = (
            a.output_root
            / "calibration-label-evaluation-authorization-v1.json"
        )
        state = frozen_write_json(output, auth)
    except (
        OSError,
        ValueError,
        StageCCalibrationLabelEvaluationAuthorizationError,
    ) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    scope = auth["evaluation_scope"]
    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "selected_candidate_id": auth["selected_candidate_id"],
        "calibration_sample_count": scope["calibration_sample_count"],
        "calibration_label_counts": scope["calibration_label_counts"],
        "calibration_label_vector_sha256": scope[
            "calibration_label_vector_sha256"
        ],
        "score_dataset_sha256": scope["score_dataset_sha256"],
        "score_vector_sha256": scope["score_vector_sha256"],
        "evaluation_input_sha256": scope["evaluation_input_sha256"],
        "calibration_metric_computation_authorized": auth[
            "calibration_metric_computation_authorized"
        ],
        "calibration_metrics_computed": auth[
            "calibration_metrics_computed"
        ],
        "threshold_analysis_authorized": auth[
            "threshold_analysis_authorized"
        ],
        "threshold_selection_authorized": auth[
            "threshold_selection_authorized"
        ],
        "threshold_selected": auth["threshold_selected"],
        "threshold_frozen": auth["threshold_frozen"],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
