from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_calibration_scoring_authorization import (
    StageCCalibrationScoringAuthorizationError,
    frozen_write_json,
    issue_calibration_scoring_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Authorize selected-candidate scoring on frozen complete calibration "
            "features with labels locked."
        )
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--selection-record", type=Path, required=True)
    p.add_argument("--training-manifest", type=Path, required=True)
    p.add_argument("--candidate-root", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_calibration_scoring_authorization(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            selection_record_path=a.selection_record,
            training_manifest_path=a.training_manifest,
            candidate_root=a.candidate_root,
        )
        output = a.output_root / "calibration-scoring-authorization-v1.json"
        state = frozen_write_json(output, auth)
    except (OSError, ValueError, StageCCalibrationScoringAuthorizationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    scope = auth["calibration_scoring_scope"]
    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "selected_candidate_id": auth["selected_candidate_id"],
        "selected_candidate_artifact_sha256": auth[
            "selected_candidate_artifact_sha256"
        ],
        "calibration_sample_count": scope["authorized_sample_count"],
        "calibration_sample_set_sha256": scope[
            "authorized_sample_set_sha256"
        ],
        "calibration_feature_matrix_sha256": scope[
            "authorized_feature_matrix_sha256"
        ],
        "calibration_scoring_authorized": auth[
            "calibration_scoring_authorized"
        ],
        "calibration_label_access_authorized": auth[
            "calibration_label_access_authorized"
        ],
        "calibration_labels_accessed": auth["calibration_labels_accessed"],
        "calibration_fitting_authorized": auth[
            "calibration_fitting_authorized"
        ],
        "threshold_selection_authorized": auth[
            "threshold_selection_authorized"
        ],
        "threshold_frozen": auth["threshold_frozen"],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
