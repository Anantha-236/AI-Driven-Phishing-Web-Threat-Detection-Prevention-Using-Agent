from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_selection_scoring_authorization import (
    StageCSelectionScoringAuthorizationError,
    frozen_write_json,
    issue_selection_scoring_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Authorize feature-only selection scoring for frozen Stage-C candidates."
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--task11-authorization", type=Path, required=True)
    p.add_argument("--training-manifest", type=Path, required=True)
    p.add_argument("--candidate-root", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_selection_scoring_authorization(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            task11_authorization_path=a.task11_authorization,
            training_manifest_path=a.training_manifest,
            candidate_root=a.candidate_root,
        )
        output = a.output_root / "selection-scoring-authorization-v1.json"
        state = frozen_write_json(output, auth)
    except (OSError, ValueError, StageCSelectionScoringAuthorizationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "selection_sample_count": auth["selection_scope"]["selection_sample_count"],
        "selection_sample_set_sha256": auth["selection_scope"][
            "selection_sample_set_sha256"
        ],
        "selection_feature_matrix_sha256": auth["selection_scope"][
            "selection_feature_matrix_sha256"
        ],
        "candidate_count": auth["candidate_scope"]["candidate_count"],
        "candidate_artifact_set_sha256": auth["candidate_scope"][
            "candidate_artifact_set_sha256"
        ],
        "model_scoring_authorized": auth["model_scoring_authorized"],
        "selection_label_access_authorized": auth[
            "selection_label_access_authorized"
        ],
        "model_selection_authorized": auth["model_selection_authorized"],
        "calibration_fitting_authorized": auth["calibration_fitting_authorized"],
        "threshold_selection_authorized": auth["threshold_selection_authorized"],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
