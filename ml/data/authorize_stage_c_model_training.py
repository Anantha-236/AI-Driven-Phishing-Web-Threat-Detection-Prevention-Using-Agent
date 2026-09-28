from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_model_training_authorization import (
    StageCTrainingAuthorizationError,
    frozen_write_json,
    issue_model_training_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Issue Stage-C training authorization for complete TRAIN rows."
    )
    p.add_argument("--feature-dataset", type=Path, required=True)
    p.add_argument("--feature-audit", type=Path, required=True)
    p.add_argument("--feature-readiness", type=Path, required=True)
    p.add_argument("--split-manifest", type=Path, required=True)
    p.add_argument("--task9-authorization", type=Path, required=True)
    p.add_argument("--experiment-contract", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_model_training_authorization(
            repo_root=ROOT,
            feature_dataset_path=a.feature_dataset,
            feature_audit_path=a.feature_audit,
            feature_readiness_path=a.feature_readiness,
            split_manifest_path=a.split_manifest,
            task9_authorization_path=a.task9_authorization,
            experiment_contract_path=a.experiment_contract,
        )
        output = a.output_root / "model-training-authorization-v1.json"
        state = frozen_write_json(output, auth)
    except (OSError, ValueError, StageCTrainingAuthorizationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "authorized_train_sample_count": auth["training_scope"]["authorized_sample_count"],
        "authorized_train_sample_set_sha256": auth["training_scope"][
            "authorized_sample_set_sha256"
        ],
        "modeling_candidate_sample_count": auth["modeling_universe"]["sample_count"],
        "modeling_candidate_sample_set_sha256": auth["modeling_universe"][
            "sample_set_sha256"
        ],
        "excluded_collection_incomplete_count": auth[
            "excluded_collection_incomplete"
        ]["sample_count"],
        "model_training_authorized": auth["model_training_authorized"],
        "model_selection_authorized": auth["model_selection_authorized"],
        "calibration_fitting_authorized": auth["calibration_fitting_authorized"],
        "threshold_selection_authorized": auth["threshold_selection_authorized"],
        "model_scoring_authorized": auth["model_scoring_authorized"],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
