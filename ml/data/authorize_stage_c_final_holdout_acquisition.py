from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_final_holdout_acquisition_authorization import (
    StageCFinalHoldoutAcquisitionAuthorizationError,
    frozen_write_json,
    issue_final_holdout_acquisition_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Authorize pinned Stage-C final-holdout acquisition and integrity "
            "verification after candidate+threshold freeze."
        )
    )
    p.add_argument("--threshold-freeze-record", type=Path, required=True)
    p.add_argument("--acquisition-plan", type=Path, required=True)
    p.add_argument("--experiment-contract", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_final_holdout_acquisition_authorization(
            repo_root=ROOT,
            threshold_freeze_record_path=a.threshold_freeze_record,
            acquisition_plan_path=a.acquisition_plan,
            experiment_contract_path=a.experiment_contract,
        )
        output = (
            a.output_root
            / "final-holdout-acquisition-authorization-v1.json"
        )
        state = frozen_write_json(output, auth)
    except (
        OSError,
        ValueError,
        StageCFinalHoldoutAcquisitionAuthorizationError,
    ) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    scope = auth["final_holdout_scope"]
    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "candidate_threshold_pair_sha256": auth[
            "frozen_operating_point"
        ]["candidate_threshold_pair_sha256"],
        "final_holdout_candidate_id": scope["candidate_id"],
        "final_holdout_source_id": scope["source_id"],
        "final_holdout_doi": scope["doi"],
        "final_holdout_expected_class_counts": scope[
            "expected_class_counts"
        ],
        "final_holdout_identity_sha256": scope["identity_sha256"],
        "final_holdout_acquisition_authorized": auth[
            "final_holdout_acquisition_authorized"
        ],
        "final_holdout_download_authorized": auth[
            "final_holdout_download_authorized"
        ],
        "final_holdout_feature_extraction_authorized": auth[
            "final_holdout_feature_extraction_authorized"
        ],
        "final_holdout_model_scoring_authorized": auth[
            "final_holdout_model_scoring_authorized"
        ],
        "final_holdout_metrics_authorized": auth[
            "final_holdout_metrics_authorized"
        ],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
