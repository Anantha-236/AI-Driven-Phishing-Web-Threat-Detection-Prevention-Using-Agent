from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_final_holdout_feature_extraction_authorization import (
    StageCFinalHoldoutFeatureAuthorizationError,
    authorize_final_holdout_feature_extraction,
    frozen_write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Authorize production 27-feature extraction on the frozen clean "
            "Stage-C final-holdout identity subset without model access."
        )
    )
    p.add_argument("--clean-evaluation-set", type=Path, required=True)
    p.add_argument("--contamination-audit", type=Path, required=True)
    p.add_argument("--threshold-freeze-record", type=Path, required=True)
    p.add_argument("--task28-seal", type=Path, required=True)
    p.add_argument("--task9-authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        authorization = authorize_final_holdout_feature_extraction(
            repo_root=ROOT,
            clean_set_path=a.clean_evaluation_set,
            contamination_audit_path=a.contamination_audit,
            threshold_freeze_path=a.threshold_freeze_record,
            task28_seal_path=a.task28_seal,
            task9_authorization_path=a.task9_authorization,
        )
        path = (
            a.output_root
            / "final-holdout-feature-extraction-authorization-v1.json"
        )
        state = frozen_write_json(path, authorization)
    except (
        OSError,
        ValueError,
        StageCFinalHoldoutFeatureAuthorizationError,
    ) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "authorization": str(path),
        "state": state,
        "authorization_sha256": authorization["authorization_sha256"],
        "authorized_action": authorization["authorized_action"],
        "authorized_sample_count": authorization["scope"][
            "authorized_sample_count"
        ],
        "authorized_class_counts": authorization["scope"][
            "authorized_class_counts"
        ],
        "authorized_sample_set_sha256": authorization["scope"][
            "authorized_sample_set_sha256"
        ],
        "authorized_record_set_sha256": authorization["scope"][
            "authorized_record_set_sha256"
        ],
        "authorized_artifact_set_sha256": authorization["scope"][
            "authorized_artifact_set_sha256"
        ],
        "feature_count": authorization["feature_contract"]["feature_count"],
        "feature_contract_sha256": authorization["feature_contract"][
            "feature_contract_sha256"
        ],
        "extractor_source_sha256": authorization["feature_contract"][
            "extractor_source_sha256"
        ],
        "candidate_threshold_pair_sha256": authorization[
            "frozen_operating_point"
        ]["candidate_threshold_pair_sha256"],
        "final_holdout_feature_extraction_authorized": True,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_metrics_authorized": False,
        "threshold_change_authorized": False,
        "next_gate": authorization["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
