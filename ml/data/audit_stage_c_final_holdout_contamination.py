from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_final_holdout_contamination_audit import (
    StageCFinalHoldoutContaminationError,
    audit_final_holdout_contamination,
    frozen_write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Audit the frozen Stage-C final holdout for contamination and "
            "duplicate weighting before any final feature extraction."
        )
    )
    p.add_argument("--final-holdout-index", type=Path, required=True)
    p.add_argument("--stage-c-development-index", type=Path, required=True)
    p.add_argument("--stage-b-feature-dataset", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        audit, clean = audit_final_holdout_contamination(
            repo_root=ROOT,
            final_index_path=a.final_holdout_index,
            development_index_path=a.stage_c_development_index,
            stage_b_feature_dataset_path=a.stage_b_feature_dataset,
        )
        audit_path = a.output_root / "final-holdout-contamination-audit-v1.json"
        clean_path = a.output_root / "final-holdout-clean-evaluation-set-v1.json"
        audit_state = frozen_write_json(audit_path, audit)
        clean_state = frozen_write_json(clean_path, clean)
    except (OSError, ValueError, StageCFinalHoldoutContaminationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "audit": str(audit_path),
        "audit_state": audit_state,
        "clean_evaluation_set": str(clean_path),
        "clean_set_state": clean_state,
        "original_samples": audit["original_final_holdout_samples"],
        "identity_component_count": audit["identity_component_count"],
        "quarantined_sample_count": audit["quarantined_sample_count"],
        "hard_overlap_sample_counts": audit["hard_overlap_sample_counts"],
        "duplicate_rows_removed_from_clean_weighting": audit[
            "duplicate_rows_removed_from_clean_weighting"
        ],
        "eligible_clean_samples": audit["eligible_clean_samples"],
        "eligible_clean_class_counts": audit["eligible_clean_class_counts"],
        "recommended_final_scale_satisfied": audit[
            "recommended_final_scale_satisfied"
        ],
        "clean_sample_set_sha256": audit["clean_sample_set_sha256"],
        "clean_record_set_sha256": audit["clean_record_set_sha256"],
        "model_scoring_performed": audit["model_scoring_performed"],
        "features_extracted": audit["features_extracted"],
        "next_gate": audit["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
