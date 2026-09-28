from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_candidate_selection import (
    StageCCandidateSelectionError,
    execute_candidate_selection,
    frozen_write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Execute the authorized Stage-C candidate selection rule."
    )
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--training-manifest", type=Path, required=True)
    p.add_argument("--candidate-root", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        record = execute_candidate_selection(
            repo_root=ROOT,
            authorization_path=a.authorization,
            training_manifest_path=a.training_manifest,
            candidate_root=a.candidate_root,
        )
        output = a.output_root / "selected-candidate-v1.json"
        state = frozen_write_json(output, record)
    except (OSError, ValueError, StageCCandidateSelectionError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "selection_record": str(output),
        "state": state,
        "selection_record_sha256": record["selection_record_sha256"],
        "selected_candidate_id": record["selected_candidate_id"],
        "selected_candidate_family": record["selected_candidate_family"],
        "selected_candidate_artifact_sha256": record[
            "selected_candidate_artifact"
        ]["artifact_sha256"],
        "physical_artifact_verified": record[
            "selected_candidate_artifact"
        ]["physical_artifact_verified"],
        "model_selection_authorized": record["model_selection_authorized"],
        "model_selection_performed": record["model_selection_performed"],
        "candidate_selected": record["candidate_selected"],
        "selection_diagnostic_threshold_frozen": record[
            "selection_diagnostic_threshold_frozen"
        ],
        "calibration_access_authorized": record[
            "calibration_access_authorized"
        ],
        "calibration_scoring_authorized": record[
            "calibration_scoring_authorized"
        ],
        "threshold_selection_authorized": record[
            "threshold_selection_authorized"
        ],
        "threshold_frozen": record["threshold_frozen"],
        "final_holdout_touched": record["final_holdout_touched"],
        "next_gate": record["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
