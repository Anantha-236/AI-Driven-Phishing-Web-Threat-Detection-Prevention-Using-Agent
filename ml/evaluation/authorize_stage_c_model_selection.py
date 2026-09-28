from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_model_selection_authorization import (
    StageCModelSelectionAuthorizationError,
    frozen_write_json,
    issue_model_selection_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Authorize Stage-C model selection from frozen selection evidence."
    )
    p.add_argument("--evaluation-report", type=Path, required=True)
    p.add_argument("--training-manifest", type=Path, required=True)
    p.add_argument("--experiment-contract", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_model_selection_authorization(
            repo_root=ROOT,
            evaluation_report_path=a.evaluation_report,
            training_manifest_path=a.training_manifest,
            experiment_contract_path=a.experiment_contract,
        )
        output = a.output_root / "model-selection-authorization-v1.json"
        state = frozen_write_json(output, auth)
    except (OSError, ValueError, StageCModelSelectionAuthorizationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "candidate_count": auth["selection_scope"]["candidate_count"],
        "eligible_candidate_count": auth["selection_scope"][
            "eligible_candidate_count"
        ],
        "eligible_and_primary_feasible_count": auth["selection_scope"][
            "eligible_and_primary_feasible_count"
        ],
        "selection_evidence_sha256": auth["selection_scope"][
            "selection_evidence_sha256"
        ],
        "model_selection_authorized": auth["model_selection_authorized"],
        "model_selection_performed": auth["model_selection_performed"],
        "candidate_selected": auth["candidate_selected"],
        "calibration_access_authorized": auth[
            "calibration_access_authorized"
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
