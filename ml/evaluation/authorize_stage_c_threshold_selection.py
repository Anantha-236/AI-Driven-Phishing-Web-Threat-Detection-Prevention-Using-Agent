from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_threshold_selection_authorization import (
    StageCThresholdSelectionAuthorizationError,
    frozen_write_json,
    issue_threshold_selection_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Authorize deterministic Stage-C threshold selection from frozen "
            "Task-22 calibration analysis."
        )
    )
    p.add_argument("--evaluation-report", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        auth = issue_threshold_selection_authorization(
            repo_root=ROOT,
            evaluation_report_path=a.evaluation_report,
        )
        output = (
            a.output_root / "threshold-selection-authorization-v1.json"
        )
        state = frozen_write_json(output, auth)
    except (
        OSError,
        ValueError,
        StageCThresholdSelectionAuthorizationError,
    ) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    scope = auth["threshold_selection_scope"]
    point = scope["authorized_threshold_point"]
    print(json.dumps({
        "status": "PASS",
        "authorization": str(output),
        "state": state,
        "authorization_sha256": auth["authorization_sha256"],
        "authorized_action": auth["authorized_action"],
        "selected_candidate_id": auth["selected_candidate_id"],
        "authorized_threshold": scope["authorized_threshold"],
        "authorized_threshold_evidence_sha256": scope[
            "authorized_threshold_evidence_sha256"
        ],
        "authorized_threshold_point": point,
        "threshold_selection_authorized": auth[
            "threshold_selection_authorized"
        ],
        "threshold_selection_performed": auth[
            "threshold_selection_performed"
        ],
        "threshold_selected": auth["threshold_selected"],
        "threshold_frozen": auth["threshold_frozen"],
        "final_holdout_touched": auth["final_holdout_touched"],
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
