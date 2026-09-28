from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_threshold_freeze import (
    StageCThresholdFreezeError,
    freeze_stage_c_threshold,
    frozen_write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Freeze the single Task-23 authorized Stage-C candidate/threshold "
            "operating point."
        )
    )
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--selection-record", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        record = freeze_stage_c_threshold(
            repo_root=ROOT,
            authorization_path=a.authorization,
            selection_record_path=a.selection_record,
        )
        output = a.output_root / "threshold-freeze-record-v1.json"
        state = frozen_write_json(output, record)
    except (OSError, ValueError, StageCThresholdFreezeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    point = record["frozen_operating_point"]
    print(json.dumps({
        "status": "PASS",
        "record": str(output),
        "state": state,
        "threshold_freeze_record_sha256": record[
            "threshold_freeze_record_sha256"
        ],
        "candidate_threshold_pair_sha256": point[
            "candidate_threshold_pair_sha256"
        ],
        "selected_candidate_id": record["selected_candidate_id"],
        "selected_candidate_artifact_sha256": record[
            "selected_candidate_artifact_sha256"
        ],
        "threshold": point["threshold"],
        "threshold_rule": point["threshold_rule"],
        "threshold_selection_authorized": record[
            "threshold_selection_authorized"
        ],
        "threshold_selection_performed": record[
            "threshold_selection_performed"
        ],
        "threshold_selected": record["threshold_selected"],
        "threshold_frozen": record["threshold_frozen"],
        "final_holdout_touched": record["final_holdout_touched"],
        "next_gate": record["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
