from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_primary_holdout_availability import (
    StageCPrimaryHoldoutAvailabilityError,
    freeze_primary_holdout_availability,
    frozen_write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Freeze public availability evidence for the Stage-C primary "
            "CompPhish v3 final holdout."
        )
    )
    p.add_argument("--contingency-policy", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        report = freeze_primary_holdout_availability(
            repo_root=ROOT,
            contingency_policy_path=a.contingency_policy,
        )
        output = a.output_root / "primary-holdout-availability-v1.json"
        state = frozen_write_json(output, report)
    except (OSError, ValueError, StageCPrimaryHoldoutAvailabilityError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    evidence = report["public_availability_evidence"]
    print(json.dumps({
        "status": "PASS",
        "report": str(output),
        "state": state,
        "availability_report_sha256": report["availability_report_sha256"],
        "public_evidence_sha256": report["public_evidence_sha256"],
        "primary_candidate_id": report["primary_candidate_id"],
        "availability_decision": report["availability_decision"],
        "landing_page": evidence["landing_page"],
        "download_all_control_visible": evidence[
            "download_all_control_visible"
        ],
        "raw_html_archive_name": evidence["raw_html_archive_name"],
        "mapping_file_name": evidence["mapping_file_name"],
        "manual_download_required": report["manual_download_required"],
        "fallback_activated": report["fallback_activated"],
        "final_holdout_touched": report["final_holdout_touched"],
        "final_holdout_model_scoring_authorized": report[
            "final_holdout_model_scoring_authorized"
        ],
        "next_gate": report["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
