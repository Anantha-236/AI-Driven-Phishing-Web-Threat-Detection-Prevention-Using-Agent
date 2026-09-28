from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_final_holdout_local_seal import (
    StageCFinalHoldoutLocalSealError,
    frozen_write_json,
    seal_final_holdout_download,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Freeze a byte-level local integrity seal for downloaded "
            "CompPhish v3 final-holdout artifacts."
        )
    )
    p.add_argument("--task27-report", type=Path, required=True)
    p.add_argument("--html-archive", type=Path, required=True)
    p.add_argument("--mapping-workbook", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        seal = seal_final_holdout_download(
            repo_root=ROOT,
            task27_report_path=a.task27_report,
            html_archive_path=a.html_archive,
            mapping_workbook_path=a.mapping_workbook,
        )
        output = a.output_root / "final-holdout-local-integrity-seal-v1.json"
        state = frozen_write_json(output, seal)
    except (OSError, ValueError, StageCFinalHoldoutLocalSealError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    html = seal["local_artifacts"]["html_archive"]
    mapping = seal["local_artifacts"]["mapping_workbook"]
    print(json.dumps({
        "status": "PASS",
        "seal": str(output),
        "state": state,
        "local_integrity_seal_sha256": seal[
            "local_integrity_seal_sha256"
        ],
        "local_artifact_set_sha256": seal[
            "local_artifact_set_sha256"
        ],
        "html_archive_sha256": html["sha256"],
        "html_archive_size_bytes": html["size_bytes"],
        "html_capture_count": html["txt_capture_count"],
        "html_member_inventory_sha256": html[
            "member_inventory_sha256"
        ],
        "mapping_workbook_sha256": mapping["sha256"],
        "mapping_workbook_size_bytes": mapping["size_bytes"],
        "mapping_worksheet_count": mapping["worksheet_count"],
        "mapping_labels_accessed": seal["mapping_labels_accessed"],
        "html_capture_contents_accessed": seal[
            "html_capture_contents_accessed"
        ],
        "final_holdout_bytes_accessed_for_integrity": seal[
            "final_holdout_bytes_accessed_for_integrity"
        ],
        "final_holdout_feature_extraction_authorized": seal[
            "final_holdout_feature_extraction_authorized"
        ],
        "final_holdout_model_scoring_authorized": seal[
            "final_holdout_model_scoring_authorized"
        ],
        "next_gate": seal["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
