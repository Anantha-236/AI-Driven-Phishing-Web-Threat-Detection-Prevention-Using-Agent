
from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_corpus_inspection import load_json
from .stage_c_development_record_index import (
    StageCDevelopmentIndexError,
    build_development_record_index,
    frozen_write_json,
)

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the frozen Stage-C deterministic development record index."
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--seal", type=Path, required=True)
    parser.add_argument("--inspection", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        index_payload, quarantine, report = build_development_record_index(
            archive_path=args.archive,
            seal=load_json(args.seal),
            inspection=load_json(args.inspection),
        )
        index_path = args.output_root / "development-record-index.json"
        quarantine_path = args.output_root / "archive-extra-html-quarantine.json"
        report_path = args.output_root / "development-index-report.json"

        states = {
            "index": frozen_write_json(index_path, index_payload),
            "quarantine": frozen_write_json(quarantine_path, quarantine),
            "report": frozen_write_json(report_path, report),
        }
    except (OSError, ValueError, StageCDevelopmentIndexError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "record_count": report["record_count"],
        "class_counts": report["class_counts"],
        "created_date_min": report["created_date_min"],
        "created_date_max": report["created_date_max"],
        "rec_id_contiguous_1_to_expected": report["rec_id_contiguous_1_to_expected"],
        "unique_artifact_sha256_count": report["unique_artifact_sha256_count"],
        "duplicate_artifact_groups": report["duplicate_artifact_groups"],
        "duplicate_artifact_samples": report["duplicate_artifact_samples"],
        "cross_label_duplicate_artifact_groups": report["cross_label_duplicate_artifact_groups"],
        "cross_label_duplicate_artifact_samples": report["cross_label_duplicate_artifact_samples"],
        "canonical_oversized_html_over_12_mib": report["canonical_oversized_html_over_12_mib"],
        "archive_extra_html_quarantine_count": report["archive_extra_html_quarantine_count"],
        "record_set_sha256": report["record_set_sha256"],
        "index_evidence_sha256": report["index_evidence_sha256"],
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "states": states,
        "outputs": {
            "index": str(index_path),
            "quarantine": str(quarantine_path),
            "report": str(report_path),
        },
        "next_gate": report["next_gate"],
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
