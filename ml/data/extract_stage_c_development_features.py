from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_development_feature_extraction import (
    EXPECTED_AUTHORIZATION_SHA256,
    StageCFeatureExtractionError,
    run_stage_c_development_feature_extraction,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Checkpointed Stage-C development HTML replay, production context-features-1 "
            "extraction, and post-extraction integrity audit."
        )
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--record-index", type=Path, required=True)
    parser.add_argument("--index-report", type=Path, required=True)
    parser.add_argument("--split-manifest", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--expected-authorization-sha256",
        default=EXPECTED_AUTHORIZATION_SHA256,
        help="Exact Task-9-v2 authorization identity. Defaults to the frozen current value.",
    )
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--wait-ms", type=int, default=250)
    parser.add_argument("--collector-timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--max-batches", type=int,
        help="Optional checkpointed smoke/probe limit. Omit to run all remaining batches.",
    )
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()

    def progress(event: dict) -> None:
        print(json.dumps(event, sort_keys=True), flush=True)

    try:
        result = run_stage_c_development_feature_extraction(
            repo_root=ROOT,
            archive_path=args.archive,
            record_index_path=args.record_index,
            index_report_path=args.index_report,
            split_manifest_path=args.split_manifest,
            authorization_path=args.authorization,
            output_root=args.output_root,
            expected_authorization_sha256=args.expected_authorization_sha256,
            batch_size=args.batch_size,
            wait_ms=args.wait_ms,
            timeout_seconds=args.collector_timeout_seconds,
            max_batches=args.max_batches,
            dist_path=args.dist,
            progress=progress,
        )
    except (OSError, ValueError, StageCFeatureExtractionError) as exc:
        print(json.dumps({
            "status": "FAIL",
            "error": str(exc),
            "model_training_authorized": False,
            "model_scoring_authorized": False,
            "final_holdout_touched": False,
        }, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
