from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_final_holdout_feature_extraction import (
    StageCFinalHoldoutFeatureExtractionError,
    run_stage_c_final_holdout_feature_extraction,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Replay the frozen clean Stage-C final holdout and extract the exact "
            "27 production context features without model access."
        )
    )
    p.add_argument("--html-archive", type=Path, required=True)
    p.add_argument("--clean-evaluation-set", type=Path, required=True)
    p.add_argument("--authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument(
        "--expected-authorization-sha256",
        required=True,
    )
    p.add_argument("--batch-size", type=int, default=256)
    p.add_argument("--wait-ms", type=int, default=250)
    p.add_argument("--timeout-seconds", type=int, default=1800)
    p.add_argument("--max-batches", type=int)
    p.add_argument("--dist", type=Path)
    a = p.parse_args()

    try:
        result = run_stage_c_final_holdout_feature_extraction(
            repo_root=ROOT,
            html_archive_path=a.html_archive,
            clean_set_path=a.clean_evaluation_set,
            authorization_path=a.authorization,
            output_root=a.output_root,
            expected_authorization_sha256=a.expected_authorization_sha256,
            batch_size=a.batch_size,
            wait_ms=a.wait_ms,
            timeout_seconds=a.timeout_seconds,
            max_batches=a.max_batches,
            dist_path=a.dist,
            progress=lambda row: print(
                json.dumps(row, sort_keys=True), flush=True
            ),
        )
    except (
        OSError,
        ValueError,
        StageCFinalHoldoutFeatureExtractionError,
    ) as exc:
        print(json.dumps({
            "status": "FAIL",
            "error": str(exc),
            "model_loaded": False,
            "model_scoring_performed": False,
            "metrics_computed": False,
        }, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
