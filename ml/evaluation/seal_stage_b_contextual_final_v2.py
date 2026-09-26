from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from .stage_b_contextual_final_evidence_v2 import (
    FinalEvidenceSealError,
    build_final_evidence_seal,
    build_read_only_error_analysis,
    canonical_hash,
    load_json,
    reproduce_frozen_test_scores,
    sha256_file,
    verify_final_evidence_chain,
)


def frozen_write(path: Path, value) -> str:
    rendered = json.dumps(
        value,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if canonical_hash(existing) != canonical_hash(value):
            raise FinalEvidenceSealError(
                f"refusing to replace non-identical frozen artifact: {path}"
            )
        return "EXISTING_MATCH"
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(rendered, encoding="utf-8")
    temp.replace(path)
    return "CREATED"


def git_tag_target(tag: str) -> str | None:
    try:
        value = subprocess.check_output(
            ["git", "rev-list", "-n", "1", tag],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return value or None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Seal the consumed Stage B contextual-v2 final evidence and "
            "produce aggregate read-only error analysis."
        )
    )
    parser.add_argument("features", type=Path)
    parser.add_argument("readiness", type=Path)
    parser.add_argument("task30_report", type=Path)
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("calibration", type=Path)
    parser.add_argument("final_lock", type=Path)
    parser.add_argument("final_report", type=Path)
    parser.add_argument(
        "--calibration-policy",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-lock-file-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-final-file-sha256",
        required=True,
    )
    parser.add_argument(
        "--pre-final-commit",
        required=True,
    )
    parser.add_argument("--pre-final-tag")
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        features = load_json(args.features)
        readiness = load_json(args.readiness)
        task30 = load_json(args.task30_report)
        benchmark = load_json(args.benchmark)
        calibration = load_json(args.calibration)
        policy = load_json(args.calibration_policy)
        final_lock = load_json(args.final_lock)
        final_report = load_json(args.final_report)

        actual_lock_file_hash = sha256_file(args.final_lock)
        actual_final_file_hash = sha256_file(args.final_report)

        if (
            actual_lock_file_hash.lower()
            != args.expected_lock_file_sha256.lower()
        ):
            raise FinalEvidenceSealError(
                "final-test lock file SHA-256 does not match the recorded value"
            )
        if (
            actual_final_file_hash.lower()
            != args.expected_final_file_sha256.lower()
        ):
            raise FinalEvidenceSealError(
                "final-evaluation file SHA-256 does not match the recorded value"
            )

        verification = verify_final_evidence_chain(
            feature_data=features,
            readiness=readiness,
            task30_report=task30,
            benchmark=benchmark,
            calibration=calibration,
            calibration_policy=policy,
            final_lock=final_lock,
            final_report=final_report,
        )

        test_rows, labels, scores = reproduce_frozen_test_scores(
            feature_data=verification["validated_features"],
            benchmark=benchmark,
            calibration=calibration,
            policy=verification["active_policy"],
            expected_test_score_sha256=verification[
                "test_score_sha256"
            ],
        )

        analysis = build_read_only_error_analysis(
            feature_data=verification["validated_features"],
            test_rows=test_rows,
            labels=labels,
            scores=scores,
            threshold=verification["threshold"],
            test_score_sha256=verification[
                "test_score_sha256"
            ],
        )

        tag_target = (
            git_tag_target(args.pre_final_tag)
            if args.pre_final_tag
            else None
        )
        seal = build_final_evidence_seal(
            verification=verification,
            final_lock=final_lock,
            final_report=final_report,
            lock_file_sha256=actual_lock_file_hash,
            final_report_file_sha256=actual_final_file_hash,
            pre_final_commit=args.pre_final_commit,
            pre_final_tag=args.pre_final_tag,
            tag_target_commit=tag_target,
            error_analysis=analysis,
        )

        args.output_root.mkdir(parents=True, exist_ok=True)
        analysis_path = (
            args.output_root /
            "STAGE-B-V2-READ-ONLY-ERROR-ANALYSIS.json"
        )
        seal_path = (
            args.output_root /
            "STAGE-B-V2-FINAL-EVIDENCE.json"
        )

        analysis_state = frozen_write(analysis_path, analysis)
        seal_state = frozen_write(seal_path, seal)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        FinalEvidenceSealError,
    ) as exc:
        print(json.dumps(
            {"status": "FAIL", "error": str(exc)},
            indent=2,
        ))
        return 2

    print(json.dumps({
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "final_test_consumed": True,
        "future_tuning_on_same_test_prohibited": True,
        "reproduced_test_score_sha256": verification[
            "test_score_sha256"
        ],
        "lock_file_sha256": actual_lock_file_hash,
        "final_report_file_sha256": actual_final_file_hash,
        "pre_final_commit": args.pre_final_commit,
        "pre_final_tag": args.pre_final_tag,
        "pre_final_tag_target": tag_target,
        "sample_counts": analysis["sample_counts"],
        "research_fpr_objective_supported": seal[
            "conclusion"
        ]["research_fpr_objective_supported"],
        "analysis_state": analysis_state,
        "seal_state": seal_state,
        "error_analysis": str(analysis_path),
        "evidence_seal": str(seal_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
