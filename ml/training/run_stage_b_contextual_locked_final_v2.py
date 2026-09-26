from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_contextual_locked_final_v2 import (
    ContextualLockedFinalError,
    build_lock_material,
    canonical_hash,
    create_or_validate_lock,
    run_contextual_locked_final,
    validate_contextual_final_chain,
)


def load(path: Path):
    if not path.is_file():
        raise ContextualLockedFinalError(
            f"required JSON file not found: {path}"
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContextualLockedFinalError(
            f"JSON root must be an object: {path}"
        )
    return value


def frozen_write(path: Path, value) -> str:
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if canonical_hash(existing) != canonical_hash(value):
            raise ContextualLockedFinalError(
                f"refusing to replace non-identical frozen final report: {path}"
            )
        return "EXISTING_MATCH"

    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temp.replace(path)
    return "CREATED"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the one-time Stage B contextual-v2 locked research "
            "final-test evaluation."
        )
    )
    parser.add_argument("features", type=Path)
    parser.add_argument("readiness", type=Path)
    parser.add_argument("task30_report", type=Path)
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("calibration", type=Path)
    parser.add_argument(
        "--calibration-policy",
        type=Path,
        required=True,
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument(
        "--acknowledge-final-test",
        action="store_true",
    )
    args = parser.parse_args()

    try:
        features = load(args.features)
        readiness = load(args.readiness)
        task30 = load(args.task30_report)
        benchmark = load(args.benchmark)
        calibration = load(args.calibration)
        policy = load(args.calibration_policy)

        chain = validate_contextual_final_chain(
            features,
            readiness,
            task30,
            benchmark,
            calibration,
            policy,
        )
        lock_material = build_lock_material(
            feature_data=chain["validated_features"],
            readiness=readiness,
            task30_report=task30,
            benchmark=benchmark,
            calibration=calibration,
            policy=chain["active_policy"],
            test_partition=chain["test_partition"],
        )

        if args.preflight_only:
            print(json.dumps({
                "status": "PASS",
                "research_protocol": task30[
                    "research_protocol"
                ],
                "research_only": True,
                "deployment_authorized": False,
                "selected_candidate": task30[
                    "selected_candidate"
                ],
                "test_partition": "LOCKED_UNSCORED",
                "test_samples": chain[
                    "test_partition"
                ]["sample_count"],
                "test_partition_sha256": chain[
                    "test_partition"
                ]["sha256"],
                "primary_fpr_cap": lock_material[
                    "primary_fpr_cap"
                ],
                "primary_threshold": lock_material[
                    "primary_threshold"
                ],
                "calibration_confidence_supported": task30[
                    "primary_research_operating_point"
                ]["confidence_supported"],
                "finite_sample_statistical_support": task30[
                    "primary_research_operating_point"
                ][
                    "finite_sample_statistical_support"
                ],
                "lock_not_created": True,
                "test_not_scored": True,
            }, indent=2))
            return 0

        if not args.acknowledge_final_test:
            raise ContextualLockedFinalError(
                "final test remains locked; rerun with "
                "--acknowledge-final-test only when you intend the "
                "one-time contextual-v2 test exposure"
            )

        lock_path = (
            args.output_root /
            "contextual-v2-final-test.lock.json"
        )
        lock_state = create_or_validate_lock(
            lock_path,
            lock_material,
        )

        # The lock now exists and matches the exact evidence chain.
        # Only after this point may test probabilities be computed.
        result = run_contextual_locked_final(
            feature_data=features,
            readiness=readiness,
            task30_report=task30,
            benchmark=benchmark,
            calibration=calibration,
            policy=policy,
        )
        result["final_test_lock_sha256"] = canonical_hash(
            lock_material
        )
        result["final_test_lock_state"] = lock_state

        output = (
            args.output_root /
            "contextual-v2-final-evaluation.json"
        )
        report_state = frozen_write(output, result)

    except (
        OSError,
        json.JSONDecodeError,
        ValueError,
        ContextualLockedFinalError,
    ) as exc:
        print(json.dumps(
            {"status": "FAIL", "error": str(exc)},
            indent=2,
        ))
        return 2

    fixed = result["fixed_operating_point"]
    cm = fixed["confusion_matrix"]
    print(json.dumps({
        "status": result["status"],
        "research_only": result["research_only"],
        "deployment_authorized": result[
            "deployment_authorized"
        ],
        "selected_candidate": result[
            "selected_candidate"
        ],
        "test_samples": result["test_samples"],
        "average_precision": result[
            "threshold_free_metrics"
        ]["average_precision"],
        "roc_auc": result[
            "threshold_free_metrics"
        ]["roc_auc"],
        "brier_score": result[
            "threshold_free_metrics"
        ]["brier_score"],
        "threshold": fixed["threshold"],
        "tn": cm["tn"],
        "fp": cm["fp"],
        "fn": cm["fn"],
        "tp": cm["tp"],
        "precision": fixed["precision"],
        "recall": fixed["recall"],
        "observed_fpr": fixed["observed_fpr"],
        "fpr_wilson_95": fixed[
            "fpr_wilson_95"
        ],
        "observed_fpr_within_research_cap": fixed[
            "observed_fpr_within_research_cap"
        ],
        "wilson_95_upper_within_research_cap": fixed[
            "wilson_95_upper_within_research_cap"
        ],
        "warnings": result["warnings"],
        "lock_state": lock_state,
        "report_state": report_state,
        "output": str(output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
