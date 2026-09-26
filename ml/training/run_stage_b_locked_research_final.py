from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_locked_research_final import (
    ResearchFinalError,
    acquire_final_test_lock,
    finalize_lock,
    load_json,
    lock_path_for_dataset,
    run_locked_research_final,
    validate_research_final_chain,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the one-time locked Stage B research final-test evaluation."
    )
    parser.add_argument("features", type=Path)
    parser.add_argument("readiness", type=Path)
    parser.add_argument("task22_report", type=Path)
    parser.add_argument(
        "--calibration-policy",
        type=Path,
        default=Path("ml/training/manifests/stage-b-calibration-policy.json"),
    )
    parser.add_argument(
        "--lock-root",
        type=Path,
        default=Path(".runtime/stage-b/research-final-test-locks"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--acknowledge-one-time-final-test", action="store_true")
    args = parser.parse_args()

    try:
        features = load_json(args.features)
        readiness = load_json(args.readiness)
        task22 = load_json(args.task22_report)
        policy = load_json(args.calibration_policy)
        chain = validate_research_final_chain(
            feature_data=features,
            readiness=readiness,
            task22=task22,
            calibration_policy=policy,
        )
        lock_path = lock_path_for_dataset(
            args.lock_root, chain["feature_dataset_sha256"]
        )

        preflight = {
            "status": "PASS",
            "research_only": True,
            "deployment_authorized": False,
            "feature_dataset_sha256": chain["feature_dataset_sha256"],
            "test_partition_identity_sha256": chain["test_partition_identity_sha256"],
            "test_samples": chain["test_samples"],
            "lock_path": str(lock_path),
            "lock_exists": lock_path.exists(),
            "output_exists": args.output.exists(),
        }
        if args.preflight_only:
            print(json.dumps(preflight, indent=2))
            return 0 if not lock_path.exists() and not args.output.exists() else 3

        if not args.acknowledge_one_time_final_test:
            parser.error(
                "final test remains locked; use --acknowledge-one-time-final-test "
                "only after Task 22 is frozen"
            )
        if args.output.exists():
            raise ResearchFinalError(
                f"refusing to overwrite existing research final report: {args.output}"
            )

        prepared = acquire_final_test_lock(
            path=lock_path,
            chain=chain,
            feature_path=args.features,
            readiness_path=args.readiness,
            task22_path=args.task22_report,
            calibration_policy_path=args.calibration_policy,
        )

        result = run_locked_research_final(
            feature_data=features,
            readiness=readiness,
            task22=task22,
            calibration_policy=policy,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        finalize_lock(
            lock_path,
            prepared,
            result=result,
            output_path=args.output,
        )

        print(json.dumps({
            "status": result["status"],
            "research_only": result["research_only"],
            "deployment_authorized": result["deployment_authorized"],
            "selected_candidate": result["selected_candidate"],
            "test_samples": result["test_samples"],
            "observed_fpr": result["fixed_research_operating_point"]["observed_fpr"],
            "recall": result["fixed_research_operating_point"]["recall"],
            "lock": str(lock_path),
            "output": str(args.output),
        }, indent=2))
        return 0
    except (ResearchFinalError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
