from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_contextual_research_benchmark_v2 import (
    ContextualResearchBenchmarkError,
    canonical_hash,
    run_contextual_v2_benchmark_calibration,
    validate_contextual_v2_readiness,
)
from ml.training.stage_b_calibration import validate_calibration_policy


def load(path: Path):
    if not path.is_file():
        raise ContextualResearchBenchmarkError(
            f"required JSON file not found: {path}"
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContextualResearchBenchmarkError(
            f"JSON root must be an object: {path}"
        )
    return value


def write_frozen(path: Path, value) -> None:
    rendered = json.dumps(
        value,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if canonical_hash(existing) != canonical_hash(value):
            raise ContextualResearchBenchmarkError(
                f"refusing to replace non-identical frozen artifact: {path}"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(rendered, encoding="utf-8")
    temp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run Stage B contextual research-v2 benchmark and calibration "
            "without scoring the locked test partition."
        )
    )
    parser.add_argument("features", type=Path)
    parser.add_argument("readiness", type=Path)
    parser.add_argument("--calibration-policy", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    try:
        features = load(args.features)
        readiness = load(args.readiness)
        validated = validate_contextual_v2_readiness(
            features,
            readiness,
        )
        policy = (
            validate_calibration_policy(load(args.calibration_policy))
            if args.calibration_policy
            else None
        )

        if args.preflight_only:
            print(json.dumps({
                "status": "PASS",
                "research_protocol": readiness.get("research_protocol"),
                "research_only": True,
                "deployment_authorized": False,
                "test_partition": "LOCKED_NOT_USED",
                "feature_dataset_identity": {
                    "feature_version": validated.get("feature_version"),
                    "feature_contract_sha256": validated.get(
                        "feature_contract_sha256"
                    ),
                    "extractor_source_sha256": validated.get(
                        "extractor_source_sha256"
                    ),
                    "episode_set_sha256": validated.get(
                        "episode_set_sha256"
                    ),
                },
                "counts": readiness.get("counts"),
                "chronology": readiness.get("chronology"),
                "calibration_policy_validated": policy is not None,
            }, indent=2))
            return 0

        result = run_contextual_v2_benchmark_calibration(
            features,
            readiness,
            policy,
        )
    except (
        OSError,
        json.JSONDecodeError,
        ValueError,
        ContextualResearchBenchmarkError,
    ) as exc:
        print(json.dumps(
            {"status": "FAIL", "error": str(exc)},
            indent=2,
        ))
        return 2

    args.output_root.mkdir(parents=True, exist_ok=True)
    report_path = (
        args.output_root /
        "contextual-v2-benchmark-calibration.json"
    )
    benchmark_path = args.output_root / "benchmark.json"
    calibration_path = args.output_root / "calibration.json"

    try:
        write_frozen(report_path, result)
        write_frozen(benchmark_path, result["benchmark"])
        write_frozen(calibration_path, result["calibration"])
    except (
        OSError,
        json.JSONDecodeError,
        ContextualResearchBenchmarkError,
    ) as exc:
        print(json.dumps(
            {"status": "FAIL", "error": str(exc)},
            indent=2,
        ))
        return 2

    primary = result["primary_research_operating_point"]
    print(json.dumps({
        "status": result["status"],
        "research_protocol": result["research_protocol"],
        "research_only": result["research_only"],
        "deployment_authorized": result["deployment_authorized"],
        "test_partition": result["test_partition"]["status"],
        "selected_candidate": result["selected_candidate"],
        "candidate_ranking": result["candidate_ranking"],
        "calibration_method": result["calibration_method"],
        "primary_fpr_cap": primary["fpr_cap"],
        "observed_fpr": primary["observed_fpr"],
        "recall": primary["recall"],
        "precision": primary["precision"],
        "wilson_95_fpr_upper": primary["wilson_95_fpr_upper"],
        "empirically_resolved": primary["empirically_resolved"],
        "confidence_supported": primary["confidence_supported"],
        "finite_sample_statistical_support": primary[
            "finite_sample_statistical_support"
        ],
        "underlying_calibration_threshold_flag": result[
            "underlying_calibration_flag"
        ]["deployment_threshold_authorized"],
        "output": str(report_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
