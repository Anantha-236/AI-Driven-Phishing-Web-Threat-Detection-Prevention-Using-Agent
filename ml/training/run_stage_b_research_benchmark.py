from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_research_benchmark import (
    ResearchBenchmarkError,
    run_research_benchmark_calibration,
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run research-only Stage B benchmark and calibration without touching test."
    )
    parser.add_argument("features", type=Path)
    parser.add_argument("readiness", type=Path)
    parser.add_argument("--calibration-policy", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = run_research_benchmark_calibration(
            load(args.features),
            load(args.readiness),
            load(args.calibration_policy) if args.calibration_policy else None,
        )
    except (OSError, json.JSONDecodeError, ResearchBenchmarkError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output_root.mkdir(parents=True, exist_ok=True)
    report_path = args.output_root / "research-benchmark-calibration.json"
    benchmark_path = args.output_root / "benchmark.json"
    calibration_path = args.output_root / "calibration.json"

    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    benchmark_path.write_text(
        json.dumps(result["benchmark"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    calibration_path.write_text(
        json.dumps(result["calibration"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps({
        "status": result["status"],
        "research_only": result["research_only"],
        "deployment_authorized": result["deployment_authorized"],
        "test_partition": result["test_partition"]["status"],
        "selected_candidate": result["selected_candidate"],
        "primary_fpr_cap": result["primary_research_operating_point"]["fpr_cap"],
        "finite_sample_statistical_support": result["primary_research_operating_point"]["finite_sample_statistical_support"],
        "underlying_calibration_threshold_flag": result["underlying_calibration_flag"]["deployment_threshold_authorized"],
        "output": str(report_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
