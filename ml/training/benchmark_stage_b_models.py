from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_benchmark import BenchmarkError, benchmark_stage_b_models


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Stage B train/selection model benchmark.")
    parser.add_argument("feature_dataset", type=Path)
    parser.add_argument("readiness_audit", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    feature_data = json.loads(args.feature_dataset.read_text(encoding="utf-8"))
    readiness = json.loads(args.readiness_audit.read_text(encoding="utf-8"))
    try:
        result = benchmark_stage_b_models(feature_data, readiness)
    except BenchmarkError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
