from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ml.training.stage_b_calibration import (
    CalibrationError,
    calibrate_stage_b_model,
)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate the selected Stage B model without touching final test.")
    parser.add_argument("features", type=Path)
    parser.add_argument("readiness", type=Path)
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = calibrate_stage_b_model(
            _load(args.features),
            _load(args.readiness),
            _load(args.benchmark),
            _load(args.policy) if args.policy else None,
        )
    except (OSError, json.JSONDecodeError, CalibrationError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "selected_candidate": result["selected_candidate"],
        "calibration_method": result["calibration_method"],
        "deployment_threshold_authorized": result["threshold_selection"]["deployment_threshold_authorized"],
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
