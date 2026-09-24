from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.training.stage_b_release_candidate import freeze_stage_b_release_candidate


def load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze a Stage B ONNX release candidate without deploying it.")
    parser.add_argument("features")
    parser.add_argument("readiness")
    parser.add_argument("benchmark")
    parser.add_argument("calibration")
    parser.add_argument("final_evaluation")
    parser.add_argument("--policy", default="ml/training/manifests/stage-b-calibration-policy.json")
    parser.add_argument("--output-dir", default=".runtime/stage-b/release-candidate")
    parser.add_argument("--acknowledge-release-freeze", action="store_true")
    args = parser.parse_args()

    if not args.acknowledge_release_freeze:
        parser.error("--acknowledge-release-freeze is required")
    output = Path(args.output_dir)
    if output.exists() and any(output.iterdir()):
        parser.error("output directory is not empty; refusing to overwrite a frozen candidate")

    result = freeze_stage_b_release_candidate(
        load(args.features),
        load(args.readiness),
        load(args.benchmark),
        load(args.calibration),
        load(args.final_evaluation),
        output,
        load(args.policy),
    )
    print(json.dumps({
        "status": result["status"],
        "model_id": result["model_id"],
        "onnx_sha256": result["onnx"]["sha256"],
        "parity": result["parity"],
        "release_gate": result["release_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
