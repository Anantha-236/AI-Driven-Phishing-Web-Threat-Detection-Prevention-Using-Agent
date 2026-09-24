"""CLI for materializing Stage B contextual vectors with the deployed TSFEG extractor."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_features import materialize_feature_dataset

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--splits", type=Path, required=True)
    parser.add_argument("--episodes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    splits = json.loads(args.splits.read_text(encoding="utf-8"))
    episodes = json.loads(args.episodes.read_text(encoding="utf-8"))
    result = materialize_feature_dataset(splits, episodes, repo_root=ROOT)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "feature_version": result["feature_version"],
        "feature_count": len(result["feature_names"]),
        "feature_contract_sha256": result["feature_contract_sha256"],
        "extractor_source_sha256": result["extractor_source_sha256"],
        "samples": sum(part["sample_count"] for part in result["partitions"].values()),
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
