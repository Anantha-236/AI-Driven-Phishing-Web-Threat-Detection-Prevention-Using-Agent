from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_readiness import DEFAULT_POLICY, audit_feature_dataset_readiness


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Stage B feature-dataset readiness before model training.")
    parser.add_argument("feature_dataset", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    feature_data = json.loads(args.feature_dataset.read_text(encoding="utf-8"))
    policy = DEFAULT_POLICY if args.policy is None else json.loads(args.policy.read_text(encoding="utf-8"))
    result = audit_feature_dataset_readiness(feature_data, policy)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["training_allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
