from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_dataset_registry import (
    StageCDatasetRegistryError,
    audit_dataset_registry,
)
from .stage_c_protocol import load_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit Stage-C dataset/holdout registration and contamination guards."
    )
    parser.add_argument("--protocol-readiness", type=Path, required=True)
    parser.add_argument("--consumed-guard", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit_dataset_registry(
            protocol_readiness=load_json(args.protocol_readiness),
            consumed_guard=load_json(args.consumed_guard),
            registry=load_json(args.registry),
            repo_root=args.repo_root.resolve(),
        )
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, StageCDatasetRegistryError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
