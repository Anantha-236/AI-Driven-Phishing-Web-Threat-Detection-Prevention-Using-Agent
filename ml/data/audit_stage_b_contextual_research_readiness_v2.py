from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_contextual_research_readiness_v2 import (
    ContextualResearchReadinessError,
    audit_contextual_research_v2_readiness,
)


def load(path: Path):
    if not path.is_file():
        raise ContextualResearchReadinessError(
            f"required JSON file not found: {path}"
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContextualResearchReadinessError(
            f"JSON root must be an object: {path}"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit Stage B contextual research protocol-v2 readiness."
    )
    parser.add_argument("feature_dataset", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = audit_contextual_research_v2_readiness(
            load(args.feature_dataset),
            load(args.policy),
        )
    except (
        ContextualResearchReadinessError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_suffix(args.output.suffix + ".tmp")
    temp.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temp.replace(args.output)

    print(json.dumps({
        "status": result["status"],
        "training_allowed": result["training_allowed"],
        "research_protocol": result["research_protocol"],
        "research_only": result["research_only"],
        "deployment_authorized": result["deployment_authorized"],
        "counts": result["counts"],
        "chronology": result["chronology"],
        "issues": result["issues"],
        "output": str(args.output),
    }, indent=2))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
