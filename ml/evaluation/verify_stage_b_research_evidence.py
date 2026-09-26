from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_research_evidence import (
    ResearchEvidenceError,
    load_json,
    verify_evidence_chain,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify and freeze the Stage B scaled research evidence chain."
    )
    parser.add_argument("--task20-report", type=Path, required=True)
    parser.add_argument("--task21-report", type=Path, required=True)
    parser.add_argument("--task21-readiness", type=Path, required=True)
    parser.add_argument("--task22-report", type=Path, required=True)
    parser.add_argument("--task23-report", type=Path, required=True)
    parser.add_argument("--task23-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        parser.error("refusing to overwrite an existing research evidence manifest")

    try:
        result = verify_evidence_chain(
            task20_report=load_json(args.task20_report),
            task21_report=load_json(args.task21_report),
            task21_readiness=load_json(args.task21_readiness),
            task22_report=load_json(args.task22_report),
            task23_report=load_json(args.task23_report),
            final_lock=load_json(args.task23_lock),
        )
    except (ResearchEvidenceError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": result["status"],
        "research_only": result["research_only"],
        "deployment_authorized": result["deployment_authorized"],
        "feature_dataset_sha256": result["feature_dataset_sha256"],
        "test_samples": result["test_samples"],
        "selected_candidate": result["selected_candidate"],
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
