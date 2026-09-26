from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_contextual_research_v2 import (
    ContextualResearchSplitError,
    construct_contextual_research_splits,
)


def load(path: Path):
    if not path.is_file():
        raise ContextualResearchSplitError(f"required JSON file not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContextualResearchSplitError(f"JSON root must be an object: {path}")
    return value


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build Stage B contextual research protocol v2 splits."
    )
    parser.add_argument("--normalized-plan", type=Path, required=True)
    parser.add_argument("--raw-plan", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--readiness-policy", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        normalized = load(args.normalized_plan)
        contract = load(args.contract)
        policy = load(args.readiness_policy)
        splits = construct_contextual_research_splits(normalized, contract, policy)

        supervised_ids = {
            row["sample_id"]
            for partition in splits["partitions"].values()
            for row in partition["records"]
        }

        supervised_normalized = json.loads(json.dumps(normalized))
        supervised_normalized["plan_id"] = (
            str(normalized.get("plan_id", "stage-b")) + "-contextual-v2-supervised"
        )
        supervised_normalized["items"] = [
            row for row in normalized["items"]
            if row.get("sample_id") in supervised_ids
        ]
        if len(supervised_normalized["items"]) != len(supervised_ids):
            raise ContextualResearchSplitError(
                "normalized supervised plan does not exactly match split sample IDs"
            )

        args.output_root.mkdir(parents=True, exist_ok=True)
        atomic_json(args.output_root / "research-splits.json", splits)
        atomic_json(
            args.output_root / "supervised-replay-plan.normalized.json",
            supervised_normalized,
        )

        raw_output = None
        if args.raw_plan is not None:
            raw = load(args.raw_plan)
            raw_items = raw.get("items")
            if not isinstance(raw_items, list):
                raise ContextualResearchSplitError("raw plan requires items")
            supervised_raw = json.loads(json.dumps(raw))
            supervised_raw["plan_id"] = (
                str(raw.get("plan_id", "stage-b")) + "-contextual-v2-supervised"
            )
            supervised_raw["items"] = [
                row for row in raw_items
                if row.get("sample_id") in supervised_ids
            ]
            if len(supervised_raw["items"]) != len(supervised_ids):
                raise ContextualResearchSplitError(
                    "raw supervised plan does not exactly match split sample IDs"
                )
            raw_output = args.output_root / "supervised-replay-plan.json"
            atomic_json(raw_output, supervised_raw)

        counts = {
            name: {
                "total": payload["sample_count"],
                "legitimate": payload["legitimate"],
                "phishing": payload["phishing"],
            }
            for name, payload in splits["partitions"].items()
        }
        report = {
            "schema_version": "stage-b-contextual-research-v2-report-1",
            "status": "PASS",
            "research_only": True,
            "deployment_authorized": False,
            "protocol_id": splits["audit"]["protocol_id"],
            "counts": counts,
            "selected_cutoff": splits["audit"]["selected_cutoff"],
            "chronology_bridge_sample_count": splits["audit"]["chronology_bridge_sample_count"],
            "active_isolation_dimensions": splits["audit"]["isolation_dimensions"],
            "audit_only_dimensions": splits["audit"]["audit_only_dimensions"],
            "supervised_samples": len(supervised_ids),
            "outputs": {
                "research_splits": str(args.output_root / "research-splits.json"),
                "supervised_replay_plan_normalized": str(
                    args.output_root / "supervised-replay-plan.normalized.json"
                ),
                "supervised_replay_plan": str(raw_output) if raw_output else None,
            },
        }
        atomic_json(args.output_root / "contextual-v2-report.json", report)

    except (OSError, json.JSONDecodeError, ValueError, ContextualResearchSplitError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
