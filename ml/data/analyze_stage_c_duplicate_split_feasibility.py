
from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_duplicate_split_feasibility import (
    StageCSplitFeasibilityError,
    analyze_temporal_feasibility,
    build_duplicate_audit,
    frozen_write_json,
    load_json,
    _require_inputs,
)

def main() -> int:
    p = argparse.ArgumentParser(
        description="Audit Stage-C exact duplicates and strict-forward artifact-safe split feasibility."
    )
    p.add_argument("--index", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--max-results", type=int, default=20)
    a = p.parse_args()

    try:
        index = load_json(a.index)
        report = load_json(a.report)
        policy = load_json(a.policy)
        _require_inputs(index, report, policy)
        audit, quarantine_ids = build_duplicate_audit(index)
        feasibility = analyze_temporal_feasibility(
            index=index,
            quarantine_ids=quarantine_ids,
            audit=audit,
            policy=policy,
            max_results=max(1, a.max_results),
        )
        audit_path = a.output_root / "duplicate-artifact-audit.json"
        feas_path = a.output_root / "strict-forward-split-feasibility.json"
        states = {
            "audit": frozen_write_json(audit_path, audit),
            "feasibility": frozen_write_json(feas_path, feasibility),
        }
    except (OSError, ValueError, StageCSplitFeasibilityError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    best = feasibility["recommended_candidate"]
    print(json.dumps({
        "status": "PASS",
        "record_count": audit["record_count"],
        "unique_artifacts": audit["unique_artifacts"],
        "duplicate_groups": audit["duplicate_artifacts"]["groups"],
        "duplicate_samples": audit["duplicate_artifacts"]["samples"],
        "cross_label_groups": audit["cross_label_duplicate_artifacts"]["groups"],
        "cross_label_samples": audit["cross_label_duplicate_artifacts"]["samples"],
        "oversized_samples": audit["oversized_sample_count"],
        "quarantine_union_count": audit["quarantine_union_count"],
        "eligible_samples": audit["eligible_sample_count"],
        "feasibility": feasibility["feasibility"],
        "candidate_pairs_examined": feasibility["candidate_pairs_examined"],
        "planning_floor_feasible_pairs": feasibility["planning_floor_feasible_pairs"],
        "recommended_candidate": best,
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "states": states,
        "outputs": {
            "duplicate_audit": str(audit_path),
            "split_feasibility": str(feas_path),
        },
        "next_gate": feasibility["next_gate"],
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
