from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_holdout_contingency_policy import (
    StageCHoldoutContingencyPolicyError,
    freeze_holdout_contingency_policy,
    frozen_write_json,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Freeze the performance-blind Stage-C final-holdout fallback policy."
        )
    )
    p.add_argument("--task25-authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        policy = freeze_holdout_contingency_policy(
            repo_root=ROOT,
            task25_authorization_path=a.task25_authorization,
        )
        output = a.output_root / "final-holdout-contingency-policy-v1.json"
        state = frozen_write_json(output, policy)
    except (OSError, ValueError, StageCHoldoutContingencyPolicyError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    sp = policy["selection_policy"]
    print(json.dumps({
        "status": "PASS",
        "policy": str(output),
        "state": state,
        "contingency_policy_sha256": policy["contingency_policy_sha256"],
        "policy_evidence_sha256": policy["policy_evidence_sha256"],
        "primary_final_holdout_candidate_id": policy[
            "primary_final_holdout_candidate_id"
        ],
        "fallback_candidate_ids": [
            x["candidate_id"] for x in sp["fallbacks_in_priority_order"]
        ],
        "performance_blind_selection_required": sp[
            "performance_blind_selection_required"
        ],
        "fallback_activated": policy["fallback_activated"],
        "model_scoring_authorized": policy["model_scoring_authorized"],
        "metric_computation_authorized": policy[
            "metric_computation_authorized"
        ],
        "final_holdout_touched": policy["final_holdout_touched"],
        "next_gate": policy["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
