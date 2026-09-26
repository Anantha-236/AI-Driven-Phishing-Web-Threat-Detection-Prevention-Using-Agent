from __future__ import annotations
import argparse
import json
from pathlib import Path

from .stage_c_feature_extraction_authorization import (
    StageCFeatureAuthorizationError,
    frozen_write_json,
    load_json,
)
from .stage_c_feature_extraction_authorization_v2 import (
    load_production_feature_contract,
    register_and_authorize_v2,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Issue corrected Stage-C feature authorization bound to "
            "production TSFEG order."
        )
    )
    p.add_argument("--experiment-contract", type=Path, required=True)
    p.add_argument("--feature-semantics", type=Path, required=True)
    p.add_argument("--split-contract", type=Path, required=True)
    p.add_argument("--split-manifest", type=Path, required=True)
    p.add_argument("--superseded-authorization", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()

    try:
        production = load_production_feature_contract(ROOT)
        reg, auth = register_and_authorize_v2(
            experiment_contract=load_json(a.experiment_contract),
            feature_semantics=load_json(a.feature_semantics),
            split_contract=load_json(a.split_contract),
            split_manifest=load_json(a.split_manifest),
            superseded_authorization=load_json(
                a.superseded_authorization
            ),
            production_feature_contract=production,
        )
        rp = a.output_root / "development-split-registration-v2.json"
        ap = a.output_root / "feature-extraction-authorization-v2.json"
        states = {
            "registration": frozen_write_json(rp, reg),
            "authorization": frozen_write_json(ap, auth),
        }
    except (OSError, ValueError, StageCFeatureAuthorizationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "superseded_authorization_sha256": auth["supersedes"][
            "authorization_sha256"
        ],
        "authorized_sample_count": auth["scope"]["authorized_sample_count"],
        "feature_version": auth["feature_contract"][
            "source_feature_version"
        ],
        "feature_count": auth["feature_contract"]["feature_count"],
        "ordered_features": auth["feature_contract"]["ordered_features"],
        "feature_contract_sha256": auth["feature_contract"][
            "feature_contract_sha256"
        ],
        "extractor_source_sha256": auth["feature_contract"][
            "extractor_source_sha256"
        ],
        "feature_extraction_authorized": True,
        "model_training_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "registration_sha256": reg["registration_sha256"],
        "authorization_sha256": auth["authorization_sha256"],
        "states": states,
        "outputs": {
            "registration": str(rp),
            "authorization": str(ap),
        },
        "next_gate": auth["next_gate"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
