from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_temporal_coverage import (
    TemporalCoveragePlanError,
    build_temporal_coverage_plan,
    load_inventory,
    load_metadata_records,
    apply_verified_shard_index,
    validate_readiness_targets,
)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan additional Zenodo 8041387 shards from metadata before downloading archives."
    )
    parser.add_argument("--phishing-csv", type=Path, required=True)
    parser.add_argument("--legitimate-csv", type=Path, required=True)
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("ml/data/manifests/zenodo-8041387-full-files.json"),
    )
    parser.add_argument(
        "--readiness-policy",
        type=Path,
        default=Path("ml/data/manifests/stage-b-research-replay-readiness-policy.json"),
    )
    parser.add_argument("--existing-shard", action="append", default=[])
    parser.add_argument("--shard-index", type=Path, required=True)
    parser.add_argument("--reserve-fraction", type=float, default=0.20)
    parser.add_argument("--max-cutoff-candidates", type=int, default=256)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        inventory_raw = _load(args.inventory)
        inventory = load_inventory(inventory_raw)
        targets = validate_readiness_targets(
            _load(args.readiness_policy),
            reserve_fraction=args.reserve_fraction,
        )
        phishing, p_report = load_metadata_records(
            args.phishing_csv,
            klass="phishing",
            shards=inventory["phishing"],
        )
        legitimate, l_report = load_metadata_records(
            args.legitimate_csv,
            klass="legitimate",
            shards=inventory["legitimate"],
        )

        shard_by_name = {
            shard.name: shard
            for values in inventory.values()
            for shard in values
        }
        shard_index = _load(args.shard_index)
        phishing, phishing_mapping = apply_verified_shard_index(
            phishing,
            inventory["phishing"],
            klass="phishing",
            shard_index=shard_index,
        )
        legitimate, legitimate_mapping = apply_verified_shard_index(
            legitimate,
            inventory["legitimate"],
            klass="legitimate",
            shard_index=shard_index,
        )
        identity_validation = [phishing_mapping, legitimate_mapping]

        plan = build_temporal_coverage_plan(
            phishing_records=phishing,
            legitimate_records=legitimate,
            inventory=inventory,
            targets=targets,
            existing_shards=args.existing_shard,
            max_cutoff_candidates=args.max_cutoff_candidates,
        )
        plan["metadata_reports"] = {
            "phishing": p_report,
            "legitimate": l_report,
        }
        plan["shard_identity_validation"] = identity_validation
        plan["shard_mapping_method"] = "VERIFIED_REMOTE_ZIP_CENTRAL_DIRECTORY"
        plan["shard_index"] = str(args.shard_index)
    except (TemporalCoveragePlanError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "PASS",
        "output": str(args.output),
        "candidate_target_per_class": plan["targets"]["candidate_metadata_target_per_class"],
        "recommended_cutoff": plan["recommended_strict_forward_cutoff"],
        "selected_shards": len(plan["selected_shards"]),
        "download_shards": len(plan["download_recommendations"]),
        "estimated_additional_download_gb_decimal": plan["estimated_additional_download_gb_decimal"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
