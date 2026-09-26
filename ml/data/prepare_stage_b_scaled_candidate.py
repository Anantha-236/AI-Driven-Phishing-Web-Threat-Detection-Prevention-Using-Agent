from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_scaled_assembly import (
    ScaledAssemblyError,
    _load,
    assemble_scaled_candidate,
    input_preflight,
    validate_inputs,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage B Task 20: extract Task-19-selected shards and assemble a scaled research candidate."
    )
    parser.add_argument("--coverage-plan", type=Path, required=True)
    parser.add_argument("--shard-index", type=Path, required=True)
    parser.add_argument("--phishing-csv", type=Path, required=True)
    parser.add_argument("--legitimate-csv", type=Path, required=True)
    parser.add_argument("--brands-csv", type=Path)
    parser.add_argument("--download-root", type=Path, action="append", required=True)
    parser.add_argument("--extraction-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--split-contract",
        type=Path,
        default=Path("ml/data/manifests/stage-b-research-archive-split-contract.json"),
    )
    parser.add_argument(
        "--readiness-policy",
        type=Path,
        default=Path("ml/data/manifests/stage-b-research-replay-readiness-policy.json"),
    )
    parser.add_argument("--wait-ms", type=int, default=600)
    parser.add_argument("--license-reference", required=True)
    parser.add_argument("--acknowledge-research-use", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    try:
        coverage = _load(args.coverage_plan)
        shard_index = _load(args.shard_index)
        selected, _ = validate_inputs(coverage, shard_index)
        preflight = input_preflight(selected, args.download_root)

        if args.preflight_only:
            print(json.dumps(preflight, indent=2))
            return 0 if preflight["status"] == "PASS" else 3

        if not args.acknowledge_research_use:
            parser.error("--acknowledge-research-use is required before extraction/assembly")
        if preflight["status"] != "PASS":
            print(json.dumps(preflight, indent=2))
            return 3

        report = assemble_scaled_candidate(
            coverage_plan_path=args.coverage_plan,
            shard_index_path=args.shard_index,
            phishing_csv=args.phishing_csv,
            legitimate_csv=args.legitimate_csv,
            brands_csv=args.brands_csv,
            download_roots=args.download_root,
            extraction_root=args.extraction_root,
            output_root=args.output_root,
            split_contract_path=args.split_contract,
            readiness_policy_path=args.readiness_policy,
            wait_ms=args.wait_ms,
            license_reference=args.license_reference,
        )
    except (ScaledAssemblyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": report["status"],
        "candidate_samples": report["candidate_samples"],
        "selected_shards": report["selected_shards"],
        "partitions": report["split_partitions"],
        "duplicate_artifact_quarantine": report["duplicate_artifact_quarantine"]["samples"],
        "chronology_bridge_quarantine_samples": report["chronology_bridge_quarantine_samples"],
        "count_readiness": report["split_count_readiness"]["status"],
        "outputs": report["outputs"],
    }, indent=2))
    return 0 if report["status"] == "PASS" else 4


if __name__ == "__main__":
    raise SystemExit(main())
