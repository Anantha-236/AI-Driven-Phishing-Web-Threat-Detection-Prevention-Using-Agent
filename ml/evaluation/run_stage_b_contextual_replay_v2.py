from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from ml.data.stage_b_archive_replay import validate_archive_replay_plan
from .stage_b_contextual_replay_v2 import (
    PROTOCOL_ID,
    ScaledReplayError,
    checkpoint_sources_match,
    validate_task28_outputs,
)
from .stage_b_scaled_replay import (
    load_json,
    merge_batch_episodes,
    sha256_file,
    validate_batch_episode_output,
    write_batches,
)

ROOT = Path(__file__).resolve().parents[2]


def run_checked(command: list[str]) -> None:
    print("RUN:", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=ROOT)
    if completed.returncode != 0:
        raise ScaledReplayError(
            f"command failed with exit code {completed.returncode}: "
            f"{' '.join(command)}"
        )


def expected_replay_source_hashes(dist_value: str) -> dict[str, str]:
    dist_root = Path(dist_value)
    if not dist_root.is_absolute():
        dist_root = ROOT / dist_root
    collector = dist_root / "collector.js"
    service_worker = dist_root / "service-worker.js"
    tsfeg = ROOT / "browser-extension" / "src" / "core" / "tsfeg.ts"
    for path in (collector, service_worker, tsfeg):
        if not path.is_file():
            raise ScaledReplayError(
                f"replay source file not found for checkpoint identity: {path}"
            )
    return {
        "collector_js_sha256": sha256_file(collector),
        "service_worker_js_sha256": sha256_file(service_worker),
        "tsfeg_source_sha256": sha256_file(tsfeg),
    }


def atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run resume-safe Chromium replay, feature materialization and "
            "contextual research-v2 readiness."
        )
    )
    parser.add_argument("--protocol-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--dist", default="dist")
    parser.add_argument(
        "--readiness-policy",
        type=Path,
        default=Path(
            "ml/data/manifests/"
            "stage-b-contextual-research-readiness-policy-v2.json"
        ),
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    protocol = args.protocol_root
    work = args.work_root

    raw_path = protocol / "supervised-replay-plan.json"
    normalized_path = protocol / "supervised-replay-plan.normalized.json"
    split_path = protocol / "research-splits.json"
    report_path = protocol / "contextual-v2-report.json"

    try:
        if type(args.batch_size) is not int or args.batch_size < 1:
            raise ScaledReplayError("batch_size must be a positive integer")
        if not args.archive_root.is_dir():
            raise ScaledReplayError(
                f"archive root not found: {args.archive_root}"
            )
        if not args.readiness_policy.is_file():
            raise ScaledReplayError(
                f"contextual-v2 readiness policy not found: "
                f"{args.readiness_policy}"
            )

        raw = load_json(raw_path)
        normalized = load_json(normalized_path)
        splits = load_json(split_path)
        report = load_json(report_path)

        preflight, collector_raw = validate_task28_outputs(
            protocol_root=protocol,
            archive_root=args.archive_root,
            raw_plan=raw,
            normalized_plan=normalized,
            splits=splits,
            report=report,
        )

        summary = {
            **preflight,
            "batch_size": args.batch_size,
            "estimated_batch_count": (
                preflight["samples"] + args.batch_size - 1
            ) // args.batch_size,
            "readiness_policy": str(args.readiness_policy),
        }
        print(json.dumps(summary, indent=2))

        if args.preflight_only:
            return 0

        work.mkdir(parents=True, exist_ok=True)
        atomic_json(work / "preflight.json", summary)

        collector_raw_path = work / "collector-replay-plan.json"
        atomic_json(collector_raw_path, collector_raw)
        collector_normalized = validate_archive_replay_plan(
            collector_raw, args.archive_root
        )
        collector_normalized_path = (
            work / "collector-replay-plan.normalized.json"
        )
        atomic_json(collector_normalized_path, collector_normalized)

        batches_root = work / "batches"
        manifest = write_batches(
            collector_raw,
            batch_size=args.batch_size,
            batches_root=batches_root,
        )
        atomic_json(work / "batch-manifest.json", {
            "status": "PASS",
            "protocol_id": PROTOCOL_ID,
            "research_only": True,
            "deployment_authorized": False,
            "source_plan_sha256": sha256_file(collector_raw_path),
            "batch_size": args.batch_size,
            "batch_count": len(manifest),
            "batches": manifest,
        })

        if not args.skip_build:
            run_checked(["npm.cmd", "run", "build"])

        current_source_hashes = expected_replay_source_hashes(args.dist)

        batch_plans = []
        batch_outputs = []

        for index, row in enumerate(manifest, start=1):
            plan_path = Path(row["plan_path"])
            episode_path = Path(row["episode_path"])
            batch_plan = load_json(plan_path)
            batch_plans.append(batch_plan)

            reuse = False
            if episode_path.is_file():
                try:
                    existing = load_json(episode_path)
                    validate_batch_episode_output(existing, batch_plan)
                    if not checkpoint_sources_match(
                        existing,
                        current_source_hashes,
                    ):
                        raise ScaledReplayError(
                            "checkpoint collector source hashes differ from current build"
                        )
                    batch_outputs.append(existing)
                    reuse = True
                    print(
                        f"[{index}/{len(manifest)}] REUSE {row['batch']} "
                        f"samples={row['sample_count']}",
                        flush=True,
                    )
                except Exception as exc:
                    print(
                        f"[{index}/{len(manifest)}] stale/invalid checkpoint "
                        f"ignored: {exc}",
                        flush=True,
                    )
                    episode_path.unlink(missing_ok=True)

            if reuse:
                continue

            print(
                f"[{index}/{len(manifest)}] REPLAY {row['batch']} "
                f"samples={row['sample_count']}",
                flush=True,
            )
            run_checked([
                "node",
                "scripts/stage-b-collect-archive-replay.mjs",
                "--plan", str(plan_path),
                "--archive-root", str(args.archive_root),
                "--output", str(episode_path),
                "--dist", args.dist,
            ])
            output = load_json(episode_path)
            validate_batch_episode_output(output, batch_plan)
            batch_outputs.append(output)

        merged = merge_batch_episodes(
            batch_outputs,
            batch_plans,
            source_plan_sha256=sha256_file(collector_raw_path),
        )
        merged_path = work / "research-supervised-episodes.json"
        atomic_json(merged_path, merged)

        features_path = work / "research-features.json"
        run_checked([
            sys.executable,
            "-m", "ml.data.materialize_stage_b_features",
            "--splits", str(split_path),
            "--episodes", str(merged_path),
            "--output", str(features_path),
        ])

        readiness_path = work / "research-readiness.json"
        run_checked([
            sys.executable,
            "-m",
            "ml.data.audit_stage_b_contextual_research_readiness_v2",
            str(features_path),
            "--policy", str(args.readiness_policy),
            "--output", str(readiness_path),
        ])

        readiness = load_json(readiness_path)
        if readiness.get("status") != "PASS":
            raise ScaledReplayError(
                "contextual-v2 research readiness status is not PASS"
            )
        if readiness.get("training_allowed") is not True:
            raise ScaledReplayError(
                "contextual-v2 readiness did not authorize research benchmarking"
            )
        if readiness.get("research_protocol") != PROTOCOL_ID:
            raise ScaledReplayError(
                "contextual-v2 readiness protocol identity mismatch"
            )
        if readiness.get("brand_group_role") != (
            "AUDIT_ONLY_NOT_MODEL_OBSERVABLE"
        ):
            raise ScaledReplayError(
                "contextual-v2 brand audit-only guard mismatch"
            )
        if readiness.get("research_only") is not True:
            raise ScaledReplayError("contextual-v2 readiness lost research-only guard")
        if readiness.get("deployment_authorized") is not False:
            raise ScaledReplayError(
                "contextual-v2 readiness unexpectedly authorizes deployment"
            )

        result = {
            "schema_version": "stage-b-contextual-replay-v2-run-1",
            "status": "PASS",
            "protocol_id": PROTOCOL_ID,
            "research_only": True,
            "deployment_authorized": False,
            "training_allowed_for_research_benchmark": True,
            "samples": len(merged["episodes"]),
            "batches": len(manifest),
            "active_isolation_dimensions": [
                "artifact_group", "domain_group"
            ],
            "audit_only_dimensions": ["brand_group"],
            "outputs": {
                "preflight": str(work / "preflight.json"),
                "collector_raw_plan": str(collector_raw_path),
                "collector_normalized_plan": str(
                    collector_normalized_path
                ),
                "batch_manifest": str(work / "batch-manifest.json"),
                "episodes": str(merged_path),
                "features": str(features_path),
                "readiness": str(readiness_path),
            },
        }
        atomic_json(work / "task29-run-report.json", result)
        print(json.dumps(result, indent=2))
        return 0

    except (
        ScaledReplayError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
