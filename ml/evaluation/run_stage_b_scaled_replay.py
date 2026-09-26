from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from .stage_b_scaled_replay import (
    ScaledReplayError,
    load_json,
    merge_batch_episodes,
    sha256_file,
    validate_batch_episode_output,
    validate_task20_outputs,
    write_batches,
)

ROOT = Path(__file__).resolve().parents[2]


def run_checked(command: list[str]) -> None:
    print("RUN:", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=ROOT)
    if completed.returncode != 0:
        raise ScaledReplayError(
            f"command failed with exit code {completed.returncode}: {' '.join(command)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run resume-safe Task 20 supervised archive replay, feature materialization and research readiness."
    )
    parser.add_argument("--task20-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--dist", default="dist")
    parser.add_argument(
        "--readiness-policy",
        type=Path,
        default=Path("ml/data/manifests/stage-b-research-replay-readiness-policy.json"),
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    task20 = args.task20_root
    work = args.work_root
    raw_path = task20 / "supervised-replay-plan.json"
    normalized_path = task20 / "supervised-replay-plan.normalized.json"
    split_path = task20 / "research-splits.json"
    archive_root = task20 / "supervised-archive"

    try:
        raw = load_json(raw_path)
        normalized = load_json(normalized_path)
        splits = load_json(split_path)
        preflight = validate_task20_outputs(
            task20_root=task20,
            raw_plan=raw,
            normalized_plan=normalized,
            splits=splits,
        )
        if not archive_root.is_dir():
            raise ScaledReplayError(f"Task 20 supervised archive not found: {archive_root}")
        if not args.readiness_policy.is_file():
            raise ScaledReplayError(f"research readiness policy not found: {args.readiness_policy}")

        print(json.dumps({
            **preflight,
            "archive_root": str(archive_root),
            "batch_size": args.batch_size,
        }, indent=2))
        if args.preflight_only:
            return 0

        work.mkdir(parents=True, exist_ok=True)
        batches_root = work / "batches"
        manifest = write_batches(raw, batch_size=args.batch_size, batches_root=batches_root)
        (work / "batch-manifest.json").write_text(
            json.dumps({
                "status": "PASS",
                "source_plan_sha256": sha256_file(raw_path),
                "batch_size": args.batch_size,
                "batch_count": len(manifest),
                "batches": manifest,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        if not args.skip_build:
            run_checked(["npm.cmd", "run", "build"])

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
                    batch_outputs.append(existing)
                    reuse = True
                    print(
                        f"[{index}/{len(manifest)}] REUSE {row['batch']} "
                        f"samples={row['sample_count']}",
                        flush=True,
                    )
                except Exception as exc:
                    print(
                        f"[{index}/{len(manifest)}] stale/invalid checkpoint ignored: {exc}",
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
                "--archive-root", str(archive_root),
                "--output", str(episode_path),
                "--dist", args.dist,
            ])
            output = load_json(episode_path)
            validate_batch_episode_output(output, batch_plan)
            batch_outputs.append(output)

        merged = merge_batch_episodes(
            batch_outputs,
            batch_plans,
            source_plan_sha256=sha256_file(raw_path),
        )
        merged_path = work / "research-supervised-episodes.json"
        merged_path.write_text(
            json.dumps(merged, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

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
            "-m", "ml.data.audit_stage_b_research_readiness",
            str(features_path),
            "--policy", str(args.readiness_policy),
            "--output", str(readiness_path),
        ])
        readiness = load_json(readiness_path)
        if readiness.get("training_allowed") is not True:
            raise ScaledReplayError("research readiness audit did not authorize benchmarking")
        if readiness.get("research_only") is not True or readiness.get("deployment_authorized") is not False:
            raise ScaledReplayError("research readiness deployment guard mismatch")

        result = {
            "status": "PASS",
            "research_only": True,
            "deployment_authorized": False,
            "training_allowed_for_research_benchmark": True,
            "samples": len(merged["episodes"]),
            "batches": len(manifest),
            "outputs": {
                "batch_manifest": str(work / "batch-manifest.json"),
                "episodes": str(merged_path),
                "features": str(features_path),
                "readiness": str(readiness_path),
            },
        }
        (work / "task21-run-report.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(result, indent=2))
        return 0
    except (ScaledReplayError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
