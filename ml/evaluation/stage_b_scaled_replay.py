"""Stage B Task 21: resume-safe research replay orchestration.

This module prepares deterministic batches from the Task-20 supervised replay
plan, validates/reuses completed batch episode files, merges them exactly once,
and provides fail-closed preflight checks before any browser work.

It deliberately reuses the existing safe archive replay collector and existing
feature/readiness CLIs rather than creating a second event collector.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

RAW_PLAN_SCHEMA = "stage-b-archive-replay-plan-1"
NORMALIZED_PLAN_SCHEMA = "stage-b-archive-replay-normalized-1"
EPISODE_SCHEMA = "stage-b-event-episodes-1"
REPLAY_PROVENANCE = "ARCHIVED_BROWSER_REPLAY"
PIPELINE_SCHEMA = "stage-b-scaled-replay-run-1"


class ScaledReplayError(RuntimeError):
    pass


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ScaledReplayError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScaledReplayError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ScaledReplayError(f"JSON root must be an object: {path}")
    return value


def validate_task20_outputs(
    *,
    task20_root: Path,
    raw_plan: Mapping[str, Any],
    normalized_plan: Mapping[str, Any],
    splits: Mapping[str, Any],
) -> dict[str, Any]:
    report = load_json(task20_root / "scaled-assembly-report.json")
    if report.get("schema_version") != "stage-b-scaled-candidate-assembly-1":
        raise ScaledReplayError("unsupported Task 20 assembly report schema")
    if report.get("status") != "PASS":
        raise ScaledReplayError(
            f"Task 20 is not replay-ready: status={report.get('status')!r}"
        )
    if report.get("research_only") is not True or report.get("deployment_authorized") is not False:
        raise ScaledReplayError("Task 20 report lost research-only/deployment guard")
    readiness = report.get("split_count_readiness")
    if not isinstance(readiness, Mapping) or readiness.get("status") != "PASS":
        raise ScaledReplayError("Task 20 split-count readiness is not PASS")

    if raw_plan.get("schema_version") != RAW_PLAN_SCHEMA:
        raise ScaledReplayError("Task 20 supervised raw plan schema mismatch")
    if normalized_plan.get("schema_version") != NORMALIZED_PLAN_SCHEMA:
        raise ScaledReplayError("Task 20 supervised normalized plan schema mismatch")
    if normalized_plan.get("collection_provenance") != REPLAY_PROVENANCE:
        raise ScaledReplayError("Task 20 normalized plan provenance mismatch")
    if raw_plan.get("plan_id") != normalized_plan.get("plan_id"):
        raise ScaledReplayError("Task 20 raw/normalized plan_id mismatch")

    raw_items = raw_plan.get("items")
    normalized_items = normalized_plan.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ScaledReplayError("Task 20 supervised raw plan has no items")
    if not isinstance(normalized_items, list) or not normalized_items:
        raise ScaledReplayError("Task 20 supervised normalized plan has no items")
    raw_ids = [row.get("sample_id") for row in raw_items if isinstance(row, Mapping)]
    normalized_ids = [row.get("sample_id") for row in normalized_items if isinstance(row, Mapping)]
    if len(raw_ids) != len(raw_items) or len(normalized_ids) != len(normalized_items):
        raise ScaledReplayError("invalid supervised plan item")
    if len(set(raw_ids)) != len(raw_ids) or len(set(normalized_ids)) != len(normalized_ids):
        raise ScaledReplayError("duplicate sample_id in supervised plan")
    if set(raw_ids) != set(normalized_ids):
        raise ScaledReplayError("Task 20 raw/normalized supervised sample sets differ")

    partitions = splits.get("partitions")
    if not isinstance(partitions, Mapping):
        raise ScaledReplayError("Task 20 research splits missing partitions")
    split_ids = []
    for name in ("train", "selection", "calibration", "test"):
        payload = partitions.get(name)
        rows = payload.get("records") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list) or not rows:
            raise ScaledReplayError(f"Task 20 split {name} is empty")
        split_ids.extend(
            row.get("sample_id") for row in rows if isinstance(row, Mapping)
        )
    if len(split_ids) != len(set(split_ids)):
        raise ScaledReplayError("Task 20 sample appears in multiple split partitions")
    if set(split_ids) != set(raw_ids):
        raise ScaledReplayError("Task 20 supervised plan does not exactly match research splits")

    supervised = report.get("supervised")
    if not isinstance(supervised, Mapping):
        raise ScaledReplayError("Task 20 report missing supervised-copy record")
    if supervised.get("supervised_samples") != len(raw_ids):
        raise ScaledReplayError("Task 20 supervised sample count mismatch")

    return {
        "status": "PASS",
        "samples": len(raw_ids),
        "plan_id": raw_plan["plan_id"],
        "task20_report_sha256": sha256_file(task20_root / "scaled-assembly-report.json"),
        "raw_plan_sha256": sha256_file(task20_root / "supervised-replay-plan.json"),
        "normalized_plan_sha256": sha256_file(task20_root / "supervised-replay-plan.normalized.json"),
        "splits_sha256": sha256_file(task20_root / "research-splits.json"),
    }


def batch_raw_plan(
    raw_plan: Mapping[str, Any],
    *,
    batch_size: int,
) -> list[dict[str, Any]]:
    if raw_plan.get("schema_version") != RAW_PLAN_SCHEMA:
        raise ScaledReplayError("unsupported raw replay-plan schema")
    if type(batch_size) is not int or batch_size < 1:
        raise ScaledReplayError("batch_size must be a positive integer")
    raw_items = raw_plan.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ScaledReplayError("raw replay plan has no items")

    items = sorted(
        (deepcopy(dict(row)) for row in raw_items if isinstance(row, Mapping)),
        key=lambda row: str(row.get("sample_id", "")),
    )
    if len(items) != len(raw_items) or any(not row.get("sample_id") for row in items):
        raise ScaledReplayError("invalid raw replay-plan item")
    if len({row["sample_id"] for row in items}) != len(items):
        raise ScaledReplayError("duplicate sample_id in raw replay plan")

    batches = []
    total = (len(items) + batch_size - 1) // batch_size
    width = max(4, len(str(total)))
    for ordinal, start in enumerate(range(0, len(items), batch_size), start=1):
        subset = items[start:start + batch_size]
        batch = {
            "schema_version": RAW_PLAN_SCHEMA,
            "plan_id": f"{raw_plan['plan_id']}-batch-{ordinal:0{width}d}-of-{total:0{width}d}",
            "created_at": raw_plan["created_at"],
            "dataset": deepcopy(raw_plan["dataset"]),
            "items": subset,
        }
        batches.append(batch)
    return batches


def expected_batch_identity(batch_plan: Mapping[str, Any]) -> dict[str, Any]:
    ids = [row["sample_id"] for row in batch_plan["items"]]
    return {
        "plan_sha256": canonical_hash(batch_plan),
        "sample_ids_sha256": canonical_hash(sorted(ids)),
        "sample_count": len(ids),
    }


def validate_batch_episode_output(
    episode_data: Mapping[str, Any],
    batch_plan: Mapping[str, Any],
) -> dict[str, Any]:
    if episode_data.get("schema_version") != EPISODE_SCHEMA:
        raise ScaledReplayError("unsupported batch episode schema")
    failures = episode_data.get("failures")
    if failures != []:
        raise ScaledReplayError("batch contains replay failures")
    episodes = episode_data.get("episodes")
    if not isinstance(episodes, list):
        raise ScaledReplayError("batch episodes must be a list")

    expected = {row["sample_id"] for row in batch_plan["items"]}
    seen = set()
    for row in episodes:
        if not isinstance(row, Mapping):
            raise ScaledReplayError("invalid batch episode row")
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen:
            raise ScaledReplayError("batch episode sample_id missing or duplicated")
        seen.add(sample_id)
        if row.get("collection_provenance") != REPLAY_PROVENANCE:
            raise ScaledReplayError("batch episode provenance mismatch")
        if row.get("dropped_events") != 0:
            raise ScaledReplayError(f"batch episode dropped events: {sample_id}")
        if type(row.get("delivery_errors")) is not int or row["delivery_errors"] < 0:
            raise ScaledReplayError("invalid delivery_errors")
        events = row.get("events")
        if not isinstance(events, list) or not events:
            raise ScaledReplayError(f"batch episode has no sanitized events: {sample_id}")
        events_hash = row.get("events_sha256")
        if not isinstance(events_hash, str) or len(events_hash) != 64:
            raise ScaledReplayError("invalid events_sha256")
        if canonical_hash(events) != events_hash:
            raise ScaledReplayError(f"batch event hash mismatch: {sample_id}")

    if seen != expected:
        raise ScaledReplayError(
            f"batch sample set mismatch: expected={len(expected)}, observed={len(seen)}"
        )
    return {
        "status": "PASS",
        "samples": len(seen),
        **expected_batch_identity(batch_plan),
    }


def merge_batch_episodes(
    batch_outputs: Sequence[Mapping[str, Any]],
    batch_plans: Sequence[Mapping[str, Any]],
    *,
    source_plan_sha256: str,
) -> dict[str, Any]:
    if len(batch_outputs) != len(batch_plans) or not batch_outputs:
        raise ScaledReplayError("batch output/plan count mismatch")

    merged = []
    source_hashes = None
    safety_policy = None
    collector_versions = set()
    seen = set()
    for output, plan in zip(batch_outputs, batch_plans, strict=True):
        validate_batch_episode_output(output, plan)
        collector = output.get("collector_version")
        if not isinstance(collector, str) or not collector:
            raise ScaledReplayError("batch collector_version missing")
        collector_versions.add(collector)

        current_hashes = output.get("source_hashes")
        current_policy = output.get("safety_policy")
        if not isinstance(current_hashes, Mapping) or not isinstance(current_policy, Mapping):
            raise ScaledReplayError("batch source_hashes/safety_policy missing")
        if source_hashes is None:
            source_hashes = dict(current_hashes)
            safety_policy = dict(current_policy)
        elif dict(current_hashes) != source_hashes or dict(current_policy) != safety_policy:
            raise ScaledReplayError("collector source hashes/safety policy changed between batches")

        for row in output["episodes"]:
            sample_id = row["sample_id"]
            if sample_id in seen:
                raise ScaledReplayError(f"sample appears in multiple replay batches: {sample_id}")
            seen.add(sample_id)
            merged.append(deepcopy(dict(row)))

    if len(collector_versions) != 1:
        raise ScaledReplayError("collector version changed between batches")
    expected_all = {
        row["sample_id"]
        for plan in batch_plans
        for row in plan["items"]
    }
    if seen != expected_all:
        raise ScaledReplayError("merged replay sample set is incomplete")

    merged.sort(key=lambda row: row["sample_id"])
    return {
        "schema_version": EPISODE_SCHEMA,
        "collector_version": next(iter(collector_versions)),
        "plan_sha256": source_plan_sha256,
        "collection_mode": "DETERMINISTIC_BATCH_MERGE",
        "source_hashes": source_hashes,
        "safety_policy": safety_policy,
        "episodes": merged,
        "failures": [],
    }


def write_batches(
    raw_plan: Mapping[str, Any],
    *,
    batch_size: int,
    batches_root: Path,
) -> list[dict[str, Any]]:
    plans = batch_raw_plan(raw_plan, batch_size=batch_size)
    batches_root.mkdir(parents=True, exist_ok=True)
    manifest_rows = []
    for index, batch in enumerate(plans, start=1):
        name = f"batch-{index:04d}"
        plan_path = batches_root / f"{name}.plan.json"
        episode_path = batches_root / f"{name}.episodes.json"
        plan_path.write_text(
            json.dumps(batch, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        identity = expected_batch_identity(batch)
        manifest_rows.append({
            "batch": name,
            "plan_path": str(plan_path),
            "episode_path": str(episode_path),
            **identity,
        })
    return manifest_rows
