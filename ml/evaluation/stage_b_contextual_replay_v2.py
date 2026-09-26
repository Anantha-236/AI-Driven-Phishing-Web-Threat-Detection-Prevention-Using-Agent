"""Stage B Task 29: resume-safe Chromium replay for contextual research protocol v2.

Task 29 intentionally reuses Task 21's proven deterministic batching and merge
logic, but replaces the Task-20/v1 preflight with a protocol-v2 preflight.

Critical consistency rule:
Task 28's normalized supervised plan is authoritative for v2 model metadata.
The browser collector raw plan is reconstructed from that normalized plan
instead of replaying the older Task-20-derived raw plan unchanged. This keeps
exact-host domain_group semantics aligned across collection, splitting,
feature materialization and readiness evidence.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ml.data.stage_b_archive_replay import validate_archive_replay_plan
from .stage_b_scaled_replay import (
    NORMALIZED_PLAN_SCHEMA,
    RAW_PLAN_SCHEMA,
    REPLAY_PROVENANCE,
    ScaledReplayError,
    canonical_hash,
    load_json,
    sha256_file,
)

PROTOCOL_ID = "single-source-contextual-archive-replay-research-v2"
TASK28_REPORT_SCHEMA = "stage-b-contextual-research-v2-report-1"
TASK29_PREFLIGHT_SCHEMA = "stage-b-contextual-replay-v2-preflight-1"


def _rows_by_id(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise ScaledReplayError(f"{label} requires non-empty items")
    result: dict[str, dict[str, Any]] = {}
    for raw in items:
        if not isinstance(raw, Mapping):
            raise ScaledReplayError(f"{label} item must be an object")
        sample_id = raw.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise ScaledReplayError(f"{label} item sample_id is required")
        if sample_id in result:
            raise ScaledReplayError(f"duplicate sample_id in {label}: {sample_id}")
        result[sample_id] = dict(raw)
    return result


def build_collector_plan_from_v2_normalized(
    normalized_plan: Mapping[str, Any],
) -> dict[str, Any]:
    if normalized_plan.get("schema_version") != NORMALIZED_PLAN_SCHEMA:
        raise ScaledReplayError("unsupported Task 28 normalized replay-plan schema")
    if normalized_plan.get("collection_provenance") != REPLAY_PROVENANCE:
        raise ScaledReplayError("Task 28 normalized replay provenance mismatch")

    dataset = normalized_plan.get("dataset")
    if not isinstance(dataset, Mapping):
        raise ScaledReplayError("Task 28 normalized plan dataset missing")
    items = normalized_plan.get("items")
    rows = _rows_by_id(items, "Task 28 normalized plan")

    collector_items = []
    for sample_id in sorted(rows):
        row = rows[sample_id]
        collector_items.append({
            "sample_id": sample_id,
            "html_path": row["html_path"],
            "ground_truth": row["ground_truth"],
            "observed_at": row["observed_at"],
            "artifact_sha256": row["artifact_sha256"],
            "domain_group": row["domain_group"],
            "brand_group": row.get("brand_group"),
            "source_group": row["source_group"],
            "wait_ms": row["wait_ms"],
        })

    return {
        "schema_version": RAW_PLAN_SCHEMA,
        "plan_id": str(normalized_plan["plan_id"]) + "-collector",
        "created_at": normalized_plan["created_at"],
        "dataset": {
            "dataset_id": dataset["dataset_id"],
            "provider": dataset["provider"],
            "source_reference": dataset["source_reference"],
            "source_snapshot_sha256": dataset["source_snapshot_sha256"],
            "independence_group": dataset["independence_group"],
            "license_reference": dataset["license_reference"],
            "research_use_allowed": True,
        },
        "items": collector_items,
    }


def _split_rows(splits: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    partitions = splits.get("partitions")
    if not isinstance(partitions, Mapping):
        raise ScaledReplayError("Task 28 research splits missing partitions")
    seen: dict[str, dict[str, Any]] = {}
    for name in ("train", "selection", "calibration", "test"):
        payload = partitions.get(name)
        rows = payload.get("records") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list) or not rows:
            raise ScaledReplayError(f"Task 28 split {name} is empty")
        for raw in rows:
            if not isinstance(raw, Mapping):
                raise ScaledReplayError(f"invalid Task 28 split row in {name}")
            sample_id = raw.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise ScaledReplayError("Task 28 split row sample_id is required")
            if sample_id in seen:
                raise ScaledReplayError(
                    f"sample appears in multiple Task 28 partitions: {sample_id}"
                )
            row = dict(raw)
            row["_partition"] = name
            seen[sample_id] = row
    return seen


def validate_task28_outputs(
    *,
    protocol_root: Path,
    archive_root: Path,
    raw_plan: Mapping[str, Any],
    normalized_plan: Mapping[str, Any],
    splits: Mapping[str, Any],
    report: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if report.get("schema_version") != TASK28_REPORT_SCHEMA:
        raise ScaledReplayError("unsupported Task 28 contextual-v2 report schema")
    if report.get("status") != "PASS":
        raise ScaledReplayError(
            f"Task 28 is not replay-ready: status={report.get('status')!r}"
        )
    if report.get("protocol_id") != PROTOCOL_ID:
        raise ScaledReplayError("Task 28 protocol_id mismatch")
    if report.get("research_only") is not True:
        raise ScaledReplayError("Task 28 lost research-only guard")
    if report.get("deployment_authorized") is not False:
        raise ScaledReplayError("Task 28 unexpectedly authorizes deployment")
    if report.get("active_isolation_dimensions") != [
        "artifact_group", "domain_group"
    ]:
        raise ScaledReplayError("Task 28 active isolation dimensions mismatch")
    if report.get("audit_only_dimensions") != ["brand_group"]:
        raise ScaledReplayError("Task 28 brand audit-only declaration mismatch")

    if raw_plan.get("schema_version") != RAW_PLAN_SCHEMA:
        raise ScaledReplayError("Task 28 supervised raw plan schema mismatch")
    if normalized_plan.get("schema_version") != NORMALIZED_PLAN_SCHEMA:
        raise ScaledReplayError("Task 28 supervised normalized plan schema mismatch")
    if normalized_plan.get("collection_provenance") != REPLAY_PROVENANCE:
        raise ScaledReplayError("Task 28 normalized plan provenance mismatch")

    raw_rows = _rows_by_id(raw_plan.get("items"), "Task 28 raw plan")
    normalized_rows = _rows_by_id(
        normalized_plan.get("items"), "Task 28 normalized plan"
    )
    split_rows = _split_rows(splits)

    if set(raw_rows) != set(normalized_rows):
        raise ScaledReplayError(
            "Task 28 raw/normalized supervised sample sets differ"
        )
    if set(normalized_rows) != set(split_rows):
        raise ScaledReplayError(
            "Task 28 supervised normalized plan does not exactly match splits"
        )
    if report.get("supervised_samples") != len(normalized_rows):
        raise ScaledReplayError("Task 28 supervised sample count mismatch")

    audit = splits.get("audit")
    if not isinstance(audit, Mapping):
        raise ScaledReplayError("Task 28 research split audit missing")
    if audit.get("protocol_id") != PROTOCOL_ID:
        raise ScaledReplayError("Task 28 split protocol_id mismatch")
    if audit.get("research_only") is not True:
        raise ScaledReplayError("Task 28 split lost research-only guard")
    if audit.get("deployment_authorized") is not False:
        raise ScaledReplayError("Task 28 split unexpectedly authorizes deployment")
    if audit.get("strict_forward_test") is not True:
        raise ScaledReplayError("Task 28 split lost strict-forward final-test guard")
    if audit.get("isolation_dimensions") != ["artifact_group", "domain_group"]:
        raise ScaledReplayError("Task 28 split isolation dimensions mismatch")
    if audit.get("audit_only_dimensions") != ["brand_group"]:
        raise ScaledReplayError("Task 28 split brand audit-only declaration mismatch")

    # The v2 normalized plan is authoritative for split metadata. The raw plan
    # may retain Task-20/v1 domain grouping and therefore is deliberately not
    # used as the collector authority.
    for sample_id, split_row in split_rows.items():
        normalized = normalized_rows[sample_id]
        checks = {
            "ground_truth": "ground_truth",
            "artifact_group": "artifact_sha256",
            "domain_group": "domain_group",
            "brand_group": "brand_group",
            "observed_at": "observed_at",
        }
        for split_field, plan_field in checks.items():
            if split_row.get(split_field) != normalized.get(plan_field):
                raise ScaledReplayError(
                    f"Task 28 split/normalized metadata mismatch for "
                    f"{sample_id}: {split_field}"
                )

    collector_raw = build_collector_plan_from_v2_normalized(normalized_plan)
    try:
        collector_normalized = validate_archive_replay_plan(
            collector_raw, archive_root
        )
    except Exception as exc:
        raise ScaledReplayError(
            f"Task 29 collector-plan/archive validation failed: {exc}"
        ) from exc

    collector_rows = _rows_by_id(
        collector_normalized.get("items"), "Task 29 collector normalized plan"
    )
    for sample_id, expected in normalized_rows.items():
        actual = collector_rows.get(sample_id)
        if actual is None:
            raise ScaledReplayError(
                f"Task 29 collector validation lost sample: {sample_id}"
            )
        for field in (
            "html_path", "ground_truth", "observed_at", "artifact_sha256",
            "domain_group", "brand_group", "source_group", "wait_ms",
        ):
            if actual.get(field) != expected.get(field):
                raise ScaledReplayError(
                    f"Task 29 collector normalized metadata drift for "
                    f"{sample_id}: {field}"
                )

    preflight = {
        "schema_version": TASK29_PREFLIGHT_SCHEMA,
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "protocol_id": PROTOCOL_ID,
        "samples": len(normalized_rows),
        "active_isolation_dimensions": ["artifact_group", "domain_group"],
        "audit_only_dimensions": ["brand_group"],
        "archive_root": str(archive_root),
        "task28_report_sha256": sha256_file(
            protocol_root / "contextual-v2-report.json"
        ),
        "raw_plan_sha256": sha256_file(
            protocol_root / "supervised-replay-plan.json"
        ),
        "normalized_plan_sha256": sha256_file(
            protocol_root / "supervised-replay-plan.normalized.json"
        ),
        "splits_sha256": sha256_file(protocol_root / "research-splits.json"),
        "collector_plan_sha256": canonical_hash(collector_raw),
        "collector_normalized_sha256": canonical_hash(collector_normalized),
    }
    return preflight, collector_raw


def checkpoint_sources_match(
    episode_data: Mapping[str, Any],
    expected_hashes: Mapping[str, str],
) -> bool:
    actual = episode_data.get("source_hashes")
    return isinstance(actual, Mapping) and dict(actual) == dict(expected_hashes)
