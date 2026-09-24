"""Fail-closed acquisition-plan validation for Stage B browser event episodes.

The plan file is local-only input. It may contain target URLs, but the collector
output must never persist those URLs. Controlled mode is loopback-only. Live mode
is passive and must be explicitly enabled by the caller.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping
from urllib.parse import urlsplit

from .stage_b_splitting import SPLIT_SCHEMA

ACQUISITION_PLAN_SCHEMA = "stage-b-acquisition-plan-1"
ALLOWED_MODES = {"CONTROLLED_LOCAL", "LIVE_PASSIVE"}
ALLOWED_PROVENANCE = {"CONTROLLED_BROWSER", "REAL_BROWSER"}
PLAN_FIELDS = {"schema_version", "plan_id", "created_at", "items"}
ITEM_FIELDS = {"sample_id", "mode", "target_url", "collection_provenance", "wait_ms"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MIN_WAIT_MS = 250
MAX_WAIT_MS = 10_000


class AcquisitionPlanError(ValueError):
    """Raised when a Stage B acquisition plan violates the safety/data contract."""


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AcquisitionPlanError("created_at is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AcquisitionPlanError("created_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AcquisitionPlanError("created_at must include a timezone")
    return parsed


def _supervised_ids(split_data: Mapping[str, Any]) -> set[str]:
    if split_data.get("schema_version") != SPLIT_SCHEMA:
        raise AcquisitionPlanError("unsupported Stage B split schema")
    partitions = split_data.get("partitions")
    if not isinstance(partitions, Mapping) or set(partitions) != {"train", "selection", "calibration", "test"}:
        raise AcquisitionPlanError("all four locked partitions are required")
    result: set[str] = set()
    for partition, payload in partitions.items():
        records = payload.get("records") if isinstance(payload, Mapping) else None
        if not isinstance(records, list) or not records:
            raise AcquisitionPlanError(f"partition {partition} has no supervised records")
        for raw in records:
            if not isinstance(raw, Mapping):
                raise AcquisitionPlanError("split record must be an object")
            sample_id = raw.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise AcquisitionPlanError("split record sample_id is required")
            if sample_id in result:
                raise AcquisitionPlanError("sample appears in more than one locked partition")
            result.add(sample_id)
    return result


def _validate_target(item: Mapping[str, Any], *, allow_live_passive: bool) -> dict[str, Any]:
    unexpected = set(item) - ITEM_FIELDS
    if unexpected:
        raise AcquisitionPlanError(
            f"unexpected acquisition item fields: {', '.join(sorted(unexpected))}"
        )
    sample_id = item.get("sample_id")
    if not isinstance(sample_id, str) or not sample_id.strip():
        raise AcquisitionPlanError("acquisition sample_id is required")
    mode = item.get("mode")
    if mode not in ALLOWED_MODES:
        raise AcquisitionPlanError("unsupported acquisition mode")
    target_url = item.get("target_url")
    if not isinstance(target_url, str) or not target_url:
        raise AcquisitionPlanError("target_url is required")
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AcquisitionPlanError("target_url must be HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise AcquisitionPlanError("target_url cannot contain credentials")
    if parsed.fragment:
        raise AcquisitionPlanError("target_url fragments are not allowed")

    provenance = item.get("collection_provenance")
    if provenance not in ALLOWED_PROVENANCE:
        raise AcquisitionPlanError("explicit collection_provenance is required")

    host = parsed.hostname.lower()
    if mode == "CONTROLLED_LOCAL":
        if host not in LOOPBACK_HOSTS:
            raise AcquisitionPlanError("CONTROLLED_LOCAL targets must use a loopback host")
        if provenance != "CONTROLLED_BROWSER":
            raise AcquisitionPlanError("CONTROLLED_LOCAL requires CONTROLLED_BROWSER provenance")
    else:
        if not allow_live_passive:
            raise AcquisitionPlanError("LIVE_PASSIVE requires allow_live_passive=True")
        if provenance != "REAL_BROWSER":
            raise AcquisitionPlanError("LIVE_PASSIVE requires REAL_BROWSER provenance")

    wait_ms = item.get("wait_ms")
    if type(wait_ms) is not int or not (MIN_WAIT_MS <= wait_ms <= MAX_WAIT_MS):
        raise AcquisitionPlanError(
            f"wait_ms must be an integer between {MIN_WAIT_MS} and {MAX_WAIT_MS}"
        )

    return {
        "sample_id": sample_id.strip(),
        "mode": mode,
        "target_url": target_url,
        "collection_provenance": provenance,
        "wait_ms": wait_ms,
    }


def validate_acquisition_plan(
    plan: Mapping[str, Any],
    split_data: Mapping[str, Any],
    *,
    allow_live_passive: bool = False,
) -> dict[str, Any]:
    if not isinstance(plan, Mapping):
        raise AcquisitionPlanError("acquisition plan must be an object")
    unexpected = set(plan) - PLAN_FIELDS
    if unexpected:
        raise AcquisitionPlanError(
            f"unexpected acquisition plan fields: {', '.join(sorted(unexpected))}"
        )
    if plan.get("schema_version") != ACQUISITION_PLAN_SCHEMA:
        raise AcquisitionPlanError("unsupported acquisition plan schema")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or not plan_id.strip():
        raise AcquisitionPlanError("plan_id is required")
    _parse_time(plan.get("created_at"))
    items = plan.get("items")
    if not isinstance(items, list) or not items:
        raise AcquisitionPlanError("acquisition plan must contain items")

    locked_ids = _supervised_ids(split_data)
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in items:
        if not isinstance(raw, Mapping):
            raise AcquisitionPlanError("acquisition item must be an object")
        item = _validate_target(raw, allow_live_passive=allow_live_passive)
        sample_id = item["sample_id"]
        if sample_id in seen:
            raise AcquisitionPlanError(f"duplicate sample_id in acquisition plan: {sample_id}")
        if sample_id not in locked_ids:
            raise AcquisitionPlanError(f"sample {sample_id} is not present in locked splits")
        seen.add(sample_id)
        normalized.append(item)

    return {
        "schema_version": ACQUISITION_PLAN_SCHEMA,
        "plan_id": plan_id.strip(),
        "created_at": plan["created_at"],
        "items": deepcopy(normalized),
    }
