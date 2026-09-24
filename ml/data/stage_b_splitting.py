"""Leakage-resistant four-way partition construction for Stage B.

This layer consumes reconciled, privacy-safe URL metadata. It never fabricates
independence: artifact, domain, brand and source relationships are collapsed into
indivisible connected components before any partition is assigned.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from typing import Any, Iterable, Mapping

from .stage_b_manifest import validate_split_contract
from .stage_b_reconciliation import RECONCILED_SCHEMA


SPLIT_SCHEMA = "stage-b-splits-1"
DEFAULT_FRACTIONS = {
    "train": 0.60,
    "selection": 0.15,
    "calibration": 0.15,
    "test": 0.10,
}


class SplitConstructionError(ValueError):
    """Raised when honest Stage B partitions cannot be constructed."""


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise SplitConstructionError(f"labeled records require {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SplitConstructionError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SplitConstructionError(f"{field} must include a timezone")
    return parsed


class _UnionFind:
    def __init__(self, count: int) -> None:
        self.parent = list(range(count))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _required_group_value(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SplitConstructionError(f"labeled records require {field}")
    return value.strip()


def _validate_reconciled(data: Mapping[str, Any], contract: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    if data.get("schema_version") != RECONCILED_SCHEMA:
        raise SplitConstructionError("unsupported reconciled dataset schema")
    raw_records = data.get("records")
    if not isinstance(raw_records, list):
        raise SplitConstructionError("reconciled records must be a list")

    required = set(contract["group_isolation"])
    supported = {"artifact_sha256", "domain_group", "brand_group", "source_group"}
    if not required <= supported:
        raise SplitConstructionError("split contract contains unsupported isolation dimensions")

    labeled: list[dict[str, Any]] = []
    excluded_unlabeled: list[str] = []
    chronology_field = contract["chronology"]["field"]

    seen_samples: set[str] = set()
    for raw in raw_records:
        if not isinstance(raw, Mapping):
            raise SplitConstructionError("reconciled record must be an object")
        sample_id = raw.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen_samples:
            raise SplitConstructionError("sample_id must be unique and non-empty")
        seen_samples.add(sample_id)

        label = raw.get("ground_truth")
        status = raw.get("label_status")
        if label not in (0, 1) or status != "VERIFIED_SOURCE_LABEL":
            if label is None and status == "UNLABELED_CANDIDATE":
                excluded_unlabeled.append(sample_id)
                continue
            raise SplitConstructionError("split input contains a non-verified label")

        row = dict(raw)
        row["_observed_dt"] = _parse_time(row.get(chronology_field), chronology_field)

        if "artifact_sha256" in required:
            _required_group_value(row, "artifact_group")
        if "domain_group" in required:
            _required_group_value(row, "domain_group")
        if "brand_group" in required:
            _required_group_value(row, "brand_group")
        if "source_group" in required:
            groups = row.get("source_groups")
            if not isinstance(groups, list) or not groups or any(not isinstance(v, str) or not v.strip() for v in groups):
                raise SplitConstructionError("labeled records require source_group lineage")

        labeled.append(row)

    if not labeled:
        raise SplitConstructionError("no verified labeled records are available for splitting")
    if {row["ground_truth"] for row in labeled} != {0, 1}:
        raise SplitConstructionError("both verified classes are required")
    return labeled, sorted(excluded_unlabeled)


def _componentize(rows: list[dict[str, Any]], contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    uf = _UnionFind(len(rows))
    required = set(contract["group_isolation"])
    seen: dict[tuple[str, str], int] = {}

    for index, row in enumerate(rows):
        keys: list[tuple[str, str]] = []
        if "artifact_sha256" in required:
            keys.append(("artifact", row["artifact_group"]))
        if "domain_group" in required:
            keys.append(("domain", row["domain_group"]))
        if "brand_group" in required:
            keys.append(("brand", row["brand_group"]))
        if "source_group" in required:
            keys.extend(("source", group) for group in row["source_groups"])

        for key in keys:
            if key in seen:
                uf.union(index, seen[key])
            else:
                seen[key] = index

    buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, row in enumerate(rows):
        buckets[uf.find(index)].append(row)

    components: list[dict[str, Any]] = []
    for bucket in buckets.values():
        sample_ids = sorted(row["sample_id"] for row in bucket)
        components.append({
            "component_id": "split-component-" + _canonical_hash(sample_ids)[:24],
            "records": sorted(bucket, key=lambda row: row["sample_id"]),
            "sample_count": len(bucket),
            "labels": {row["ground_truth"] for row in bucket},
            "min_time": min(row["_observed_dt"] for row in bucket),
            "max_time": max(row["_observed_dt"] for row in bucket),
        })

    components.sort(key=lambda c: (c["min_time"], c["max_time"], c["component_id"]))
    return components


def _label_component_counts(components: Iterable[Mapping[str, Any]]) -> dict[int, int]:
    items = list(components)
    return {
        label: sum(1 for component in items if label in component["labels"])
        for label in (0, 1)
    }


def _contains_both(components: Iterable[Mapping[str, Any]]) -> bool:
    labels: set[int] = set()
    for component in components:
        labels.update(component["labels"])
    return labels == {0, 1}


def _choose_test_suffix(components: list[dict[str, Any]], target_count: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[tuple[float, int, str, list[dict[str, Any]], list[dict[str, Any]]]] = []
    for boundary in range(1, len(components)):
        prefix = components[:boundary]
        suffix = components[boundary:]
        if not _contains_both(suffix):
            continue
        if max(c["max_time"] for c in prefix) >= min(c["min_time"] for c in suffix):
            continue
        counts = _label_component_counts(prefix)
        if counts[0] < 3 or counts[1] < 3:
            continue
        suffix_count = sum(c["sample_count"] for c in suffix)
        candidates.append((
            abs(suffix_count - target_count),
            suffix_count,
            suffix[0]["component_id"],
            prefix,
            suffix,
        ))
    if not candidates:
        raise SplitConstructionError(
            "cannot create a strict-forward final test while preserving four independent partitions"
        )
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return candidates[0][3], candidates[0][4]


def _can_reserve(available: list[dict[str, Any]], remove: dict[str, Any], remaining_partitions: int) -> bool:
    rest = [component for component in available if component is not remove]
    counts = _label_component_counts(rest)
    return counts[0] >= remaining_partitions and counts[1] >= remaining_partitions


def _choose_partition(
    available: list[dict[str, Any]],
    target_count: float,
    remaining_partitions: int,
    name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    chosen: list[dict[str, Any]] = []
    remaining = list(available)
    labels: set[int] = set()
    current_count = 0

    while labels != {0, 1}:
        missing = {0, 1} - labels
        candidates = [
            component for component in remaining
            if component["labels"] & missing and _can_reserve(remaining, component, remaining_partitions)
        ]
        if not candidates:
            raise SplitConstructionError(
                f"cannot construct {name} without violating independent class coverage"
            )
        candidates.sort(key=lambda component: (
            -len(component["labels"] & missing),
            abs((current_count + component["sample_count"]) - target_count),
            component["sample_count"],
            component["component_id"],
        ))
        selected = candidates[0]
        chosen.append(selected)
        remaining.remove(selected)
        labels.update(selected["labels"])
        current_count += selected["sample_count"]

    while remaining:
        current_diff = abs(current_count - target_count)
        candidates = [
            component for component in remaining
            if _can_reserve(remaining, component, remaining_partitions)
            and abs((current_count + component["sample_count"]) - target_count) < current_diff
        ]
        if not candidates:
            break
        candidates.sort(key=lambda component: (
            abs((current_count + component["sample_count"]) - target_count),
            component["sample_count"],
            component["component_id"],
        ))
        selected = candidates[0]
        chosen.append(selected)
        remaining.remove(selected)
        current_count += selected["sample_count"]

    return chosen, remaining


def _public_record(row: Mapping[str, Any], partition: str) -> dict[str, Any]:
    clean = {key: deepcopy(value) for key, value in row.items() if not key.startswith("_")}
    clean["partition"] = partition
    return clean


def _partition_payload(name: str, components: list[dict[str, Any]]) -> dict[str, Any]:
    records = [
        _public_record(row, name)
        for component in components
        for row in component["records"]
    ]
    records.sort(key=lambda row: row["sample_id"])
    labels = [row["ground_truth"] for row in records]
    return {
        "sample_count": len(records),
        "legitimate": labels.count(0),
        "phishing": labels.count(1),
        "component_count": len(components),
        "component_ids": sorted(component["component_id"] for component in components),
        "records": records,
    }


def _assert_no_overlap(partitions: Mapping[str, Mapping[str, Any]], contract: Mapping[str, Any]) -> dict[str, Any]:
    required = set(contract["group_isolation"])
    dimensions: dict[str, dict[str, set[str]]] = {}
    for dimension in required:
        by_partition: dict[str, set[str]] = {}
        for name, payload in partitions.items():
            values: set[str] = set()
            for row in payload["records"]:
                if dimension == "artifact_sha256":
                    values.add(row["artifact_group"])
                elif dimension == "source_group":
                    values.update(row["source_groups"])
                else:
                    values.add(row[dimension])
            by_partition[name] = values
        names = list(partitions)
        for i, left in enumerate(names):
            for right in names[i + 1:]:
                overlap = by_partition[left] & by_partition[right]
                if overlap:
                    raise SplitConstructionError(
                        f"{dimension} leakage between {left} and {right}"
                    )
        dimensions[dimension] = {
            name: set(values) for name, values in by_partition.items()
        }
    return {
        dimension: {name: len(values) for name, values in by_partition.items()}
        for dimension, by_partition in dimensions.items()
    }


def construct_stage_b_splits(
    reconciled: Mapping[str, Any],
    split_contract: Mapping[str, Any],
    *,
    fractions: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    contract = validate_split_contract(split_contract)
    fractions = dict(DEFAULT_FRACTIONS if fractions is None else fractions)
    if set(fractions) != set(contract["partition_order"]):
        raise SplitConstructionError("fractions must cover exactly the four contract partitions")
    if any(type(value) not in (int, float) or value <= 0 for value in fractions.values()):
        raise SplitConstructionError("partition fractions must be positive")
    total_fraction = sum(float(value) for value in fractions.values())
    if abs(total_fraction - 1.0) > 1e-9:
        raise SplitConstructionError("partition fractions must sum to 1")

    rows, excluded_unlabeled = _validate_reconciled(reconciled, contract)
    components = _componentize(rows, contract)
    counts = _label_component_counts(components)
    if counts[0] < 4 or counts[1] < 4:
        raise SplitConstructionError(
            "insufficient isolation components for four independent partitions"
        )

    total_samples = len(rows)
    if contract["chronology"].get("strict_forward_test") is not True:
        raise SplitConstructionError("Stage B requires strict_forward_test")

    pre_test, test_components = _choose_test_suffix(
        components,
        total_samples * float(fractions["test"]),
    )

    selection_components, remaining = _choose_partition(
        pre_test,
        total_samples * float(fractions["selection"]),
        remaining_partitions=2,
        name="selection",
    )
    calibration_components, train_components = _choose_partition(
        remaining,
        total_samples * float(fractions["calibration"]),
        remaining_partitions=1,
        name="calibration",
    )

    assignment = {
        "train": train_components,
        "selection": selection_components,
        "calibration": calibration_components,
        "test": test_components,
    }
    for name, assigned in assignment.items():
        if not assigned or not _contains_both(assigned):
            raise SplitConstructionError(
                f"{name} must contain independently isolated examples of both classes"
            )

    partitions = {
        name: _partition_payload(name, assignment[name])
        for name in contract["partition_order"]
    }
    isolation_counts = _assert_no_overlap(partitions, contract)

    non_test_times = [
        row["_observed_dt"]
        for name in ("train", "selection", "calibration")
        for component in assignment[name]
        for row in component["records"]
    ]
    test_times = [
        row["_observed_dt"]
        for component in test_components
        for row in component["records"]
    ]
    if min(test_times) <= max(non_test_times):
        raise SplitConstructionError("strict-forward final test chronology was not achieved")

    usage_policy = {
        "train": ["MODEL_FIT"],
        "selection": ["CANDIDATE_SELECTION"],
        "calibration": ["PROBABILITY_CALIBRATION", "THRESHOLD_SELECTION"],
        "test": ["FINAL_EVALUATION_ONLY"],
    }

    return {
        "schema_version": SPLIT_SCHEMA,
        "contract_sha256": _canonical_hash(contract),
        "source_schema_version": RECONCILED_SCHEMA,
        "partition_order": list(contract["partition_order"]),
        "target_fractions": {name: float(fractions[name]) for name in contract["partition_order"]},
        "usage_policy": usage_policy,
        "partitions": partitions,
        "excluded": {
            "unlabeled_candidates": excluded_unlabeled,
            "upstream_quarantine_groups": [
                item.get("artifact_group")
                for item in reconciled.get("quarantine", [])
                if isinstance(item, Mapping) and isinstance(item.get("artifact_group"), str)
            ],
        },
        "audit": {
            "final_test_locked": True,
            "strict_forward_test": True,
            "test_min_observed_at": min(test_times).isoformat(),
            "non_test_max_observed_at": max(non_test_times).isoformat(),
            "isolation_group_counts": isolation_counts,
            "artifact_isolation_mapping": "artifact_sha256 contract requirement is enforced with Task 3 artifact_group, which is stricter because query/path variants are connected before splitting.",
            "deterministic": True,
        },
        "limitations": [
            "Partition construction can prove declared metadata isolation, not semantic independence of unknown relationships.",
            "Missing brand/domain/time metadata causes a fail-closed split rather than silent fallback.",
            "Unlabeled popularity candidates are excluded from supervised partitions until independently validated.",
            "The final test is chronologically later than all train/selection/calibration records under the declared observed_at field.",
        ],
    }
