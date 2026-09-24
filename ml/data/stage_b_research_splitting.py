"""Research-only four-way splitting for a single archived-browser-replay source.

This protocol exists because a single archive dataset cannot honestly satisfy
the production Stage B source-group independence contract. It therefore:

* consumes a validated Task-16 normalized archive-replay plan directly;
* isolates artifact, domain and brand groups across all partitions;
* keeps the final test strictly later than train/selection/calibration;
* locks selection/calibration/test usage exactly like the normal Stage B flow;
* explicitly records that source independence is relaxed;
* permanently marks the split as non-deployable research evidence.

It never changes the production split contract or production splitter.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import hashlib
import json
from typing import Any, Iterable, Mapping

ARCHIVE_NORMALIZED_SCHEMA = "stage-b-archive-replay-normalized-1"
RESEARCH_SPLIT_CONTRACT_SCHEMA = "stage-b-research-split-contract-1"
SPLIT_SCHEMA = "stage-b-splits-1"
PARTITIONS = ("train", "selection", "calibration", "test")
DEFAULT_FRACTIONS = {
    "train": 0.60,
    "selection": 0.15,
    "calibration": 0.15,
    "test": 0.10,
}
REQUIRED_ISOLATION = ("artifact_sha256", "domain_group", "brand_group")


class ResearchSplitError(ValueError):
    """Raised when honest research-only archive partitions cannot be built."""


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ResearchSplitError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResearchSplitError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ResearchSplitError(f"{field} must include a timezone")
    return parsed


def validate_research_split_contract(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ResearchSplitError("research split contract must be an object")
    allowed = {
        "schema_version", "protocol_id", "partition_order", "group_isolation",
        "chronology", "threshold_policy", "final_test_locked",
        "source_independence_required", "deployment_authorized", "notes",
    }
    unexpected = set(data) - allowed
    if unexpected:
        raise ResearchSplitError(
            f"unexpected research split contract fields: {', '.join(sorted(unexpected))}"
        )
    if data.get("schema_version") != RESEARCH_SPLIT_CONTRACT_SCHEMA:
        raise ResearchSplitError("unsupported research split contract schema")
    if data.get("protocol_id") != "single-source-archive-replay-research-v1":
        raise ResearchSplitError("unsupported research split protocol")
    if data.get("partition_order") != list(PARTITIONS):
        raise ResearchSplitError("partition_order must be train, selection, calibration, test")
    isolation = data.get("group_isolation")
    if isolation != list(REQUIRED_ISOLATION):
        raise ResearchSplitError(
            "research archive protocol must isolate artifact_sha256, domain_group and brand_group"
        )
    chronology = data.get("chronology")
    if not isinstance(chronology, Mapping) or chronology != {
        "field": "observed_at",
        "strict_forward_test": True,
    }:
        raise ResearchSplitError("research archive protocol requires strict-forward observed_at test")
    threshold = data.get("threshold_policy")
    expected_threshold = {
        "model_fit_partition": "train",
        "candidate_selection_partition": "selection",
        "probability_calibration_partition": "calibration",
        "threshold_selection_partition": "calibration",
        "final_evaluation_partition": "test",
    }
    if threshold != expected_threshold:
        raise ResearchSplitError("research threshold partition roles are invalid")
    if data.get("final_test_locked") is not True:
        raise ResearchSplitError("research final test must remain locked")
    if data.get("source_independence_required") is not False:
        raise ResearchSplitError("single-source archive research must declare relaxed source independence")
    if data.get("deployment_authorized") is not False:
        raise ResearchSplitError("research archive split can never authorize deployment")
    notes = data.get("notes")
    if not isinstance(notes, list) or not notes or any(not isinstance(v, str) or not v.strip() for v in notes):
        raise ResearchSplitError("research split contract requires explicit limitations")
    return json.loads(json.dumps(data))


class _UnionFind:
    def __init__(self, count: int) -> None:
        self.parent = list(range(count))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[b] = a


def _validate_archive_plan(data: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str]:
    if data.get("schema_version") != ARCHIVE_NORMALIZED_SCHEMA:
        raise ResearchSplitError("Task 17 requires a normalized Task 16 archive replay plan")
    if data.get("collection_provenance") != "ARCHIVED_BROWSER_REPLAY":
        raise ResearchSplitError("research archive split requires ARCHIVED_BROWSER_REPLAY provenance")
    dataset = data.get("dataset")
    if not isinstance(dataset, Mapping):
        raise ResearchSplitError("normalized archive plan requires dataset metadata")
    source_group = dataset.get("independence_group")
    if not isinstance(source_group, str) or not source_group.strip():
        raise ResearchSplitError("archive dataset independence_group is required")
    raw_items = data.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ResearchSplitError("normalized archive plan requires items")

    rows: list[dict[str, Any]] = []
    seen_samples: set[str] = set()
    seen_artifacts: set[str] = set()
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            raise ResearchSplitError("archive item must be an object")
        sample_id = raw.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen_samples:
            raise ResearchSplitError("sample_id must be unique and non-empty")
        seen_samples.add(sample_id)

        label = raw.get("ground_truth")
        if type(label) is not int or label not in (0, 1):
            raise ResearchSplitError("archive items require binary verified ground truth")

        artifact = raw.get("artifact_sha256")
        if not isinstance(artifact, str) or len(artifact) != 64:
            raise ResearchSplitError("archive items require artifact_sha256")
        try:
            int(artifact, 16)
        except ValueError as exc:
            raise ResearchSplitError("artifact_sha256 must be hexadecimal") from exc
        if artifact in seen_artifacts:
            raise ResearchSplitError("duplicate archive artifact cannot enter supervised splitting")
        seen_artifacts.add(artifact)

        domain = raw.get("domain_group")
        brand = raw.get("brand_group")
        if not isinstance(domain, str) or not domain.strip():
            raise ResearchSplitError("archive items require domain_group")
        if not isinstance(brand, str) or not brand.strip():
            raise ResearchSplitError(
                "archive items require brand_group for cross-partition brand isolation"
            )
        item_source = raw.get("source_group")
        if item_source != source_group:
            raise ResearchSplitError("archive item source_group must match dataset independence_group")

        observed_at = raw.get("observed_at")
        observed_dt = _parse_time(observed_at, "observed_at")
        rows.append({
            "sample_id": sample_id,
            "ground_truth": label,
            "observed_at": observed_at,
            "_observed_dt": observed_dt,
            "artifact_group": artifact,
            "domain_group": domain.strip(),
            "brand_group": brand.strip(),
            "source_groups": [source_group],
        })

    if {row["ground_truth"] for row in rows} != {0, 1}:
        raise ResearchSplitError("both legitimate and phishing classes are required")
    return rows, source_group


def _componentize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    uf = _UnionFind(len(rows))
    seen: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        keys = (
            ("artifact", row["artifact_group"]),
            ("domain", row["domain_group"]),
            ("brand", row["brand_group"]),
        )
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
            "component_id": "research-component-" + _canonical_hash(sample_ids)[:24],
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


def _choose_test_suffix(
    components: list[dict[str, Any]],
    target_count: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates = []
    for boundary in range(1, len(components)):
        prefix, suffix = components[:boundary], components[boundary:]
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
        raise ResearchSplitError(
            "cannot create strict-forward research test while preserving four class-covered partitions"
        )
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return candidates[0][3], candidates[0][4]


def _can_reserve(
    available: list[dict[str, Any]],
    remove: dict[str, Any],
    remaining_partitions: int,
) -> bool:
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
    count = 0

    while labels != {0, 1}:
        missing = {0, 1} - labels
        candidates = [
            component
            for component in remaining
            if component["labels"] & missing
            and _can_reserve(remaining, component, remaining_partitions)
        ]
        if not candidates:
            raise ResearchSplitError(
                f"cannot construct {name} while preserving later class coverage"
            )
        candidates.sort(key=lambda component: (
            -len(component["labels"] & missing),
            abs((count + component["sample_count"]) - target_count),
            component["sample_count"],
            component["component_id"],
        ))
        selected = candidates[0]
        chosen.append(selected)
        remaining.remove(selected)
        labels.update(selected["labels"])
        count += selected["sample_count"]

    while remaining:
        current_diff = abs(count - target_count)
        candidates = [
            component
            for component in remaining
            if _can_reserve(remaining, component, remaining_partitions)
            and abs((count + component["sample_count"]) - target_count) < current_diff
        ]
        if not candidates:
            break
        candidates.sort(key=lambda component: (
            abs((count + component["sample_count"]) - target_count),
            component["sample_count"],
            component["component_id"],
        ))
        selected = candidates[0]
        chosen.append(selected)
        remaining.remove(selected)
        count += selected["sample_count"]

    return chosen, remaining


def _public_record(row: Mapping[str, Any], partition: str) -> dict[str, Any]:
    return {
        "sample_id": row["sample_id"],
        "partition": partition,
        "ground_truth": row["ground_truth"],
        "artifact_group": row["artifact_group"],
        "domain_group": row["domain_group"],
        "brand_group": row["brand_group"],
        "source_groups": list(row["source_groups"]),
        "observed_at": row["observed_at"],
    }


def _payload(name: str, components: list[dict[str, Any]]) -> dict[str, Any]:
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
        "component_ids": sorted(c["component_id"] for c in components),
        "records": records,
    }


def _assert_research_isolation(partitions: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    fields = {
        "artifact_sha256": "artifact_group",
        "domain_group": "domain_group",
        "brand_group": "brand_group",
    }
    names = list(PARTITIONS)
    for dimension, field in fields.items():
        values_by_partition: dict[str, set[str]] = {}
        for name in PARTITIONS:
            values_by_partition[name] = {
                str(row[field]) for row in partitions[name]["records"]
            }
        for index, left in enumerate(names):
            for right in names[index + 1:]:
                if values_by_partition[left] & values_by_partition[right]:
                    raise ResearchSplitError(f"{dimension} leakage between {left} and {right}")
        result[dimension] = {
            name: len(values_by_partition[name]) for name in PARTITIONS
        }
    return result


def construct_research_archive_splits(
    normalized_archive_plan: Mapping[str, Any],
    research_contract: Mapping[str, Any],
    *,
    fractions: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    contract = validate_research_split_contract(research_contract)
    rows, source_group = _validate_archive_plan(normalized_archive_plan)

    active_fractions = dict(DEFAULT_FRACTIONS if fractions is None else fractions)
    if set(active_fractions) != set(PARTITIONS):
        raise ResearchSplitError("fractions must cover exactly train/selection/calibration/test")
    if any(type(value) not in (int, float) or value <= 0 for value in active_fractions.values()):
        raise ResearchSplitError("partition fractions must be positive")
    if abs(sum(float(value) for value in active_fractions.values()) - 1.0) > 1e-9:
        raise ResearchSplitError("partition fractions must sum to 1")

    components = _componentize(rows)
    counts = _label_component_counts(components)
    if counts[0] < 4 or counts[1] < 4:
        raise ResearchSplitError(
            "insufficient artifact/domain/brand-isolated components for four class-covered partitions"
        )

    total = len(rows)
    pre_test, test_components = _choose_test_suffix(
        components, total * float(active_fractions["test"])
    )
    selection_components, remaining = _choose_partition(
        pre_test,
        total * float(active_fractions["selection"]),
        remaining_partitions=2,
        name="selection",
    )
    calibration_components, train_components = _choose_partition(
        remaining,
        total * float(active_fractions["calibration"]),
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
            raise ResearchSplitError(f"{name} must contain both classes")

    partitions = {name: _payload(name, assignment[name]) for name in PARTITIONS}
    isolation_counts = _assert_research_isolation(partitions)

    non_test_times = [
        row["_observed_dt"]
        for name in ("train", "selection", "calibration")
        for component in assignment[name]
        for row in component["records"]
    ]
    test_times = [
        row["_observed_dt"]
        for component in assignment["test"]
        for row in component["records"]
    ]
    if min(test_times) <= max(non_test_times):
        raise ResearchSplitError("strict-forward research final test chronology was not achieved")

    return {
        "schema_version": SPLIT_SCHEMA,
        "contract_sha256": _canonical_hash(contract),
        "source_schema_version": ARCHIVE_NORMALIZED_SCHEMA,
        "partition_order": list(PARTITIONS),
        "target_fractions": {
            name: float(active_fractions[name]) for name in PARTITIONS
        },
        "usage_policy": {
            "train": ["MODEL_FIT"],
            "selection": ["CANDIDATE_SELECTION"],
            "calibration": ["PROBABILITY_CALIBRATION", "THRESHOLD_SELECTION"],
            "test": ["FINAL_EVALUATION_ONLY"],
        },
        "partitions": partitions,
        "excluded": {
            "unlabeled_candidates": [],
            "upstream_quarantine_groups": [],
        },
        "audit": {
            "final_test_locked": True,
            "strict_forward_test": True,
            "test_min_observed_at": min(test_times).isoformat(),
            "non_test_max_observed_at": max(non_test_times).isoformat(),
            "isolation_group_counts": isolation_counts,
            "deterministic": True,
            "research_only": True,
            "protocol_id": contract["protocol_id"],
            "source_independence_required": False,
            "source_independence_relaxed": True,
            "single_source_group_sha256": hashlib.sha256(
                source_group.encode("utf-8")
            ).hexdigest(),
            "deployment_authorized": False,
            "production_readiness_equivalent": False,
        },
        "limitations": [
            "This protocol intentionally relaxes source-group independence because all samples come from one declared archive source.",
            "Artifact, domain and brand connected components remain isolated across all four partitions.",
            "The final test is strictly later than all non-test records under declared observed_at metadata.",
            "A PASS research split cannot be interpreted as production readiness or deployment authorization.",
            "Archive capture biases and shared collection methodology may create dependencies not represented by artifact/domain/brand metadata.",
        ],
    }
