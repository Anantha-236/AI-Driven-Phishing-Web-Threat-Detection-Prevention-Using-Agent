"""Fail-closed readiness audit for Stage B model benchmarking.

The audit consumes the privacy-safe feature dataset produced by Task 5 and a
versioned readiness policy. It never trains, tunes, calibrates, or evaluates a
model. Its only job is to determine whether later benchmark stages may proceed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from typing import Any, Iterable, Mapping

from .stage_b_features import PARTITIONS, validate_feature_dataset

READINESS_SCHEMA = "stage-b-readiness-audit-1"
READINESS_POLICY_SCHEMA = "stage-b-readiness-policy-1"
DEFAULT_POLICY = {
    "schema_version": READINESS_POLICY_SCHEMA,
    "min_samples_per_class": {
        "train": 100,
        "selection": 50,
        "calibration": 50,
        "test": 100,
    },
    "allowed_provenance": {
        "train": ["REAL_BROWSER", "ARCHIVED_SANITIZED_EVENTS"],
        "selection": ["REAL_BROWSER"],
        "calibration": ["REAL_BROWSER"],
        "test": ["REAL_BROWSER"],
    },
    "require_strict_forward_test": True,
    "require_group_isolation": ["artifact_group", "domain_group", "brand_group", "source_groups"],
}


class ReadinessAuditError(ValueError):
    """Raised when the readiness policy or feature dataset cannot be audited."""


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ReadinessAuditError("feature rows require timezone-aware observed_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReadinessAuditError("invalid observed_at") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReadinessAuditError("observed_at must include a timezone")
    return parsed


def validate_readiness_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "schema_version", "min_samples_per_class", "allowed_provenance",
        "require_strict_forward_test", "require_group_isolation", "notes",
    }
    unexpected = set(policy) - allowed_keys
    if unexpected:
        raise ReadinessAuditError(
            f"unexpected readiness policy fields: {', '.join(sorted(unexpected))}"
        )
    if policy.get("schema_version") != READINESS_POLICY_SCHEMA:
        raise ReadinessAuditError("unsupported readiness policy schema")

    mins = policy.get("min_samples_per_class")
    if not isinstance(mins, Mapping) or set(mins) != set(PARTITIONS):
        raise ReadinessAuditError("readiness policy requires per-partition class minima")
    for partition, value in mins.items():
        if type(value) is not int or value < 1:
            raise ReadinessAuditError(f"invalid minimum sample count for {partition}")

    provenance = policy.get("allowed_provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != set(PARTITIONS):
        raise ReadinessAuditError("readiness policy requires provenance rules for every partition")
    allowed_values = {"REAL_BROWSER", "CONTROLLED_BROWSER", "ARCHIVED_SANITIZED_EVENTS", "SYNTHETIC"}
    for partition, values in provenance.items():
        if not isinstance(values, list) or not values or any(v not in allowed_values for v in values):
            raise ReadinessAuditError(f"invalid provenance policy for {partition}")

    if type(policy.get("require_strict_forward_test")) is not bool:
        raise ReadinessAuditError("require_strict_forward_test must be boolean")

    dimensions = policy.get("require_group_isolation")
    supported = {"artifact_group", "domain_group", "brand_group", "source_groups"}
    if not isinstance(dimensions, list) or not dimensions or any(v not in supported for v in dimensions):
        raise ReadinessAuditError("unsupported readiness isolation dimension")

    return json.loads(json.dumps(policy))


def _values_for_dimension(row: Mapping[str, Any], dimension: str) -> set[str]:
    if dimension == "source_groups":
        raw = row.get("source_groups")
        if not isinstance(raw, list) or not raw or any(not isinstance(v, str) or not v.strip() for v in raw):
            raise ReadinessAuditError("feature rows require source_groups lineage")
        return {v.strip() for v in raw}
    raw = row.get(dimension)
    # brand_group is optional: missing/null means unknown, not a shared group.
    if raw is None and dimension == "brand_group":
        return set()
    if not isinstance(raw, str) or not raw.strip():
        raise ReadinessAuditError(f"feature rows require {dimension}")
    return {raw.strip()}


def _group_overlaps(rows_by_partition: Mapping[str, list[Mapping[str, Any]]], dimensions: Iterable[str]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for dimension in dimensions:
        owners: dict[str, set[str]] = defaultdict(set)
        for partition, rows in rows_by_partition.items():
            for row in rows:
                for value in _values_for_dimension(row, dimension):
                    owners[value].add(partition)
        for value, partitions in sorted(owners.items()):
            if len(partitions) > 1:
                issues.append({
                    "code": "GROUP_OVERLAP",
                    "dimension": dimension,
                    "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    "partitions": sorted(partitions),
                })
    return issues


def audit_feature_dataset_readiness(
    feature_data: Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:  # preserve Task 5 as the authoritative feature validator
        raise ReadinessAuditError(f"invalid feature dataset: {exc}") from exc

    active_policy = validate_readiness_policy(policy or DEFAULT_POLICY)
    partitions = validated["partitions"]
    rows_by_partition: dict[str, list[Mapping[str, Any]]] = {}
    issues: list[dict[str, Any]] = []
    counts: dict[str, Any] = {}
    provenance_counts: dict[str, dict[str, int]] = {}
    times: dict[str, list[datetime]] = {}

    for partition in PARTITIONS:
        payload = partitions[partition]
        rows = payload.get("records") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list) or not rows:
            raise ReadinessAuditError(f"feature partition {partition} is empty")
        rows_by_partition[partition] = rows

        labels = Counter(row.get("ground_truth") for row in rows)
        if any(label not in (0, 1) for label in labels):
            raise ReadinessAuditError("readiness audit requires verified binary ground truth")
        counts[partition] = {
            "total": len(rows),
            "legitimate": labels.get(0, 0),
            "phishing": labels.get(1, 0),
        }
        minimum = active_policy["min_samples_per_class"][partition]
        for label, name in ((0, "legitimate"), (1, "phishing")):
            if labels.get(label, 0) < minimum:
                issues.append({
                    "code": "INSUFFICIENT_CLASS_SAMPLES",
                    "partition": partition,
                    "class": name,
                    "observed": labels.get(label, 0),
                    "required": minimum,
                })

        allowed = set(active_policy["allowed_provenance"][partition])
        pc = Counter()
        partition_times: list[datetime] = []
        for row in rows:
            provenance = row.get("collection_provenance")
            if not isinstance(provenance, str):
                raise ReadinessAuditError("feature rows require collection_provenance")
            pc[provenance] += 1
            if provenance not in allowed:
                issues.append({
                    "code": "DISALLOWED_PROVENANCE",
                    "partition": partition,
                    "provenance": provenance,
                    "sample_id_sha256": hashlib.sha256(str(row.get("sample_id", "")).encode("utf-8")).hexdigest(),
                })
            partition_times.append(_parse_time(row.get("observed_at")))
        provenance_counts[partition] = dict(sorted(pc.items()))
        times[partition] = partition_times

    issues.extend(_group_overlaps(rows_by_partition, active_policy["require_group_isolation"]))

    chronology: dict[str, Any] = {"required": active_policy["require_strict_forward_test"]}
    if active_policy["require_strict_forward_test"]:
        non_test_times = [
            value
            for partition in ("train", "selection", "calibration")
            for value in times[partition]
        ]
        latest_non_test = max(non_test_times)
        earliest_test = min(times["test"])
        chronology.update({
            "non_test_max_observed_at": latest_non_test.isoformat(),
            "test_min_observed_at": earliest_test.isoformat(),
            "strict_forward": latest_non_test < earliest_test,
        })
        if latest_non_test >= earliest_test:
            issues.append({
                "code": "FINAL_TEST_NOT_STRICTLY_FORWARD",
                "non_test_max_observed_at": latest_non_test.isoformat(),
                "test_min_observed_at": earliest_test.isoformat(),
            })

    unique_groups: dict[str, dict[str, int]] = {}
    for dimension in active_policy["require_group_isolation"]:
        unique_groups[dimension] = {}
        for partition, rows in rows_by_partition.items():
            values: set[str] = set()
            for row in rows:
                values.update(_values_for_dimension(row, dimension))
            unique_groups[dimension][partition] = len(values)

    return {
        "schema_version": READINESS_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "training_allowed": not issues,
        "policy_sha256": _canonical_hash(active_policy),
        "feature_dataset_identity": {
            "feature_version": validated.get("feature_version"),
            "feature_contract_sha256": validated.get("feature_contract_sha256"),
            "extractor_source_sha256": validated.get("extractor_source_sha256"),
            "episode_set_sha256": validated.get("episode_set_sha256"),
        },
        "counts": counts,
        "provenance_counts": provenance_counts,
        "unique_group_counts": unique_groups,
        "chronology": chronology,
        "issues": issues,
        "limitations": [
            "PASS means the declared Stage B readiness policy is satisfied; it does not prove statistical sufficiency or real-world generalization.",
            "Group isolation is only as strong as the supplied artifact/domain/brand/source metadata.",
            "The default sample minima are a development gate, not a claim of research-grade sample-size adequacy.",
        ],
    }
