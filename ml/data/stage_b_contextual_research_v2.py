"""Stage B research protocol v2 for the contextual browser model.

Protocol rationale:
- The deployed contextual feature vector never contains literal brand identity,
  hostname strings, URL text, or origin identifiers.
- Exact artifact identity remains isolated.
- Exact-host domain identity remains isolated as a conservative site/tenant
  boundary.
- brand_group is retained on every record for audit/subgroup evaluation but is
  not a connectivity/isolation key.
- The final test remains strictly forward in observed_at.
- Source-group independence remains explicitly relaxed because this is one
  archive source.
- The protocol is research-only and never authorizes deployment.

This module is separate from the v1 splitter so historical v1 artifacts remain
reproducible.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from typing import Any, Mapping

from .stage_b_research_splitting import (
    ARCHIVE_NORMALIZED_SCHEMA,
    PARTITIONS,
    SPLIT_SCHEMA,
    _parse_time,
    _validate_archive_plan,
)

CONTRACT_SCHEMA = "stage-b-research-split-contract-2"
PROTOCOL_ID = "single-source-contextual-archive-replay-research-v2"
ISOLATION_KEYS = ("artifact_group", "domain_group")


class ContextualResearchSplitError(ValueError):
    pass


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
    ).hexdigest()


class _UF:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != CONTRACT_SCHEMA:
        raise ContextualResearchSplitError("unsupported contextual research split contract")
    if contract.get("protocol_id") != PROTOCOL_ID:
        raise ContextualResearchSplitError("unsupported contextual research protocol")
    if contract.get("partition_order") != list(PARTITIONS):
        raise ContextualResearchSplitError("partition_order must match Stage B")
    if contract.get("group_isolation") != ["artifact_sha256", "domain_group"]:
        raise ContextualResearchSplitError(
            "v2 contextual protocol must isolate artifact_sha256 and domain_group"
        )
    if contract.get("audit_only_groups") != ["brand_group"]:
        raise ContextualResearchSplitError("brand_group must remain an explicit audit-only group")
    if contract.get("chronology") != {
        "field": "observed_at",
        "strict_forward_test": True,
    }:
        raise ContextualResearchSplitError("v2 requires strict-forward observed_at final test")
    if contract.get("final_test_locked") is not True:
        raise ContextualResearchSplitError("final test must remain locked")
    if contract.get("source_independence_required") is not False:
        raise ContextualResearchSplitError("single-source research must declare relaxed source independence")
    if contract.get("deployment_authorized") is not False:
        raise ContextualResearchSplitError("research protocol cannot authorize deployment")
    rationale = contract.get("brand_isolation_rationale")
    if not isinstance(rationale, str) or "not model-observable" not in rationale.lower():
        raise ContextualResearchSplitError("contract must document why brand is audit-only")
    return json.loads(json.dumps(contract))


def validate_readiness_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    mins = policy.get("min_samples_per_class")
    if not isinstance(mins, Mapping) or set(mins) != set(PARTITIONS):
        raise ContextualResearchSplitError("readiness policy requires all four class minima")
    for name, value in mins.items():
        if type(value) is not int or value < 1:
            raise ContextualResearchSplitError(f"invalid minimum for {name}")
    if policy.get("require_group_isolation") != ["artifact_group", "domain_group"]:
        raise ContextualResearchSplitError(
            "v2 readiness policy must isolate artifact_group and domain_group only"
        )
    if policy.get("require_strict_forward_test") is not True:
        raise ContextualResearchSplitError("v2 readiness requires strict-forward final test")
    allowed = policy.get("allowed_provenance")
    if not isinstance(allowed, Mapping) or any(
        allowed.get(name) != ["ARCHIVED_BROWSER_REPLAY"] for name in PARTITIONS
    ):
        raise ContextualResearchSplitError(
            "v2 readiness allows only ARCHIVED_BROWSER_REPLAY"
        )
    return json.loads(json.dumps(policy))


def _componentize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    uf = _UF(len(rows))
    seen: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        for field in ISOLATION_KEYS:
            token = (field, str(row[field]))
            if token in seen:
                uf.union(index, seen[token])
            else:
                seen[token] = index

    buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, row in enumerate(rows):
        buckets[uf.find(index)].append(row)

    out = []
    for bucket in buckets.values():
        ids = sorted(row["sample_id"] for row in bucket)
        out.append({
            "component_id": "contextual-v2-component-" + _canonical_hash(ids)[:24],
            "records": sorted(bucket, key=lambda row: row["sample_id"]),
            "sample_count": len(bucket),
            "label_counts": {
                0: sum(row["ground_truth"] == 0 for row in bucket),
                1: sum(row["ground_truth"] == 1 for row in bucket),
            },
            "labels": {row["ground_truth"] for row in bucket},
            "min_time": min(row["_observed_dt"] for row in bucket),
            "max_time": max(row["_observed_dt"] for row in bucket),
        })
    out.sort(key=lambda c: (c["min_time"], c["max_time"], c["component_id"]))
    return out


def _counts(components: list[dict[str, Any]]) -> dict[int, int]:
    return {
        label: sum(c["label_counts"][label] for c in components)
        for label in (0, 1)
    }


def _label_component_counts(components: list[dict[str, Any]]) -> dict[int, int]:
    return {
        label: sum(1 for c in components if c["label_counts"][label] > 0)
        for label in (0, 1)
    }


def _can_remove(
    available: list[dict[str, Any]],
    candidate: dict[str, Any],
    reserve_samples: dict[int, int],
    reserve_partitions: int,
) -> bool:
    rest = [c for c in available if c is not candidate]
    counts = _counts(rest)
    component_counts = _label_component_counts(rest)
    return all(
        counts[label] >= reserve_samples[label]
        and component_counts[label] >= reserve_partitions
        for label in (0, 1)
    )


def _choose_partition(
    available: list[dict[str, Any]],
    *,
    minimum: int,
    target_total: float,
    reserve_samples: dict[int, int],
    reserve_partitions: int,
    name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    chosen: list[dict[str, Any]] = []
    remaining = list(available)
    selected_counts = {0: 0, 1: 0}
    selected_total = 0

    while selected_counts[0] < minimum or selected_counts[1] < minimum:
        deficits = {
            label: max(0, minimum - selected_counts[label])
            for label in (0, 1)
        }
        candidates = [
            c for c in remaining
            if (
                (deficits[0] and c["label_counts"][0] > 0)
                or (deficits[1] and c["label_counts"][1] > 0)
            )
            and _can_remove(
                remaining, c, reserve_samples, reserve_partitions
            )
        ]
        if not candidates:
            raise ContextualResearchSplitError(
                f"cannot satisfy {name} class minimum while preserving later partitions"
            )

        def key(c):
            useful = sum(
                min(deficits[label], c["label_counts"][label])
                for label in (0, 1)
            )
            overshoot = sum(
                max(0, c["label_counts"][label] - deficits[label])
                for label in (0, 1)
            )
            return (
                -useful,
                overshoot,
                abs((selected_total + c["sample_count"]) - target_total),
                c["sample_count"],
                c["component_id"],
            )

        selected = min(candidates, key=key)
        chosen.append(selected)
        remaining.remove(selected)
        for label in (0, 1):
            selected_counts[label] += selected["label_counts"][label]
        selected_total += selected["sample_count"]

    while remaining:
        current_diff = abs(selected_total - target_total)
        candidates = [
            c for c in remaining
            if _can_remove(remaining, c, reserve_samples, reserve_partitions)
            and abs((selected_total + c["sample_count"]) - target_total) < current_diff
        ]
        if not candidates:
            break
        selected = min(
            candidates,
            key=lambda c: (
                abs((selected_total + c["sample_count"]) - target_total),
                c["sample_count"],
                c["component_id"],
            ),
        )
        chosen.append(selected)
        remaining.remove(selected)
        for label in (0, 1):
            selected_counts[label] += selected["label_counts"][label]
        selected_total += selected["sample_count"]

    return chosen, remaining


def _public(row: Mapping[str, Any], partition: str) -> dict[str, Any]:
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


def _payload(name: str, comps: list[dict[str, Any]]) -> dict[str, Any]:
    records = [
        _public(row, name)
        for comp in comps
        for row in comp["records"]
    ]
    records.sort(key=lambda row: row["sample_id"])
    labels = Counter(row["ground_truth"] for row in records)
    return {
        "sample_count": len(records),
        "legitimate": labels[0],
        "phishing": labels[1],
        "component_count": len(comps),
        "component_ids": sorted(c["component_id"] for c in comps),
        "records": records,
    }


def _isolation_audit(partitions: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for dimension, field in (
        ("artifact_sha256", "artifact_group"),
        ("domain_group", "domain_group"),
    ):
        owners: dict[str, set[str]] = defaultdict(set)
        counts: dict[str, int] = {}
        for partition in PARTITIONS:
            values = {str(row[field]) for row in partitions[partition]["records"]}
            counts[partition] = len(values)
            for value in values:
                owners[value].add(partition)
        overlap = [value for value, parts in owners.items() if len(parts) > 1]
        if overlap:
            raise ContextualResearchSplitError(
                f"{dimension} leakage across partitions"
            )
        result[dimension] = counts

    brand_owners: dict[str, set[str]] = defaultdict(set)
    for partition in PARTITIONS:
        for row in partitions[partition]["records"]:
            brand_owners[str(row["brand_group"])].add(partition)
    cross_partition_brands = {
        hashlib.sha256(brand.encode("utf-8")).hexdigest(): sorted(parts)
        for brand, parts in brand_owners.items()
        if len(parts) > 1
    }
    result["brand_group_audit_only"] = {
        "unique_total": len(brand_owners),
        "cross_partition_brand_count": len(cross_partition_brands),
        "cross_partition_brand_hashes": cross_partition_brands,
    }
    return result


def construct_contextual_research_splits(
    normalized_plan: Mapping[str, Any],
    contract: Mapping[str, Any],
    readiness_policy: Mapping[str, Any],
) -> dict[str, Any]:
    active_contract = validate_contract(contract)
    active_policy = validate_readiness_policy(readiness_policy)
    rows, source_group = _validate_archive_plan(normalized_plan)
    components = _componentize(rows)
    total = len(rows)

    minima = active_policy["min_samples_per_class"]
    upstream_required = (
        minima["train"] + minima["selection"] + minima["calibration"]
    )
    test_required = minima["test"]

    candidates = []
    for cutoff in sorted({c["min_time"] for c in components}):
        prefix = [c for c in components if c["max_time"] < cutoff]
        suffix = [c for c in components if c["min_time"] >= cutoff]
        bridges = [c for c in components if c["min_time"] < cutoff <= c["max_time"]]
        if not prefix or not suffix:
            continue
        pc = _counts(prefix)
        sc = _counts(suffix)
        pcc = _label_component_counts(prefix)
        if any(pc[label] < upstream_required for label in (0, 1)):
            continue
        if any(sc[label] < test_required for label in (0, 1)):
            continue
        if any(pcc[label] < 3 for label in (0, 1)):
            continue

        bridge_samples = sum(c["sample_count"] for c in bridges)
        suffix_total = sum(c["sample_count"] for c in suffix)
        candidates.append((
            bridge_samples,
            abs(suffix_total - total * 0.10),
            suffix_total,
            cutoff.isoformat(),
            prefix,
            suffix,
            bridges,
        ))

    if not candidates:
        raise ContextualResearchSplitError(
            "no readiness-feasible strict-forward cutoff under contextual v2 isolation"
        )

    candidates.sort(key=lambda item: item[:4])

    allocation_errors: list[str] = []
    selected_assignment = None
    selected_meta = None
    for candidate in candidates:
        _, _, _, cutoff_iso, prefix, test_components, bridges = candidate
        try:
            selection, rest = _choose_partition(
                prefix,
                minimum=minima["selection"],
                target_total=total * 0.15,
                reserve_samples={
                    0: minima["calibration"] + minima["train"],
                    1: minima["calibration"] + minima["train"],
                },
                reserve_partitions=2,
                name="selection",
            )
            calibration, train = _choose_partition(
                rest,
                minimum=minima["calibration"],
                target_total=total * 0.15,
                reserve_samples={
                    0: minima["train"],
                    1: minima["train"],
                },
                reserve_partitions=1,
                name="calibration",
            )
            train_counts = _counts(train)
            if any(train_counts[label] < minima["train"] for label in (0, 1)):
                raise ContextualResearchSplitError("train class minimum not met")

            selected_assignment = {
                "train": train,
                "selection": selection,
                "calibration": calibration,
                "test": test_components,
            }
            selected_meta = (cutoff_iso, bridges)
            break
        except ContextualResearchSplitError as exc:
            allocation_errors.append(f"{cutoff_iso}: {exc}")

    if selected_assignment is None or selected_meta is None:
        raise ContextualResearchSplitError(
            "strict-forward cutoffs are aggregate-feasible but no deterministic "
            f"four-way minimum-preserving allocation succeeded; attempts={len(allocation_errors)}"
        )

    partitions = {
        name: _payload(name, selected_assignment[name])
        for name in PARTITIONS
    }

    for name in PARTITIONS:
        minimum = minima[name]
        payload = partitions[name]
        if payload["legitimate"] < minimum or payload["phishing"] < minimum:
            raise ContextualResearchSplitError(
                f"{name} failed declared readiness class minimum"
            )

    isolation = _isolation_audit(partitions)

    non_test_times = [
        _parse_time(row["observed_at"], "observed_at")
        for name in ("train", "selection", "calibration")
        for row in partitions[name]["records"]
    ]
    test_times = [
        _parse_time(row["observed_at"], "observed_at")
        for row in partitions["test"]["records"]
    ]
    if max(non_test_times) >= min(test_times):
        raise ContextualResearchSplitError("strict-forward chronology not achieved")

    cutoff_iso, bridge_components = selected_meta
    bridge_ids = sorted(c["component_id"] for c in bridge_components)

    return {
        "schema_version": SPLIT_SCHEMA,
        "contract_sha256": _canonical_hash(active_contract),
        "source_schema_version": ARCHIVE_NORMALIZED_SCHEMA,
        "partition_order": list(PARTITIONS),
        "target_fractions": {
            "train": 0.60,
            "selection": 0.15,
            "calibration": 0.15,
            "test": 0.10,
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
            "upstream_quarantine_groups": bridge_ids,
        },
        "audit": {
            "final_test_locked": True,
            "strict_forward_test": True,
            "selected_cutoff": cutoff_iso,
            "chronology_bridge_component_count": len(bridge_components),
            "chronology_bridge_sample_count": sum(
                c["sample_count"] for c in bridge_components
            ),
            "test_min_observed_at": min(test_times).isoformat(),
            "non_test_max_observed_at": max(non_test_times).isoformat(),
            "isolation_group_counts": isolation,
            "isolation_dimensions": ["artifact_group", "domain_group"],
            "audit_only_dimensions": ["brand_group"],
            "deterministic": True,
            "research_only": True,
            "protocol_id": PROTOCOL_ID,
            "source_independence_required": False,
            "source_independence_relaxed": True,
            "single_source_group_sha256": hashlib.sha256(
                source_group.encode("utf-8")
            ).hexdigest(),
            "deployment_authorized": False,
            "production_readiness_equivalent": False,
        },
        "limitations": [
            "RESEARCH-ONLY single-source archived-browser-replay protocol.",
            "Exact artifact identity and exact-host domain groups are isolated across all partitions.",
            "brand_group is retained for audit/subgroup analysis but is not an isolation key because literal brand identity is not model-observable in context-features-1.",
            "The final test is strictly later than all train/selection/calibration records.",
            "Components crossing the chosen cutoff are quarantined rather than weakening chronology or active isolation dimensions.",
            "Source-group independence remains relaxed and this result cannot authorize deployment.",
        ],
    }
