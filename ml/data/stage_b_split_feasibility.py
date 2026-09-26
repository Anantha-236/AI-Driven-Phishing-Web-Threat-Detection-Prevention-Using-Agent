"""Analyze whether the current Stage B research candidate can satisfy
readiness counts under the existing strict-forward/group-isolation semantics.

This module is diagnostic only. It never mutates the split contract, candidate
plan, readiness thresholds, or deployment guards.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .stage_b_research_splitting import (
    DEFAULT_FRACTIONS,
    PARTITIONS,
    _componentize,
    _label_component_counts,
    _validate_archive_plan,
)


class SplitFeasibilityError(ValueError):
    pass


def _sample_label_counts(components):
    counts = Counter()
    for component in components:
        for row in component["records"]:
            counts[row["ground_truth"]] += 1
    return {0: counts[0], 1: counts[1]}


def analyze_strict_forward_readiness_feasibility(
    normalized_plan: Mapping[str, Any],
    readiness_policy: Mapping[str, Any],
    *,
    max_results: int = 25,
) -> dict[str, Any]:
    if type(max_results) is not int or max_results < 1:
        raise SplitFeasibilityError("max_results must be a positive integer")

    rows, _ = _validate_archive_plan(normalized_plan)
    components = _componentize(rows)

    minima = readiness_policy.get("min_samples_per_class")
    if not isinstance(minima, Mapping):
        raise SplitFeasibilityError("readiness policy requires min_samples_per_class")

    required = {}
    for partition in PARTITIONS:
        value = minima.get(partition)
        if type(value) is not int or value < 1:
            raise SplitFeasibilityError(
                f"invalid min_samples_per_class for {partition}"
            )
        required[partition] = value

    upstream_required = (
        required["train"] + required["selection"] + required["calibration"]
    )
    test_required = required["test"]

    total_counts = Counter(row["ground_truth"] for row in rows)
    cutoffs = sorted({component["min_time"] for component in components})
    candidates = []

    for cutoff in cutoffs:
        prefix = [c for c in components if c["max_time"] < cutoff]
        suffix = [c for c in components if c["min_time"] >= cutoff]
        bridges = [
            c for c in components
            if c["min_time"] < cutoff <= c["max_time"]
        ]
        if not prefix or not suffix:
            continue

        prefix_samples = _sample_label_counts(prefix)
        suffix_samples = _sample_label_counts(suffix)
        bridge_samples = _sample_label_counts(bridges)
        prefix_component_counts = _label_component_counts(prefix)

        aggregate_feasible = (
            prefix_samples[0] >= upstream_required
            and prefix_samples[1] >= upstream_required
            and suffix_samples[0] >= test_required
            and suffix_samples[1] >= test_required
            and prefix_component_counts[0] >= 3
            and prefix_component_counts[1] >= 3
        )

        suffix_total = suffix_samples[0] + suffix_samples[1]
        target_test = len(rows) * float(DEFAULT_FRACTIONS["test"])
        bridge_total = bridge_samples[0] + bridge_samples[1]

        # Rank first by true readiness feasibility, then by the same broad
        # quantities that matter to the current splitter: quarantine cost and
        # distance from the nominal test fraction.
        score = (
            0 if aggregate_feasible else 1,
            bridge_total,
            abs(suffix_total - target_test),
            cutoff.isoformat(),
        )
        candidates.append({
            "cutoff": cutoff.isoformat(),
            "aggregate_feasible": aggregate_feasible,
            "prefix": {
                "legitimate": prefix_samples[0],
                "phishing": prefix_samples[1],
                "required_per_class_total_for_train_selection_calibration": upstream_required,
                "label_component_counts": {
                    "legitimate": prefix_component_counts[0],
                    "phishing": prefix_component_counts[1],
                },
            },
            "test_suffix": {
                "legitimate": suffix_samples[0],
                "phishing": suffix_samples[1],
                "required_per_class": test_required,
                "samples": suffix_total,
            },
            "chronology_bridge": {
                "legitimate": bridge_samples[0],
                "phishing": bridge_samples[1],
                "samples": bridge_total,
                "components": len(bridges),
            },
            "_score": score,
        })

    feasible = [row for row in candidates if row["aggregate_feasible"]]
    ranked = sorted(candidates, key=lambda row: row["_score"])

    def public(row):
        return {k: v for k, v in row.items() if k != "_score"}

    result = {
        "status": "PASS",
        "schema_version": "stage-b-strict-forward-feasibility-1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_samples": len(rows),
        "candidate_labels": {
            "legitimate": total_counts[0],
            "phishing": total_counts[1],
        },
        "connected_components": len(components),
        "requirements": {
            "train_per_class": required["train"],
            "selection_per_class": required["selection"],
            "calibration_per_class": required["calibration"],
            "test_per_class": required["test"],
            "upstream_total_per_class_before_test": upstream_required,
        },
        "cutoffs_examined": len(candidates),
        "aggregate_feasible_cutoffs": len(feasible),
        "feasibility": (
            "FEASIBLE_UNDER_CURRENT_GROUP_SEMANTICS"
            if feasible
            else "NO_FEASIBLE_STRICT_FORWARD_CUTOFF"
        ),
        "best_candidates": [public(row) for row in ranked[:max_results]],
        "interpretation": (
            "Aggregate feasibility is necessary but not sufficient for a final "
            "four-way assignment. A feasible cutoff means the current strict "
            "artifact/domain/brand semantics may be salvageable with a "
            "readiness-aware allocator. No feasible cutoff means changing only "
            "the cutoff/allocator cannot satisfy the declared readiness minima."
        ),
    }
    return result
