from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ml.data.stage_b_split_feasibility import (
    analyze_strict_forward_readiness_feasibility,
)


def policy(train=2, selection=1, calibration=1, test=2):
    return {
        "min_samples_per_class": {
            "train": train,
            "selection": selection,
            "calibration": calibration,
            "test": test,
        }
    }


def plan(*, bridge=False):
    start = datetime(2023, 1, 1, tzinfo=timezone.utc)
    items = []
    for label in (0, 1):
        for i in range(12):
            # Before/after groups are intentionally unique.
            items.append({
                "sample_id": f"s-{label}-{i}",
                "archive_path": f"{label}/{i}.html",
                "ground_truth": label,
                "domain_group": f"d-{label}-{i}.example",
                "brand_group": f"b-{label}-{i}",
                "source_group": "source",
                "artifact_sha256": f"{label + 1:01x}" + f"{i + 1:063x}"[-63:],
                "observed_at": (start + timedelta(days=i)).isoformat(),
                "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
            })
    if bridge:
        # Force an early and late phishing record into one component.
        items[12]["brand_group"] = "bridge-brand"
        items[-1]["brand_group"] = "bridge-brand"

    return {
        "schema_version": "stage-b-archive-replay-normalized-1",
        "plan_id": "test",
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "dataset": {
            "dataset_id": "fixture",
            "source_type": "ARCHIVE_DATASET",
            "independence_group": "source",
            "license_reference": "fixture",
            "research_use_acknowledged": True,
        },
        "items": items,
    }


def test_reports_feasible_cutoffs_when_counts_allow_it():
    result = analyze_strict_forward_readiness_feasibility(
        plan(), policy(), max_results=5
    )
    assert result["status"] == "PASS"
    assert result["aggregate_feasible_cutoffs"] >= 1
    assert result["feasibility"] == "FEASIBLE_UNDER_CURRENT_GROUP_SEMANTICS"


def test_reports_no_feasible_cutoff_when_test_minimum_is_impossible():
    result = analyze_strict_forward_readiness_feasibility(
        plan(), policy(test=20), max_results=5
    )
    assert result["aggregate_feasible_cutoffs"] == 0
    assert result["feasibility"] == "NO_FEASIBLE_STRICT_FORWARD_CUTOFF"


def test_output_never_authorizes_deployment():
    result = analyze_strict_forward_readiness_feasibility(
        plan(bridge=True), policy(), max_results=5
    )
    assert result["research_only"] is True
    assert result["deployment_authorized"] is False
