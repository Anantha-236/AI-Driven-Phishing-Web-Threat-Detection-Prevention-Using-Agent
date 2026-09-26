from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ml.data.stage_b_contextual_research_v2 import (
    construct_contextual_research_splits,
)


def contract():
    return {
        "schema_version": "stage-b-research-split-contract-2",
        "protocol_id": "single-source-contextual-archive-replay-research-v2",
        "partition_order": ["train", "selection", "calibration", "test"],
        "group_isolation": ["artifact_sha256", "domain_group"],
        "audit_only_groups": ["brand_group"],
        "chronology": {"field": "observed_at", "strict_forward_test": True},
        "threshold_policy": {
            "model_fit_partition": "train",
            "candidate_selection_partition": "selection",
            "probability_calibration_partition": "calibration",
            "threshold_selection_partition": "calibration",
            "final_evaluation_partition": "test",
        },
        "final_test_locked": True,
        "source_independence_required": False,
        "deployment_authorized": False,
        "brand_isolation_rationale": "brand_group is not model-observable in context-features-1",
        "notes": ["RESEARCH-ONLY"],
    }


def policy():
    return {
        "schema_version": "stage-b-readiness-policy-1",
        "min_samples_per_class": {
            "train": 4,
            "selection": 2,
            "calibration": 2,
            "test": 4,
        },
        "allowed_provenance": {
            name: ["ARCHIVED_BROWSER_REPLAY"]
            for name in ("train", "selection", "calibration", "test")
        },
        "require_strict_forward_test": True,
        "require_group_isolation": ["artifact_group", "domain_group"],
        "notes": ["RESEARCH-ONLY"],
    }


def plan():
    start = datetime(2023, 1, 1, tzinfo=timezone.utc)
    items = []
    # 40 records/class, unique artifact/domain but heavily repeated brand.
    for label in (0, 1):
        for i in range(40):
            items.append({
                "sample_id": f"s-{label}-{i}",
                "archive_path": f"{label}/{i}.html",
                "ground_truth": label,
                "domain_group": f"host-{label}-{i}.example",
                "brand_group": "microsoft" if label else "legitimate-brand",
                "source_group": "fixture-source",
                "artifact_sha256": hashlib_sha(label, i),
                "observed_at": (start + timedelta(hours=i * 2 + label)).isoformat(),
                "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
            })
    return {
        "schema_version": "stage-b-archive-replay-normalized-1",
        "plan_id": "fixture",
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "dataset": {
            "dataset_id": "fixture",
            "source_type": "ARCHIVE_DATASET",
            "independence_group": "fixture-source",
            "license_reference": "fixture",
            "research_use_acknowledged": True,
        },
        "items": items,
    }


def hashlib_sha(label, i):
    import hashlib
    return hashlib.sha256(f"{label}:{i}".encode()).hexdigest()


def test_v2_can_split_repeated_brands_when_artifact_domain_are_independent():
    result = construct_contextual_research_splits(plan(), contract(), policy())
    assert result["audit"]["protocol_id"].endswith("v2")
    assert result["audit"]["isolation_dimensions"] == [
        "artifact_group", "domain_group"
    ]
    assert result["audit"]["audit_only_dimensions"] == ["brand_group"]
    for name, minimum in {
        "train": 4, "selection": 2, "calibration": 2, "test": 4
    }.items():
        assert result["partitions"][name]["legitimate"] >= minimum
        assert result["partitions"][name]["phishing"] >= minimum


def test_brand_overlap_is_audited_not_rejected():
    result = construct_contextual_research_splits(plan(), contract(), policy())
    audit = result["audit"]["isolation_group_counts"]["brand_group_audit_only"]
    assert audit["cross_partition_brand_count"] >= 1


def test_final_test_is_strictly_forward():
    result = construct_contextual_research_splits(plan(), contract(), policy())
    assert result["audit"]["strict_forward_test"] is True
    assert (
        result["audit"]["non_test_max_observed_at"]
        < result["audit"]["test_min_observed_at"]
    )


def test_protocol_never_authorizes_deployment():
    result = construct_contextual_research_splits(plan(), contract(), policy())
    assert result["audit"]["research_only"] is True
    assert result["audit"]["deployment_authorized"] is False
    assert result["audit"]["production_readiness_equivalent"] is False
