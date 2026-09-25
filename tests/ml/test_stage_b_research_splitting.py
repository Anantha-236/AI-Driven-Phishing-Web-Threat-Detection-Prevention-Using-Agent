from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ml.data.stage_b_research_splitting import (
    ResearchSplitError,
    construct_research_archive_splits,
    validate_research_split_contract,
)


def contract():
    return {
        "schema_version": "stage-b-research-split-contract-1",
        "protocol_id": "single-source-archive-replay-research-v1",
        "partition_order": ["train", "selection", "calibration", "test"],
        "group_isolation": ["artifact_sha256", "domain_group", "brand_group"],
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
        "notes": ["RESEARCH-ONLY single-source archive protocol"],
    }


def normalized_plan(count=16):
    items = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(count):
        items.append({
            "sample_id": f"sample-{index:03d}",
            "html_path": f"{index:03d}.html",
            "ground_truth": index % 2,
            "observed_at": (base + timedelta(days=index)).isoformat(),
            "artifact_sha256": f"{index + 1:064x}"[-64:],
            "domain_group": f"domain-{index}.example",
            "brand_group": f"brand-{index}",
            "source_group": "single-archive-source",
            "wait_ms": 500,
        })
    return {
        "schema_version": "stage-b-archive-replay-normalized-1",
        "plan_id": "research-test",
        "created_at": "2026-09-25T00:00:00Z",
        "dataset": {
            "dataset_id": "archive",
            "provider": "archive",
            "source_reference": "doi:test",
            "source_snapshot_sha256": "a" * 64,
            "independence_group": "single-archive-source",
            "license_reference": "research",
            "research_use_allowed": True,
        },
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "items": items,
        "safety_contract": {},
        "limitations": [],
    }


def test_contract_is_explicitly_non_deployable_and_omits_source_isolation():
    result = validate_research_split_contract(contract())
    assert result["source_independence_required"] is False
    assert result["deployment_authorized"] is False
    assert "source_group" not in result["group_isolation"]


def test_constructs_deterministic_four_way_research_split_from_one_source():
    first = construct_research_archive_splits(normalized_plan(), contract())
    second = construct_research_archive_splits(normalized_plan(), contract())
    assert first == second
    assert first["schema_version"] == "stage-b-splits-1"
    assert first["audit"]["research_only"] is True
    assert first["audit"]["deployment_authorized"] is False
    assert first["audit"]["source_independence_relaxed"] is True
    for payload in first["partitions"].values():
        assert {row["ground_truth"] for row in payload["records"]} == {0, 1}
        assert {tuple(row["source_groups"]) for row in payload["records"]} == {
            ("single-archive-source",)
        }


def test_artifact_domain_and_brand_never_cross_partitions():
    result = construct_research_archive_splits(normalized_plan(), contract())
    for field in ("artifact_group", "domain_group", "brand_group"):
        owners = {}
        for partition, payload in result["partitions"].items():
            for row in payload["records"]:
                value = row[field]
                assert value not in owners or owners[value] == partition
                owners[value] = partition


def test_final_test_is_strictly_later_than_non_test():
    result = construct_research_archive_splits(normalized_plan(), contract())
    test_times = [
        datetime.fromisoformat(row["observed_at"])
        for row in result["partitions"]["test"]["records"]
    ]
    non_test_times = [
        datetime.fromisoformat(row["observed_at"])
        for partition in ("train", "selection", "calibration")
        for row in result["partitions"][partition]["records"]
    ]
    assert min(test_times) > max(non_test_times)
    assert result["audit"]["strict_forward_test"] is True


def test_refuses_missing_brand_metadata_instead_of_silently_weakening_isolation():
    data = normalized_plan()
    data["items"][0]["brand_group"] = None
    with pytest.raises(ResearchSplitError, match="brand_group"):
        construct_research_archive_splits(data, contract())


def test_refuses_contract_that_accidentally_authorizes_deployment():
    bad = contract()
    bad["deployment_authorized"] = True
    with pytest.raises(ResearchSplitError, match="never authorize deployment"):
        validate_research_split_contract(bad)


def test_refuses_too_few_independent_components_for_four_partitions():
    with pytest.raises(ResearchSplitError, match="insufficient"):
        construct_research_archive_splits(normalized_plan(count=6), contract())

def test_temporal_bridge_component_is_quarantined_without_weakening_forward_test():
    data = normalized_plan(count=24)

    data["items"][2]["brand_group"] = "long-lived-shared-brand"
    data["items"][23]["brand_group"] = "long-lived-shared-brand"

    result = construct_research_archive_splits(data, contract())

    assert result["audit"]["strict_forward_test"] is True
    assert result["audit"]["chronology_bridge_component_count"] >= 1
    assert result["audit"]["chronology_bridge_sample_count"] >= 2
    assert result["excluded"]["upstream_quarantine_groups"]

    test_times = [
        datetime.fromisoformat(row["observed_at"])
        for row in result["partitions"]["test"]["records"]
    ]
    non_test_times = [
        datetime.fromisoformat(row["observed_at"])
        for partition in ("train", "selection", "calibration")
        for row in result["partitions"][partition]["records"]
    ]
    assert min(test_times) > max(non_test_times)

    supervised_brands = {
        row["brand_group"]
        for payload in result["partitions"].values()
        for row in payload["records"]
    }
    assert "long-lived-shared-brand" not in supervised_brands


def test_temporal_bridge_quarantine_remains_deterministic():
    data = normalized_plan(count=24)
    data["items"][2]["brand_group"] = "long-lived-shared-brand"
    data["items"][23]["brand_group"] = "long-lived-shared-brand"

    first = construct_research_archive_splits(data, contract())
    second = construct_research_archive_splits(data, contract())

    assert first == second
    assert first["excluded"]["upstream_quarantine_groups"] == second["excluded"]["upstream_quarantine_groups"]

