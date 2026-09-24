from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from ml.data.stage_b_splitting import SplitConstructionError, construct_stage_b_splits


def _record(index: int, label, source: str, day: int, *, domain=None, brand=None, artifact=None):
    return {
        "schema_version": "stage-b-ingested-record-1",
        "sample_id": f"sample-{index}",
        "dataset_id": f"dataset-{source}",
        "source_record_id": str(index),
        "source_group": source,
        "source_artifact_sha256": (f"{index + 1:064x}")[-64:],
        "ground_truth": label,
        "label_status": "VERIFIED_SOURCE_LABEL" if label in (0, 1) else "UNLABELED_CANDIDATE",
        "label_source": "VERIFIED_SOURCE_REVIEW" if label in (0, 1) else None,
        "observed_at": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)).isoformat(),
        "hostname": domain or f"host-{index}.example",
        "origin": f"https://{domain or f'host-{index}.example'}",
        "domain_group": domain or f"domain-{index}.example",
        "brand_group": brand or f"brand-{index}",
        "url_sha256": (f"{1000 + index:064x}")[-64:],
        "origin_path_sha256": (f"{2000 + index:064x}")[-64:],
        "redacted_url": f"https://{domain or f'host-{index}.example'}/login",
        "redistribution_allowed": False,
        "local_only": True,
        "rank": None,
        "artifact_group": artifact or f"artifact-{index}",
        "source_datasets": [f"dataset-{source}"],
        "source_groups": [source],
        "source_artifacts": [(f"{index + 1:064x}")[-64:]],
        "duplicate_count": 1,
    }


def _contract():
    return {
        "schema_version": "stage-b-split-contract-1",
        "partition_order": ["train", "selection", "calibration", "test"],
        "group_isolation": ["artifact_sha256", "domain_group", "brand_group", "source_group"],
        "chronology": {"field": "observed_at", "strict_forward_test": True},
        "threshold_policy": {
            "model_fit_partition": "train",
            "candidate_selection_partition": "selection",
            "probability_calibration_partition": "calibration",
            "threshold_selection_partition": "calibration",
            "final_evaluation_partition": "test",
        },
        "final_test_locked": True,
    }


def _reconciled():
    rows = []
    # Twelve independent source groups, alternating class, with the latest two
    # groups reserved by chronology for the final test. This provides enough
    # independent evidence for all four partitions without source reuse.
    for i in range(12):
        rows.append(_record(i, i % 2, f"source-{i}", i))
    rows.append(_record(99, None, "candidate-only", 20))
    return {
        "schema_version": "stage-b-reconciled-1",
        "stats": {},
        "records": rows,
        "quarantine": [],
        "limitations": [],
    }


def test_constructs_deterministic_four_way_split_and_excludes_unlabeled_candidates():
    a = construct_stage_b_splits(_reconciled(), _contract())
    b = construct_stage_b_splits(_reconciled(), _contract())

    assert a == b
    assert a["schema_version"] == "stage-b-splits-1"
    assert set(a["partitions"]) == {"train", "selection", "calibration", "test"}
    assert a["excluded"]["unlabeled_candidates"] == ["sample-99"]

    for name, partition in a["partitions"].items():
        labels = {row["ground_truth"] for row in partition["records"]}
        assert labels == {0, 1}, name


def test_near_duplicate_domain_brand_and_source_groups_never_cross_partitions():
    data = _reconciled()
    # Force two otherwise separate records into each isolation relationship.
    data["records"][0]["artifact_group"] = "artifact-shared"
    data["records"][1]["artifact_group"] = "artifact-shared"
    data["records"][2]["domain_group"] = "shared.example"
    data["records"][3]["domain_group"] = "shared.example"
    data["records"][4]["brand_group"] = "shared-brand"
    data["records"][5]["brand_group"] = "shared-brand"
    data["records"][6]["source_groups"] = ["shared-source"]
    data["records"][7]["source_groups"] = ["shared-source"]

    result = construct_stage_b_splits(data, _contract())
    by_sample = {
        row["sample_id"]: name
        for name, partition in result["partitions"].items()
        for row in partition["records"]
    }

    assert by_sample["sample-0"] == by_sample["sample-1"]
    assert by_sample["sample-2"] == by_sample["sample-3"]
    assert by_sample["sample-4"] == by_sample["sample-5"]
    assert by_sample["sample-6"] == by_sample["sample-7"]


def test_final_test_is_strictly_later_than_every_non_test_record():
    result = construct_stage_b_splits(_reconciled(), _contract())
    test_times = [datetime.fromisoformat(row["observed_at"]) for row in result["partitions"]["test"]["records"]]
    earlier_times = [
        datetime.fromisoformat(row["observed_at"])
        for name in ("train", "selection", "calibration")
        for row in result["partitions"][name]["records"]
    ]
    assert min(test_times) > max(earlier_times)
    assert result["audit"]["strict_forward_test"] is True


def test_refuses_to_split_one_source_group_across_four_partitions():
    data = _reconciled()
    for row in data["records"]:
        if row["ground_truth"] in (0, 1):
            row["source_groups"] = ["single-feed"]
    with pytest.raises(SplitConstructionError, match="four independent partitions"):
        construct_stage_b_splits(data, _contract())


def test_refuses_missing_group_or_time_metadata_for_labeled_records():
    data = _reconciled()
    data["records"][0]["domain_group"] = None
    with pytest.raises(SplitConstructionError, match="domain_group"):
        construct_stage_b_splits(data, _contract())

    data = _reconciled()
    data["records"][0]["observed_at"] = None
    with pytest.raises(SplitConstructionError, match="observed_at"):
        construct_stage_b_splits(data, _contract())


def test_test_partition_is_locked_and_not_eligible_for_fit_selection_or_calibration():
    result = construct_stage_b_splits(_reconciled(), _contract())
    policy = result["usage_policy"]
    assert policy["train"] == ["MODEL_FIT"]
    assert policy["selection"] == ["CANDIDATE_SELECTION"]
    assert policy["calibration"] == ["PROBABILITY_CALIBRATION", "THRESHOLD_SELECTION"]
    assert policy["test"] == ["FINAL_EVALUATION_ONLY"]
    assert result["audit"]["final_test_locked"] is True
