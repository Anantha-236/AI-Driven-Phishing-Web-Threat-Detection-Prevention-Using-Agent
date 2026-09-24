from __future__ import annotations

import copy
import hashlib
import json

import pytest

from ml.data.stage_b_readiness import (
    DEFAULT_POLICY,
    ReadinessAuditError,
    audit_feature_dataset_readiness,
    validate_readiness_policy,
)


TEST_POLICY = copy.deepcopy(DEFAULT_POLICY)
TEST_POLICY["min_samples_per_class"] = {
    "train": 2, "selection": 2, "calibration": 2, "test": 2,
}


def contract_hash(version, names):
    return hashlib.sha256(
        json.dumps(
            {"feature_version": version, "feature_names": names},
            sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def dataset():
    parts = {}
    base_dates = {
        "train": "2026-01-01T00:00:00Z",
        "selection": "2026-02-01T00:00:00Z",
        "calibration": "2026-03-01T00:00:00Z",
        "test": "2026-04-01T00:00:00Z",
    }
    for p_index, partition in enumerate(["train", "selection", "calibration", "test"]):
        rows = []
        for label in (0, 1):
            for index in range(2):
                suffix = f"{partition}-{label}-{index}"
                rows.append({
                    "sample_id": f"sample-{suffix}",
                    "partition": partition,
                    "ground_truth": label,
                    "artifact_group": f"artifact-{suffix}",
                    "domain_group": f"domain-{suffix}.example",
                    "brand_group": f"brand-{suffix}",
                    "source_groups": [f"source-{suffix}"],
                    "observed_at": base_dates[partition],
                    "events_sha256": f"{p_index+1:064x}"[-64:],
                    "collection_provenance": "REAL_BROWSER",
                    "feature_vector": [1, 0, 1],
                })
        parts[partition] = {"records": rows, "sample_count": len(rows)}
    return {
        "schema_version": "stage-b-feature-dataset-1",
        "representation": "contextual-flat",
        "feature_version": "context-features-1",
        "feature_names": ["a", "b", "c"],
        "feature_contract_sha256": contract_hash("context-features-1", ["a", "b", "c"]),
        "extractor_source_sha256": "2" * 64,
        "episode_set_sha256": "3" * 64,
        "partitions": parts,
    }


def test_ready_dataset_passes_and_reports_identity_and_counts():
    result = audit_feature_dataset_readiness(dataset(), TEST_POLICY)
    assert result["status"] == "PASS"
    assert result["training_allowed"] is True
    assert result["counts"]["test"] == {"total": 4, "legitimate": 2, "phishing": 2}
    assert result["feature_dataset_identity"]["feature_version"] == "context-features-1"
    assert len(result["feature_dataset_sha256"]) == 64
    assert result["chronology"]["strict_forward"] is True


def test_fails_when_any_partition_lacks_required_class_samples():
    data = dataset()
    data["partitions"]["selection"]["records"] = [
        row for row in data["partitions"]["selection"]["records"] if row["ground_truth"] == 0
    ]
    result = audit_feature_dataset_readiness(data, TEST_POLICY)
    assert result["training_allowed"] is False
    assert any(i["code"] == "INSUFFICIENT_CLASS_SAMPLES" and i["partition"] == "selection" for i in result["issues"])


def test_detects_trans_partition_artifact_domain_brand_and_source_overlap():
    for field in ("artifact_group", "domain_group", "brand_group"):
        data = dataset()
        data["partitions"]["test"]["records"][0][field] = data["partitions"]["train"]["records"][0][field]
        result = audit_feature_dataset_readiness(data, TEST_POLICY)
        assert any(i["code"] == "GROUP_OVERLAP" and i["dimension"] == field for i in result["issues"])

    data = dataset()
    data["partitions"]["test"]["records"][0]["source_groups"] = list(data["partitions"]["train"]["records"][0]["source_groups"])
    result = audit_feature_dataset_readiness(data, TEST_POLICY)
    assert any(i["code"] == "GROUP_OVERLAP" and i["dimension"] == "source_groups" for i in result["issues"])


def test_unknown_brand_does_not_create_false_overlap():
    data = dataset()
    for partition in data["partitions"].values():
        for row in partition["records"]:
            row["brand_group"] = None
    result = audit_feature_dataset_readiness(data, TEST_POLICY)
    assert result["training_allowed"] is True


def test_final_test_requires_real_browser_and_strict_forward_time():
    data = dataset()
    data["partitions"]["test"]["records"][0]["collection_provenance"] = "CONTROLLED_BROWSER"
    result = audit_feature_dataset_readiness(data, TEST_POLICY)
    assert any(i["code"] == "DISALLOWED_PROVENANCE" and i["partition"] == "test" for i in result["issues"])

    data = dataset()
    data["partitions"]["test"]["records"][0]["observed_at"] = "2025-12-31T00:00:00Z"
    result = audit_feature_dataset_readiness(data, TEST_POLICY)
    assert any(i["code"] == "FINAL_TEST_NOT_STRICTLY_FORWARD" for i in result["issues"])


def test_policy_is_explicit_and_fail_closed():
    validate_readiness_policy(DEFAULT_POLICY)
    bad = copy.deepcopy(DEFAULT_POLICY)
    bad["min_samples_per_class"]["test"] = 0
    with pytest.raises(ReadinessAuditError, match="invalid minimum sample count"):
        validate_readiness_policy(bad)

    bad = copy.deepcopy(DEFAULT_POLICY)
    bad["require_group_isolation"].append("hostname")
    with pytest.raises(ReadinessAuditError, match="unsupported readiness isolation"):
        validate_readiness_policy(bad)

def test_default_benchmark_policy_does_not_authorize_tiny_fixture():
    result = audit_feature_dataset_readiness(dataset())
    assert result["training_allowed"] is False
    assert any(issue["code"] == "INSUFFICIENT_CLASS_SAMPLES" for issue in result["issues"])
