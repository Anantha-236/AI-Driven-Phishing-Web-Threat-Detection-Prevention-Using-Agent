from copy import deepcopy

import pytest

from ml.data.stage_b_manifest import (
    ManifestValidationError,
    validate_manifest_set,
    validate_sample_provenance,
    validate_source_manifest,
    validate_split_contract,
)


def valid_source_manifest():
    return {
        "schema_version": "stage-b-source-manifest-1",
        "dataset_id": "openphish-2026-09-24",
        "display_name": "OpenPhish snapshot",
        "source": {
            "provider": "OpenPhish",
            "homepage": "https://openphish.com/",
            "retrieval_url": "https://example.invalid/snapshot.txt",
            "retrieved_at": "2026-09-24T12:00:00Z",
            "content_sha256": "a" * 64,
            "provenance": "REAL",
            "collection_method": "PUBLIC_FEED",
            "independence_group": "openphish",
            "license": {
                "name": "Provider terms",
                "url": "https://example.invalid/terms",
                "redistributable": False,
                "research_use_allowed": True,
            },
        },
        "labeling": {
            "positive_class": "PHISHING",
            "negative_class": "LEGITIMATE",
            "label_source": "VERIFIED_SOURCE_REVIEW",
            "validation_reference": "provider-feed-and-stage-b-review-v1",
            "model_predictions_used_as_ground_truth": False,
        },
        "privacy": {
            "contains_raw_page_content": False,
            "contains_secrets": False,
            "pii_review_status": "REVIEWED",
        },
        "grouping": {
            "domain_group": "AVAILABLE",
            "brand_group": "PARTIAL",
            "time_group": "AVAILABLE",
            "source_group": "AVAILABLE",
        },
        "intended_use": ["TRAIN", "SELECTION", "CALIBRATION", "TEST"],
        "limitations": ["Feed inclusion does not prove completeness."],
    }


def valid_sample():
    return {
        "schema_version": "stage-b-sample-provenance-1",
        "sample_id": "sha256:url:1",
        "dataset_id": "openphish-2026-09-24",
        "ground_truth": 1,
        "label_source": "VERIFIED_SOURCE_REVIEW",
        "label_reference": "feed-row-1",
        "artifact_sha256": "b" * 64,
        "observed_at": "2026-09-24T11:00:00Z",
        "domain_group": "example.test",
        "brand_group": "example-brand",
        "source_group": "openphish",
    }


def valid_split_contract():
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


def test_accepts_complete_real_source_manifest():
    manifest = validate_source_manifest(valid_source_manifest())
    assert manifest["dataset_id"] == "openphish-2026-09-24"
    assert manifest["source"]["provenance"] == "REAL"


def test_rejects_model_predictions_as_ground_truth():
    manifest = valid_source_manifest()
    manifest["labeling"]["model_predictions_used_as_ground_truth"] = True
    with pytest.raises(ManifestValidationError, match="predictions"):
        validate_source_manifest(manifest)


def test_real_source_requires_hash_license_independence_and_timezone():
    manifest = valid_source_manifest()
    manifest["source"]["content_sha256"] = "not-a-hash"
    with pytest.raises(ManifestValidationError, match="SHA-256"):
        validate_source_manifest(manifest)

    manifest = valid_source_manifest()
    manifest["source"]["license"]["research_use_allowed"] = False
    with pytest.raises(ManifestValidationError, match="research use"):
        validate_source_manifest(manifest)

    manifest = valid_source_manifest()
    manifest["source"]["independence_group"] = ""
    with pytest.raises(ManifestValidationError, match="independence_group"):
        validate_source_manifest(manifest)

    manifest = valid_source_manifest()
    manifest["source"]["retrieved_at"] = "2026-09-24T12:00:00"
    with pytest.raises(ManifestValidationError, match="timezone"):
        validate_source_manifest(manifest)


def test_sample_provenance_is_closed_and_cannot_carry_secret_fields():
    source = validate_source_manifest(valid_source_manifest())
    sample = validate_sample_provenance(valid_sample(), {source["dataset_id"]: source})
    assert sample["ground_truth"] == 1

    unsafe = valid_sample()
    unsafe["password"] = "secret"
    with pytest.raises(ManifestValidationError, match="unexpected sample fields"):
        validate_sample_provenance(unsafe, {source["dataset_id"]: source})


def test_manifest_set_rejects_duplicate_dataset_or_content_identity():
    a = valid_source_manifest()
    b = deepcopy(a)
    b["dataset_id"] = "another-dataset"

    with pytest.raises(ManifestValidationError, match="content SHA-256"):
        validate_manifest_set([a, b])


def test_split_contract_locks_test_and_separates_model_selection_calibration_and_test():
    contract = validate_split_contract(valid_split_contract())
    assert contract["final_test_locked"] is True

    reused = valid_split_contract()
    reused["threshold_policy"]["threshold_selection_partition"] = "test"
    with pytest.raises(ManifestValidationError, match="final test"):
        validate_split_contract(reused)

    weak = valid_split_contract()
    weak["group_isolation"].remove("source_group")
    with pytest.raises(ManifestValidationError, match="source_group"):
        validate_split_contract(weak)
