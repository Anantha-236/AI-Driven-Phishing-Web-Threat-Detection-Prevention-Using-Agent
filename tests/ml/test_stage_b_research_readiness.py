from __future__ import annotations

import hashlib
import json

import pytest

from ml.data.stage_b_research_readiness import (
    ResearchReadinessError,
    audit_research_replay_readiness,
)


def contract_hash(version, names):
    return hashlib.sha256(
        json.dumps(
            {"feature_version": version, "feature_names": names},
            sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def feature_dataset():
    partitions = {}
    dates = {
        "train": "2026-01-01T00:00:00Z",
        "selection": "2026-02-01T00:00:00Z",
        "calibration": "2026-03-01T00:00:00Z",
        "test": "2026-04-01T00:00:00Z",
    }
    for p_index, partition in enumerate(("train", "selection", "calibration", "test")):
        rows = []
        for label in (0, 1):
            for index in range(2):
                suffix = f"{partition}-{label}-{index}"
                rows.append({
                    "sample_id": suffix,
                    "partition": partition,
                    "ground_truth": label,
                    "artifact_group": f"artifact-{suffix}",
                    "domain_group": f"domain-{suffix}",
                    "brand_group": f"brand-{suffix}",
                    "source_groups": ["single-archive-source"],
                    "observed_at": dates[partition],
                    "events_sha256": f"{p_index + label + index + 1:064x}"[-64:],
                    "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
                    "feature_vector": [1, 0, 1],
                })
        partitions[partition] = {"records": rows, "sample_count": len(rows)}
    names = ["a", "b", "c"]
    return {
        "schema_version": "stage-b-feature-dataset-1",
        "representation": "contextual-flat",
        "feature_version": "context-features-1",
        "feature_names": names,
        "feature_contract_sha256": contract_hash("context-features-1", names),
        "extractor_source_sha256": "2" * 64,
        "episode_set_sha256": "3" * 64,
        "partitions": partitions,
    }


def policy():
    return {
        "schema_version": "stage-b-readiness-policy-1",
        "min_samples_per_class": {
            "train": 2, "selection": 2, "calibration": 2, "test": 2,
        },
        "allowed_provenance": {
            "train": ["ARCHIVED_BROWSER_REPLAY"],
            "selection": ["ARCHIVED_BROWSER_REPLAY"],
            "calibration": ["ARCHIVED_BROWSER_REPLAY"],
            "test": ["ARCHIVED_BROWSER_REPLAY"],
        },
        "require_strict_forward_test": True,
        "require_group_isolation": [
            "artifact_group", "domain_group", "brand_group"
        ],
        "notes": ["RESEARCH-ONLY archive replay readiness"],
    }


def test_research_readiness_pass_is_training_only_and_never_deployment_authority():
    result = audit_research_replay_readiness(feature_dataset(), policy())
    assert result["status"] == "PASS"
    assert result["training_allowed"] is True
    assert result["research_only"] is True
    assert result["deployment_authorized"] is False
    assert result["production_readiness_equivalent"] is False
    assert result["source_independence_relaxed"] is True


def test_research_readiness_refuses_non_archive_provenance_policy():
    bad = policy()
    bad["allowed_provenance"]["test"] = ["REAL_BROWSER"]
    with pytest.raises(ResearchReadinessError, match="only ARCHIVED_BROWSER_REPLAY"):
        audit_research_replay_readiness(feature_dataset(), bad)


def test_research_readiness_refuses_source_group_isolation_claim():
    bad = policy()
    bad["require_group_isolation"].append("source_groups")
    with pytest.raises(ResearchReadinessError, match="omit source_groups"):
        audit_research_replay_readiness(feature_dataset(), bad)
