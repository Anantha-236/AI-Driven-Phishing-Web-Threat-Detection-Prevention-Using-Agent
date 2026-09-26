from __future__ import annotations

import json
from pathlib import Path

import pytest

from ml.data.stage_c_dataset_registry import (
    StageCDatasetRegistryError,
    audit_dataset_registry,
    build_identity_index,
    validate_identity_index,
)
from ml.data.stage_c_protocol import STAGE_B_CONSUMED_TEST_SHA256


def records(prefix: str, count0: int, count1: int):
    out = []
    i = 0
    for label, count in ((0, count0), (1, count1)):
        for _ in range(count):
            i += 1
            out.append({
                "sample_id": f"{prefix}-sample-{i}",
                "artifact_group": f"{prefix}-artifact-{i}",
                "domain_group": f"{prefix}-domain-{i}",
                "ground_truth": label,
                "observed_at": f"2026-01-{(i % 27) + 1:02d}T00:00:00+00:00",
            })
    return out


def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def guard():
    return {
        "schema_version": "stage-c-consumed-test-guard-1",
        "stage": "B",
        "role": "CONSUMED_FINAL_TEST",
        "research_only": True,
        "reuse_as_stage_c_final_holdout_prohibited": True,
        "source_feature_dataset_sha256": "1" * 64,
        "test_partition_sha256": STAGE_B_CONSUMED_TEST_SHA256,
        "sample_count": 1,
        "class_counts": {"legitimate": 1, "phishing": 0},
        "identities": [{
            "sample_key_sha256": "2" * 64,
            "artifact_sha256": "3" * 64,
            "domain_group_sha256": "4" * 64,
            "events_sha256": "5" * 64,
            "ground_truth": 0,
            "observed_at": "2023-01-01T00:00:00+00:00",
        }],
        "identity_set_sha256": None,
        "privacy": {},
    }


def finalized_guard():
    from ml.data.stage_c_protocol import canonical_hash
    value = guard()
    value["identity_set_sha256"] = canonical_hash(value["identities"])
    return value


def protocol_ready():
    return {"status": "PASS", "model_training_authorized": False}


def test_identity_index_is_hashed_and_valid():
    index = build_identity_index(
        dataset_id="dev-a",
        source_id="source-a",
        role="DEVELOPMENT",
        records=records("dev", 2, 2),
    )
    validated = validate_identity_index(index)
    assert validated["sample_count"] == 4
    rendered = json.dumps(validated)
    assert "dev-sample-1" not in rendered
    assert "dev-artifact-1" not in rendered


def test_empty_registry_waits_instead_of_authorizing_training(tmp_path: Path):
    registry = {
        "schema_version": "stage-c-dataset-registry-1",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "development_datasets": [],
        "final_holdout": None,
    }
    result = audit_dataset_registry(
        protocol_readiness=protocol_ready(),
        consumed_guard=finalized_guard(),
        registry=registry,
        repo_root=tmp_path,
    )
    assert result["status"] == "WAITING"
    assert result["model_training_authorized"] is False
    assert "DEVELOPMENT_DATASET_NOT_REGISTERED" in result["blocking_reasons"]
    assert "FINAL_HOLDOUT_NOT_REGISTERED" in result["blocking_reasons"]


def test_final_holdout_requires_distinct_source(tmp_path: Path):
    dev = build_identity_index(
        dataset_id="dev-a", source_id="same-source", role="DEVELOPMENT",
        records=records("dev", 2, 2),
    )
    final = build_identity_index(
        dataset_id="final-a", source_id="same-source", role="FINAL_HOLDOUT",
        records=records("final", 381, 2),
    )
    write(tmp_path / "dev.json", dev)
    write(tmp_path / "final.json", final)
    registry = {
        "schema_version": "stage-c-dataset-registry-1",
        "stage": "C", "research_only": True, "deployment_authorized": False,
        "development_datasets": [{
            "dataset_id": "dev-a", "source_id": "same-source", "identity_index_path": "dev.json"
        }],
        "final_holdout": {
            "dataset_id": "final-a", "source_id": "same-source", "identity_index_path": "final.json"
        },
    }
    result = audit_dataset_registry(
        protocol_readiness=protocol_ready(), consumed_guard=finalized_guard(),
        registry=registry, repo_root=tmp_path,
    )
    assert result["status"] == "WAITING"
    assert "FINAL_HOLDOUT_SOURCE_NOT_INDEPENDENT" in result["blocking_reasons"]


def test_final_holdout_requires_low_fpr_resolution_capacity(tmp_path: Path):
    dev = build_identity_index(
        dataset_id="dev-a", source_id="dev-source", role="DEVELOPMENT",
        records=records("dev", 2, 2),
    )
    final = build_identity_index(
        dataset_id="final-a", source_id="final-source", role="FINAL_HOLDOUT",
        records=records("final", 380, 2),
    )
    write(tmp_path / "dev.json", dev)
    write(tmp_path / "final.json", final)
    registry = {
        "schema_version": "stage-c-dataset-registry-1", "stage": "C",
        "research_only": True, "deployment_authorized": False,
        "development_datasets": [{"dataset_id": "dev-a", "source_id": "dev-source", "identity_index_path": "dev.json"}],
        "final_holdout": {"dataset_id": "final-a", "source_id": "final-source", "identity_index_path": "final.json"},
    }
    result = audit_dataset_registry(
        protocol_readiness=protocol_ready(), consumed_guard=finalized_guard(),
        registry=registry, repo_root=tmp_path,
    )
    assert result["status"] == "WAITING"
    assert "FINAL_HOLDOUT_LOW_FPR_RESOLUTION_INSUFFICIENT" in result["blocking_reasons"]


def test_ready_registry_authorizes_research_training_only(tmp_path: Path):
    dev = build_identity_index(
        dataset_id="dev-a", source_id="dev-source", role="DEVELOPMENT",
        records=records("dev", 5, 5),
    )
    final = build_identity_index(
        dataset_id="final-a", source_id="final-source", role="FINAL_HOLDOUT",
        records=records("final", 381, 5),
    )
    write(tmp_path / "dev.json", dev)
    write(tmp_path / "final.json", final)
    registry = {
        "schema_version": "stage-c-dataset-registry-1", "stage": "C",
        "research_only": True, "deployment_authorized": False,
        "development_datasets": [{"dataset_id": "dev-a", "source_id": "dev-source", "identity_index_path": "dev.json"}],
        "final_holdout": {"dataset_id": "final-a", "source_id": "final-source", "identity_index_path": "final.json"},
    }
    result = audit_dataset_registry(
        protocol_readiness=protocol_ready(), consumed_guard=finalized_guard(),
        registry=registry, repo_root=tmp_path,
    )
    assert result["status"] == "PASS"
    assert result["model_training_authorized"] is True
    assert result["deployment_authorized"] is False
    assert result["next_gate"] == "BEGIN_STAGE_C_FEATURE_AND_MODEL_EXPERIMENTS"


def test_holdout_artifact_overlap_with_development_is_hard_failure(tmp_path: Path):
    dev_records = records("dev", 2, 2)
    final_records = records("final", 381, 2)
    final_records[0]["artifact_group"] = dev_records[0]["artifact_group"]
    dev = build_identity_index(
        dataset_id="dev-a", source_id="dev-source", role="DEVELOPMENT",
        records=dev_records,
    )
    final = build_identity_index(
        dataset_id="final-a", source_id="final-source", role="FINAL_HOLDOUT",
        records=final_records,
    )
    write(tmp_path / "dev.json", dev)
    write(tmp_path / "final.json", final)
    registry = {
        "schema_version": "stage-c-dataset-registry-1", "stage": "C",
        "research_only": True, "deployment_authorized": False,
        "development_datasets": [{"dataset_id": "dev-a", "source_id": "dev-source", "identity_index_path": "dev.json"}],
        "final_holdout": {"dataset_id": "final-a", "source_id": "final-source", "identity_index_path": "final.json"},
    }
    with pytest.raises(StageCDatasetRegistryError, match="artifact identity"):
        audit_dataset_registry(
            protocol_readiness=protocol_ready(), consumed_guard=finalized_guard(),
            registry=registry, repo_root=tmp_path,
        )
