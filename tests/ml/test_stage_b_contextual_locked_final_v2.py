from __future__ import annotations

from pathlib import Path

import pytest

import ml.training.stage_b_contextual_locked_final_v2 as mod
from ml.training.stage_b_contextual_locked_final_v2 import (
    BRAND_ROLE,
    PROTOCOL_ID,
    ContextualLockedFinalError,
    _test_partition_fingerprint,
    build_lock_material,
    canonical_hash,
    create_or_validate_lock,
)


def test_lock_is_idempotent_for_identical_chain(tmp_path: Path):
    path = tmp_path / "final.lock.json"
    material = {
        "schema_version": "stage-b-contextual-final-test-lock-v2-1",
        "value": 1,
    }
    assert create_or_validate_lock(path, material) == "CREATED"
    assert (
        create_or_validate_lock(path, material)
        == "EXISTING_MATCH"
    )


def test_lock_rejects_different_chain(tmp_path: Path):
    path = tmp_path / "final.lock.json"
    create_or_validate_lock(
        path,
        {"schema_version": "x", "value": 1},
    )
    with pytest.raises(
        ContextualLockedFinalError,
        match="different evidence chain",
    ):
        create_or_validate_lock(
            path,
            {"schema_version": "x", "value": 2},
        )


def test_lock_material_binds_test_partition():
    material = build_lock_material(
        feature_data={"f": 1},
        readiness={"r": 2},
        task30_report={
            "selected_candidate": "random_forest_compact",
            "primary_research_operating_point": {
                "fpr_cap": 0.01,
                "threshold": 0.5,
            },
        },
        benchmark={"b": 3},
        calibration={"c": 4},
        policy={"p": 5},
        test_partition={
            "sample_count": 1917,
            "sha256": "a" * 64,
        },
    )
    assert material["test_partition_sample_count"] == 1917
    assert material["test_partition_sha256"] == "a" * 64
    assert material["repeated_tuning_prohibited"] is True


def test_canonical_hash_changes_when_threshold_changes():
    a = {"threshold": 0.5}
    b = {"threshold": 0.5001}
    assert canonical_hash(a) != canonical_hash(b)


def test_protocol_constants_remain_research_only():
    assert PROTOCOL_ID.endswith("-v2")
    assert BRAND_ROLE == "AUDIT_ONLY_NOT_MODEL_OBSERVABLE"


def test_fingerprint_uses_materialized_feature_vector_field():
    data = {
        "partitions": {
            "test": {
                "records": [
                    {
                        "sample_id": "sample-1",
                        "partition": "test",
                        "ground_truth": 1,
                        "feature_vector": [1.0, 0.0, 2.5],
                    }
                ]
            }
        }
    }
    result = _test_partition_fingerprint(data)
    assert result["sample_count"] == 1
    assert len(result["sha256"]) == 64

