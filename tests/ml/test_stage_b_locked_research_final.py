from __future__ import annotations

from pathlib import Path

import pytest

from ml.training.stage_b_locked_research_final import (
    ResearchFinalError,
    acquire_final_test_lock,
    lock_path_for_dataset,
)


def chain():
    return {
        "feature_dataset_sha256": "a" * 64,
        "test_partition_identity_sha256": "b" * 64,
        "test_samples": 100,
        "benchmark": {"x": 1},
        "calibration": {"y": 2},
    }


def test_lock_path_is_dataset_specific(tmp_path: Path):
    first = lock_path_for_dataset(tmp_path, "a" * 64)
    second = lock_path_for_dataset(tmp_path, "b" * 64)
    assert first != second
    assert first.name == ("a" * 64) + ".json"


def test_final_test_lock_is_exclusive_and_fail_closed(tmp_path: Path):
    feature = tmp_path / "features.json"
    readiness = tmp_path / "readiness.json"
    task22 = tmp_path / "task22.json"
    policy = tmp_path / "policy.json"
    for path in (feature, readiness, task22, policy):
        path.write_text("{}\n", encoding="utf-8")

    lock = tmp_path / "locks" / (("a" * 64) + ".json")
    first = acquire_final_test_lock(
        path=lock,
        chain=chain(),
        feature_path=feature,
        readiness_path=readiness,
        task22_path=task22,
        calibration_policy_path=policy,
    )
    assert first["status"] == "PREPARED"
    assert lock.exists()

    with pytest.raises(ResearchFinalError, match="already locked/consumed"):
        acquire_final_test_lock(
            path=lock,
            chain=chain(),
            feature_path=feature,
            readiness_path=readiness,
            task22_path=task22,
            calibration_policy_path=policy,
        )


def test_invalid_dataset_hash_cannot_create_lock_path(tmp_path: Path):
    with pytest.raises(ResearchFinalError, match="invalid feature dataset hash"):
        lock_path_for_dataset(tmp_path, "short")
