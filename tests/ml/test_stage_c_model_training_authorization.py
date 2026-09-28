from copy import deepcopy
from pathlib import Path

import pytest

import ml.data.stage_c_model_training_authorization as mod
from ml.data.stage_c_model_training_authorization import (
    StageCTrainingAuthorizationError,
)


def row(sid, part, label, incomplete=False):
    return {
        "sample_id": sid,
        "partition": part,
        "label": label,
        "feature_vector": [0] * 27,
        "collection_incomplete": incomplete,
        "dropped_events": 1 if incomplete else 0,
        "delivery_errors": 0,
        "history_truncated": False,
    }


def test_schema_and_frozen_modeling_identity():
    assert mod.AUTH_SCHEMA == "stage-c-model-training-authorization-1"
    assert mod.EXPECTED_MODELING_COUNT == 73770
    assert mod.EXPECTED_MODELING_SHA256 == (
        "451712b4b9f2584f228b4547fd70875f1e58c2888ff4e8352eb1f7544168a98b"
    )


def test_training_scope_is_complete_train_only():
    rows = [
        row("t0", "train", 0),
        row("t1", "train", 1),
        row("s0", "selection", 0),
        row("c0", "calibration", 0),
        row("x0", "train", 0, True),
    ]
    membership = {
        r["sample_id"]: {"partition": r["partition"], "label": r["label"]}
        for r in rows
    }
    scope = mod.derive_scope(rows, membership, enforce_frozen=False)
    assert scope["modeling_candidate_sample_count"] == 4
    assert scope["collection_incomplete_count"] == 1
    assert scope["authorized_train_sample_count"] == 2
    assert scope["authorized_train_label_counts"] == {
        "legitimate": 1, "phishing": 1
    }


def test_incomplete_row_is_not_in_train_identity():
    rows = [row("t0", "train", 0), row("x0", "train", 1, True)]
    membership = {
        r["sample_id"]: {"partition": r["partition"], "label": r["label"]}
        for r in rows
    }
    scope = mod.derive_scope(rows, membership, enforce_frozen=False)
    assert scope["authorized_train_sample_set_sha256"] == mod.canonical_hash(["t0"])


def test_duplicate_sample_rejected():
    rows = [row("x", "train", 0), row("x", "train", 0)]
    membership = {"x": {"partition": "train", "label": 0}}
    with pytest.raises(StageCTrainingAuthorizationError, match="duplicate"):
        mod.derive_scope(rows, membership, enforce_frozen=False)


def test_split_mismatch_rejected():
    rows = [row("x", "train", 0)]
    membership = {"x": {"partition": "selection", "label": 0}}
    with pytest.raises(StageCTrainingAuthorizationError, match="membership"):
        mod.derive_scope(rows, membership, enforce_frozen=False)


def test_hidden_collection_loss_rejected():
    bad = row("x", "train", 0)
    bad["dropped_events"] = 1
    membership = {"x": {"partition": "train", "label": 0}}
    with pytest.raises(StageCTrainingAuthorizationError, match="collection-loss"):
        mod.derive_scope([bad], membership, enforce_frozen=False)


def test_frozen_task10_hashes_present():
    assert len(mod.EXPECTED_FEATURE_DATASET_SHA256) == 64
    assert len(mod.EXPECTED_AUDIT_FILE_SHA256) == 64
    assert len(mod.EXPECTED_READINESS_FILE_SHA256) == 64
    assert mod.EXPECTED_INCOMPLETE_COUNT == 7


def test_modeling_partition_counts_match_task10():
    assert mod.EXPECTED_MODELING_PARTITION_COUNTS["train"]["total"] == 45746
    assert mod.EXPECTED_MODELING_PARTITION_COUNTS["selection"]["total"] == 20710
    assert mod.EXPECTED_MODELING_PARTITION_COUNTS["calibration"]["total"] == 7314


def test_authorization_module_has_no_training_implementation():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src


def test_no_final_holdout_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src
