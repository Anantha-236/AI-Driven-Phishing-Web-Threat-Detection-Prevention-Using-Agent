from copy import deepcopy
from pathlib import Path
import json

import numpy as np
import pytest

import ml.training.stage_c_candidate_training as mod
from ml.training.stage_c_candidate_training import StageCCandidateTrainingError


def auth():
    return {
        "schema_version": "stage-c-model-training-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": True,
        "model_training_authorized": True,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": "FIT_MODEL_PARAMETERS_ON_COMPLETE_COLLECTION_TRAIN_ROWS",
        "training_scope": {
            "authorized_partition": "train",
            "authorized_sample_count": mod.EXPECTED_TRAIN_COUNT,
            "authorized_sample_set_sha256": mod.EXPECTED_TRAIN_SHA256,
            "authorized_label_counts": mod.EXPECTED_TRAIN_LABEL_COUNTS,
            "feature_count": 27,
            "model_observable_fields": ["feature_vector"],
            "supervision_metadata_fields": ["label"],
            "join_only_fields": ["sample_id"],
            "collection_incomplete_rows_authorized": False,
            "selection_partition_use_for_fitting_authorized": False,
            "calibration_partition_use_for_fitting_authorized": False,
            "threshold_selection_authorized": False,
            "final_holdout_authorized": False,
        },
        "modeling_universe": {
            "policy": "COLLECTION_COMPLETE_ONLY",
            "sample_count": mod.EXPECTED_MODELING_COUNT,
            "sample_set_sha256": mod.EXPECTED_MODELING_SHA256,
        },
        "excluded_collection_incomplete": {
            "sample_count": mod.EXPECTED_INCOMPLETE_COUNT,
            "model_fitting_authorized": False,
        },
        "identity_bindings": {
            "feature_dataset_sha256": mod.EXPECTED_FEATURE_DATASET_SHA256,
            "git_head": mod.EXPECTED_TASK11_GIT_HEAD,
        },
        "prohibitions": {
            "selection_labels_for_training": True,
            "calibration_labels_for_training": True,
            "model_scoring_during_training": True,
            "final_holdout_access": True,
        },
        "next_gate": "TRAIN_STAGE_C_CANDIDATE_MODELS_ON_AUTHORIZED_TRAIN_SUBSET",
    }


def test_candidate_protocol_is_fixed_and_has_no_scoring():
    p = mod.candidate_protocol()
    assert p["fit_partition"] == "train"
    assert p["selection_partition"] == "LOCKED_NOT_USED"
    assert p["calibration_partition"] == "LOCKED_NOT_USED"
    assert p["model_scoring_performed"] is False
    assert len(p["candidates"]) == 4


def test_candidate_ids_match_existing_stage_b_family_set():
    ids = [s.candidate_id for s in mod._candidate_specs()]
    assert ids == [
        "dummy_prior",
        "logistic_regression",
        "hist_gradient_boosting",
        "random_forest_compact",
    ]


def test_dummy_is_diagnostic_not_later_selection_candidate():
    specs = {s.candidate_id: s for s in mod._candidate_specs()}
    assert specs["dummy_prior"].eligible_for_later_selection is False
    assert all(
        specs[x].eligible_for_later_selection
        for x in ("logistic_regression", "hist_gradient_boosting", "random_forest_compact")
    )


def test_authorization_rejects_training_disabled():
    a = auth()
    a["model_training_authorized"] = False
    with pytest.raises(StageCCandidateTrainingError, match="model_training_authorized"):
        mod.validate_authorization(a)


def test_selection_and_calibration_fitting_are_statically_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert 'selection_partition_use_for_fitting_authorized") is False' in src
    assert 'calibration_partition_use_for_fitting_authorized") is False' in src


def test_fit_candidates_fits_only_and_freezes_four_models():
    x = np.vstack([
        np.zeros((20, 27), dtype=float),
        np.ones((20, 27), dtype=float),
    ])
    y = np.asarray([0] * 20 + [1] * 20, dtype=int)
    rows = mod.fit_candidates(x, y)
    assert len(rows) == 4
    assert {r["candidate_id"] for r in rows} == {
        "dummy_prior",
        "logistic_regression",
        "hist_gradient_boosting",
        "random_forest_compact",
    }
    assert all(len(r["artifact_sha256"]) == 64 for r in rows)
    assert all(r["artifact_size_bytes"] > 0 for r in rows)


def test_fit_rejects_wrong_feature_count():
    x = np.zeros((10, 26), dtype=float)
    y = np.asarray([0, 1] * 5, dtype=int)
    with pytest.raises(StageCCandidateTrainingError, match="27 features"):
        mod.fit_candidates(x, y)


def test_frozen_artifact_write_refuses_drift(tmp_path):
    path = tmp_path / "model.pkl"
    assert mod.atomic_frozen_bytes(path, b"one") == "CREATED"
    assert mod.atomic_frozen_bytes(path, b"one") == "EXISTING_MATCH"
    with pytest.raises(StageCCandidateTrainingError, match="non-identical"):
        mod.atomic_frozen_bytes(path, b"two")


def test_module_contains_no_prediction_or_selection_execution():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".predict(" not in src
    assert ".predict_proba(" not in src
    assert "average_precision_score" not in src
    assert "roc_auc_score" not in src
    assert "confusion_matrix" not in src


def test_no_final_holdout_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_expected_authorized_train_identity_is_frozen():
    assert mod.EXPECTED_TRAIN_COUNT == 45746
    assert mod.EXPECTED_TRAIN_SHA256 == (
        "50138895b65a7a4b1c5b7defd331e4fed715f88b281eca04edfd0f2e613124c4"
    )
    assert mod.EXPECTED_TRAIN_LABEL_COUNTS == {
        "legitimate": 22699,
        "phishing": 23047,
    }


def test_protocol_hash_reproduces():
    p = mod.candidate_protocol()
    expected = p.pop("candidate_protocol_sha256")
    assert mod.canonical_hash(p) == expected
