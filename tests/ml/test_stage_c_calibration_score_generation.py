from pathlib import Path
import json

import numpy as np
import pytest

import ml.evaluation.stage_c_calibration_score_generation as mod
from ml.evaluation.stage_c_calibration_score_generation import (
    StageCCalibrationScoringError,
)


class FakeModel:
    classes_ = np.asarray([0, 1])

    def predict_proba(self, x):
        p = np.clip(x[:, 0].astype(float), 0.0, 1.0)
        return np.column_stack([1.0 - p, p])


def test_schema_and_task19_authorization_are_frozen():
    assert mod.SCORING_SCHEMA == "stage-c-calibration-score-generation-1"
    assert mod.EXPECTED_AUTHORIZATION_SHA256 == (
        "d0ecd7710d8341077ff3cb428e11f1f632cd189a0fc5c36b438fcb9cb734bfeb"
    )


def test_all_frozen_hash_constants_are_full_lower_hex():
    values = [
        mod.EXPECTED_AUTHORIZATION_SHA256,
        mod.EXPECTED_FEATURE_DATASET_SHA256,
        mod.EXPECTED_SELECTED_ARTIFACT_SHA256,
        mod.EXPECTED_CALIBRATION_SAMPLE_SET_SHA256,
        mod.EXPECTED_CALIBRATION_FEATURE_MATRIX_SHA256,
    ]
    for value in values:
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_selected_candidate_identity_is_frozen():
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"
    assert mod.EXPECTED_SELECTED_CANDIDATE_FAMILY == "linear"
    assert mod.EXPECTED_CALIBRATION_COUNT == 7314


def test_probability_extraction_uses_positive_class():
    x = np.asarray([[0.1] + [0.0] * 26, [0.8] + [0.0] * 26])
    scores = mod.phishing_probabilities(FakeModel(), x)
    assert scores.tolist() == pytest.approx([0.1, 0.8])


def test_probability_extraction_rejects_wrong_classes():
    model = FakeModel()
    model.classes_ = np.asarray([0, 2])
    x = np.zeros((2, 27))
    with pytest.raises(StageCCalibrationScoringError, match="class mapping"):
        mod.phishing_probabilities(model, x)


def test_score_dataset_schema_is_label_blind():
    payload = mod.render_score_dataset(
        ["a", "b"],
        np.asarray([0.1, 0.9], dtype=float),
    )
    rows = [
        json.loads(line)
        for line in payload.decode("utf-8").splitlines()
    ]
    assert rows == [
        {"sample_id": "a", "phishing_probability": 0.1},
        {"sample_id": "b", "phishing_probability": 0.9},
    ]
    assert all("label" not in row for row in rows)


def test_feature_loader_never_reads_label_value():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    body = src[
        src.index("def load_calibration_features"):
        src.index("def _environment")
    ]
    assert 'row["label"]' not in body
    assert 'row.get("label")' not in body


def test_score_generation_does_not_compute_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    for name in (
        "average_precision_score",
        "roc_auc_score",
        "confusion_matrix",
        "precision_recall_curve",
        "brier_score_loss",
        "log_loss",
    ):
        assert name not in src


def test_score_generation_does_not_refit():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".fit(" not in src


def test_only_selected_candidate_path_is_constructed():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert 'f"{EXPECTED_SELECTED_CANDIDATE_ID}.pkl"' in src
    assert "EXPECTED_CANDIDATES" not in src


def test_labels_metrics_calibration_and_threshold_stay_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"calibration_label_access_authorized": False' in src
    assert '"calibration_labels_accessed": False' in src
    assert '"calibration_metrics_computed": False' in src
    assert '"calibration_fitting_authorized": False' in src
    assert '"calibration_fitting_performed": False' in src
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_selected": False' in src
    assert '"threshold_frozen": False' in src


def test_selection_diagnostic_threshold_cannot_carry_over():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"selection_diagnostic_threshold_carryover_authorized": False' in src
    assert '"reuse_selection_diagnostic_threshold": True' in src


def test_final_holdout_remains_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"final_holdout_touched": false' in src
    assert '"final_holdout_access": true' in src
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_output_refuses_drift(tmp_path):
    path = tmp_path / "scores.jsonl"
    assert mod.atomic_frozen_bytes(path, b"x\n") == "CREATED"
    assert mod.atomic_frozen_bytes(path, b"x\n") == "EXISTING_MATCH"
    with pytest.raises(StageCCalibrationScoringError, match="non-identical"):
        mod.atomic_frozen_bytes(path, b"y\n")


def test_render_rejects_length_mismatch():
    with pytest.raises(StageCCalibrationScoringError, match="length"):
        mod.render_score_dataset(
            ["a", "b"],
            np.asarray([0.1], dtype=float),
        )


def test_next_gate_is_label_evaluation_authorization():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "ISSUE_STAGE_C_CALIBRATION_LABEL_EVALUATION_AUTHORIZATION_" in src
