from pathlib import Path
import math

import numpy as np
import pytest

import ml.evaluation.stage_c_calibration_evaluation as mod
from ml.evaluation.stage_c_calibration_evaluation import StageCCalibrationEvaluationError


def test_schema_and_task21_authorization_are_frozen():
    assert mod.EVALUATION_SCHEMA == "stage-c-calibration-evaluation-1"
    assert mod.EXPECTED_AUTHORIZATION_SHA256 == (
        "7fc833b8fb9e4a8d90d744102e38fcc7fbcbd2bf7e572b51c0fb36b9198bb518"
    )


def test_all_frozen_hash_constants_are_full_lower_hex():
    values = [
        mod.EXPECTED_AUTHORIZATION_SHA256,
        mod.EXPECTED_SCORE_DATASET_SHA256,
        mod.EXPECTED_SCORE_VECTOR_SHA256,
        mod.EXPECTED_LABEL_VECTOR_SHA256,
        mod.EXPECTED_EVALUATION_INPUT_SHA256,
        mod.EXPECTED_SAMPLE_SET_SHA256,
        mod.EXPECTED_FEATURE_DATASET_SHA256,
    ]
    for value in values:
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_calibration_counts_are_frozen():
    assert mod.EXPECTED_CALIBRATION_COUNT == 7314
    assert mod.EXPECTED_LABEL_COUNTS == {
        "legitimate": 5584,
        "phishing": 1730,
    }


def test_wilson_zero_fp_is_below_one_percent():
    upper = mod.wilson_upper_95(0, 5584)
    assert 0.0 < upper < 0.01


def test_wilson_rejects_invalid_counts():
    with pytest.raises(StageCCalibrationEvaluationError, match="invalid"):
        mod.wilson_upper_95(2, 1)


def test_low_fpr_sweep_has_non_frozen_diagnostic_point(monkeypatch):
    monkeypatch.setattr(mod, "EXPECTED_CALIBRATION_COUNT", 1100)
    y = np.asarray([0] * 1000 + [1] * 100, dtype=int)
    scores = np.asarray([0.01] * 1000 + [0.9] * 100, dtype=float)
    result = mod.low_fpr_threshold_sweep(y, scores)
    point = result["diagnostic_max_recall_point_under_primary_constraint"]
    assert result["constraint_feasible"] is True
    assert point["recall"] == 1.0
    assert point["fp"] == 0
    assert point["threshold_selected"] is False
    assert point["threshold_frozen"] is False
    assert point["diagnostic_only"] is True


def test_low_fpr_sweep_hash_is_deterministic(monkeypatch):
    monkeypatch.setattr(mod, "EXPECTED_CALIBRATION_COUNT", 4)
    y = np.asarray([0, 0, 1, 1], dtype=int)
    scores = np.asarray([0.1, 0.2, 0.8, 0.9], dtype=float)
    a = mod.low_fpr_threshold_sweep(y, scores)
    b = mod.low_fpr_threshold_sweep(y, scores)
    assert a["sweep_sha256"] == b["sweep_sha256"]


def test_low_fpr_sweep_uses_gte_rule(monkeypatch):
    monkeypatch.setattr(mod, "EXPECTED_CALIBRATION_COUNT", 2)
    y = np.asarray([0, 1], dtype=int)
    scores = np.asarray([0.5, 0.5], dtype=float)
    result = mod.low_fpr_threshold_sweep(y, scores)
    assert result["threshold_rule"] == "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD"


def test_calibration_metrics_are_finite(monkeypatch):
    monkeypatch.setattr(mod, "EXPECTED_CALIBRATION_COUNT", 6)
    y = np.asarray([0, 0, 0, 1, 1, 1], dtype=int)
    scores = np.asarray([0.05, 0.10, 0.20, 0.80, 0.90, 0.95], dtype=float)
    result = mod.evaluate_calibration(y, scores)
    assert all(math.isfinite(x) for x in result["metrics"].values())
    assert result["threshold_selected"] is False
    assert result["threshold_frozen"] is False


def test_task22_does_not_select_or_freeze_threshold():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_selected": False' in src
    assert '"threshold_frozen": False' in src
    assert 'diagnostic["diagnostic_only"] = True' in src


def test_task22_does_not_refit_or_score_model():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".fit(" not in src
    assert "pickle.load" not in src
    assert "predict_proba" not in src


def test_task22_computes_only_authorized_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "average_precision_score" in src
    assert "roc_auc_score" in src
    assert "brier_score_loss" in src
    assert "log_loss" in src


def test_holdout_remains_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"final_holdout_touched": false' in src
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_refuses_drift(tmp_path):
    path = tmp_path / "report.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCCalibrationEvaluationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_threshold_selection_authorization():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "ISSUE_STAGE_C_THRESHOLD_SELECTION_AUTHORIZATION_FROM_FROZEN_"
        in src
    )
