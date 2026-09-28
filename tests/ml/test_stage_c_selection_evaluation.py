from pathlib import Path
import math

import numpy as np
import pytest

import ml.evaluation.stage_c_selection_evaluation as mod
from ml.evaluation.stage_c_selection_evaluation import StageCSelectionEvaluationError


def test_schema_and_task15_authorization_are_frozen():
    assert mod.EVALUATION_SCHEMA == "stage-c-selection-evaluation-1"
    assert mod.EXPECTED_AUTHORIZATION_SHA256 == (
        "d70f1ec228a91beba90a424528eaa3e0cda5a0a59213e5b0ee8a4adce42fb491"
    )


def test_selection_identities_are_frozen():
    assert mod.EXPECTED_SELECTION_COUNT == 20710
    assert mod.EXPECTED_SELECTION_LABEL_VECTOR_SHA256 == (
        "691d1e47db54666978079e5df7f9968bc6c705d40fbf0903f9d46a48efc04511"
    )
    assert mod.EXPECTED_EVALUATION_INPUT_SHA256 == (
        "19364663b75166b6fcdc9bd0a24fe8cfe102a3fae80920cd7fe7027082778d33"
    )


def test_candidate_order_is_fixed_not_performance_order():
    assert mod.EXPECTED_CANDIDATES == (
        "dummy_prior",
        "hist_gradient_boosting",
        "logistic_regression",
        "random_forest_compact",
    )


def test_wilson_zero_fp_is_positive_and_below_one_percent_for_full_selection():
    upper = mod.wilson_upper_95(0, 19641)
    assert 0.0 < upper < 0.01


def test_wilson_rejects_invalid_counts():
    with pytest.raises(StageCSelectionEvaluationError, match="invalid"):
        mod.wilson_upper_95(2, 1)


def test_low_fpr_sweep_has_non_frozen_diagnostic_point():
    y = np.asarray([0] * 1000 + [1] * 100, dtype=int)
    scores = np.asarray([0.01] * 1000 + [0.9] * 100, dtype=float)
    result = mod.low_fpr_diagnostic_sweep(y, scores)
    point = result["diagnostic_max_recall_point_under_primary_constraint"]
    assert result["constraint_feasible"] is True
    assert point["recall"] == 1.0
    assert point["fp"] == 0
    assert point["threshold_frozen"] is False
    assert point["diagnostic_only"] is True


def test_low_fpr_sweep_hash_is_deterministic():
    y = np.asarray([0, 0, 1, 1], dtype=int)
    scores = np.asarray([0.1, 0.2, 0.8, 0.9], dtype=float)
    a = mod.low_fpr_diagnostic_sweep(y, scores)
    b = mod.low_fpr_diagnostic_sweep(y, scores)
    assert a["sweep_sha256"] == b["sweep_sha256"]


def test_low_fpr_sweep_uses_gte_rule():
    y = np.asarray([0, 1], dtype=int)
    scores = np.asarray([0.5, 0.5], dtype=float)
    result = mod.low_fpr_diagnostic_sweep(y, scores)
    assert result["threshold_rule"] == "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD"


def test_candidate_evaluation_metrics_are_finite(monkeypatch):
    monkeypatch.setattr(mod, "EXPECTED_SELECTION_COUNT", 6)
    y = np.asarray([0, 0, 0, 1, 1, 1], dtype=int)
    scores = np.asarray([0.05, 0.10, 0.20, 0.80, 0.90, 0.95], dtype=float)
    result = mod.evaluate_candidate(y, scores, "logistic_regression")
    assert all(math.isfinite(x) for x in result["metrics"].values())
    assert result["candidate_rank"] is None
    assert result["candidate_selected"] is False
    assert result["threshold_frozen"] is False


def test_module_contains_no_candidate_ranking_implementation():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"candidate_ranking_performed": False' in src
    assert '"candidate_selected": False' in src
    assert '"candidate_rank": None' in src
    assert "sorted(candidate_evaluations" not in src
    assert "max(candidate_evaluations" not in src
    assert "min(candidate_evaluations" not in src


def test_module_does_not_freeze_threshold():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_frozen": False' in src
    assert 'diagnostic["diagnostic_only"] = True' in src


def test_module_does_not_refit_models():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".fit(" not in src
    assert "pickle.load" not in src
    assert "predict_proba" not in src


def test_calibration_and_holdout_are_not_accessed():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"calibration_fitting_authorized": false' in src
    assert '"final_holdout_touched": false' in src
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_refuses_drift(tmp_path):
    path = tmp_path / "report.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCSelectionEvaluationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_primary_contract_is_one_percent_with_95_percent_confidence():
    assert mod.EXPECTED_PRIMARY_FPR_CAP == 0.01
    assert mod.EXPECTED_CONFIDENCE_LEVEL == 0.95
