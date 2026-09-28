from pathlib import Path
import json

import pytest

import ml.evaluation.stage_c_selection_label_evaluation_authorization as mod
from ml.evaluation.stage_c_selection_label_evaluation_authorization import (
    StageCSelectionEvaluationAuthorizationError,
)


def test_schema_and_frozen_task14_identities():
    assert mod.AUTH_SCHEMA == "stage-c-selection-label-evaluation-authorization-1"
    assert mod.EXPECTED_TASK14_SCORE_DATASET_SHA256 == (
        "92bc6429d8a61f3aeed206967c9df526e60388859e742be5eaa3ea0faad822d8"
    )
    assert mod.EXPECTED_TASK14_SCORING_MANIFEST_SHA256 == (
        "430654bf68aed282069bd21cc65b454e54c6782dcd31a1a811994ac06a565f1f"
    )


def test_selection_label_counts_are_frozen():
    assert mod.EXPECTED_SELECTION_COUNT == 20710
    assert mod.EXPECTED_SELECTION_LABEL_COUNTS == {
        "legitimate": 19641,
        "phishing": 1069,
    }


def test_score_row_count_is_frozen():
    assert mod.EXPECTED_SCORE_ROWS == 82840


def test_candidate_set_is_fixed():
    assert mod.EXPECTED_CANDIDATES == (
        "dummy_prior",
        "hist_gradient_boosting",
        "logistic_regression",
        "random_forest_compact",
    )


def test_score_scan_rejects_duplicate_pair(tmp_path):
    path = tmp_path / "scores.jsonl"
    row = {
        "sample_id": "a",
        "candidate_id": "dummy_prior",
        "phishing_probability": 0.5,
    }
    path.write_text(
        json.dumps(row) + "\n" + json.dumps(row) + "\n",
        encoding="utf-8",
    )
    fake = {
        cid: {"score_vector_sha256": "0" * 64}
        for cid in mod.EXPECTED_CANDIDATES
    }
    with pytest.raises(StageCSelectionEvaluationAuthorizationError, match="duplicate"):
        mod.scan_score_dataset(path, fake)


def test_evaluation_input_identity_binds_labels_and_scores(monkeypatch):
    monkeypatch.setattr(mod, "EXPECTED_SCORE_ROWS", 8)
    labels = [
        {"sample_id": "a", "label": 0},
        {"sample_id": "b", "label": 1},
    ]
    rows = {
        cid: [
            {"sample_id": "a", "phishing_probability": 0.1},
            {"sample_id": "b", "phishing_probability": 0.9},
        ]
        for cid in mod.EXPECTED_CANDIDATES
    }
    a = mod.build_evaluation_input_identity(labels=labels, rows_by_candidate=rows)
    changed = [dict(x) for x in labels]
    changed[0]["label"] = 1
    b = mod.build_evaluation_input_identity(labels=changed, rows_by_candidate=rows)
    assert a != b


def test_task15_module_computes_no_model_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "average_precision_score" not in src
    assert "roc_auc_score" not in src
    assert "brier_score_loss" not in src
    assert "log_loss(" not in src
    assert "confusion_matrix" not in src
    assert "precision_recall_curve" not in src
    assert "roc_curve(" not in src


def test_model_selection_remains_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"model_selection_authorized": False' in src
    assert '"candidate_selected": False' in src
    assert '"candidate_ranking": True' in src
    assert '"candidate_choice": True' in src


def test_threshold_freeze_remains_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_freeze_authorized": False' in src
    assert '"threshold_freeze": True' in src


def test_calibration_and_holdout_remain_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"calibration_fitting_authorized": False' in src
    assert '"calibration_access": True' in src
    assert '"final_holdout_touched": False' in src
    assert '"final_holdout_access": True' in src


def test_no_final_holdout_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCSelectionEvaluationAuthorizationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})
