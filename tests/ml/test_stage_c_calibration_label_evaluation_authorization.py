from pathlib import Path
import json

import pytest

import ml.evaluation.stage_c_calibration_label_evaluation_authorization as mod
from ml.evaluation.stage_c_calibration_label_evaluation_authorization import (
    StageCCalibrationLabelEvaluationAuthorizationError,
)


def test_schema_and_task20_hashes_are_frozen():
    assert mod.AUTH_SCHEMA == (
        "stage-c-calibration-label-evaluation-authorization-1"
    )
    assert mod.EXPECTED_TASK20_SCORE_DATASET_SHA256 == (
        "2b4db7e3d47f52994cc67a6f660a1e8603b710c48458fffd5c5923ac35c762fa"
    )
    assert mod.EXPECTED_TASK20_SCORE_VECTOR_SHA256 == (
        "461dc8101677adf4964d4e8cbb8408d523a6c9523270f1978c803dc332e51467"
    )
    assert mod.EXPECTED_TASK20_SCORING_MANIFEST_SHA256 == (
        "913807455a49397e36458d54b9224f31d183a82e2b80cd7bf4e29318366a117d"
    )


def test_all_frozen_hash_constants_are_full_lower_hex():
    values = [
        mod.EXPECTED_TASK20_SCORE_DATASET_SHA256,
        mod.EXPECTED_TASK20_SCORE_VECTOR_SHA256,
        mod.EXPECTED_TASK20_SCORING_MANIFEST_SHA256,
        mod.EXPECTED_TASK19_AUTHORIZATION_SHA256,
        mod.EXPECTED_FEATURE_DATASET_SHA256,
        mod.EXPECTED_CALIBRATION_SAMPLE_SET_SHA256,
        mod.EXPECTED_SELECTED_ARTIFACT_SHA256,
    ]
    for value in values:
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_calibration_scope_is_frozen():
    assert mod.EXPECTED_CALIBRATION_COUNT == 7314
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"


def test_score_scanner_accepts_only_label_blind_schema(tmp_path):
    path = tmp_path / "scores.jsonl"
    rows = [
        {"sample_id": "a", "phishing_probability": 0.1},
        {"sample_id": "b", "phishing_probability": 0.9},
    ]
    path.write_text(
        "".join(
            json.dumps(x, separators=(",", ":")) + "\n"
            for x in rows
        ),
        encoding="utf-8",
    )
    old_count = mod.EXPECTED_CALIBRATION_COUNT
    old_set = mod.EXPECTED_CALIBRATION_SAMPLE_SET_SHA256
    old_vec = mod.EXPECTED_TASK20_SCORE_VECTOR_SHA256
    try:
        mod.EXPECTED_CALIBRATION_COUNT = 2
        mod.EXPECTED_CALIBRATION_SAMPLE_SET_SHA256 = mod.canonical_hash(
            ["a", "b"]
        )
        mod.EXPECTED_TASK20_SCORE_VECTOR_SHA256 = mod.canonical_hash(rows)
        out = mod.scan_calibration_scores(path)
        assert out["sample_ids"] == ["a", "b"]
    finally:
        mod.EXPECTED_CALIBRATION_COUNT = old_count
        mod.EXPECTED_CALIBRATION_SAMPLE_SET_SHA256 = old_set
        mod.EXPECTED_TASK20_SCORE_VECTOR_SHA256 = old_vec


def test_label_derivation_requires_calibration_complete_samples():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    body = src[
        src.index("def derive_calibration_labels"):
        src.index("def build_evaluation_input_identity")
    ]
    assert 'part != "calibration" or incomplete' in body


def test_task21_does_not_compute_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    for name in (
        "average_precision_score(",
        "roc_auc_score(",
        "brier_score_loss(",
        "log_loss(",
        "confusion_matrix(",
    ):
        assert name not in src


def test_task21_does_not_fit_or_score_model():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".fit(" not in src
    assert "predict_proba" not in src
    assert "pickle.load" not in src


def test_metric_computation_is_authorized_but_not_performed():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"calibration_metric_computation_authorized": True' in src
    assert '"calibration_metrics_computed": False' in src


def test_threshold_analysis_authorized_but_selection_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_analysis_authorized": True' in src
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_selected": False' in src
    assert '"threshold_frozen": False' in src


def test_selection_threshold_cannot_carry_over():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"reuse_selection_diagnostic_threshold": True' in src


def test_final_holdout_remains_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"final_holdout_touched": false' in src
    assert '"final_holdout_access": true' in src
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(
        StageCCalibrationLabelEvaluationAuthorizationError,
        match="non-identical",
    ):
        mod.frozen_write_json(path, {"x": 2})


def test_evaluation_input_identity_joins_score_and_label():
    labels = [
        {"sample_id": "a", "label": 0},
        {"sample_id": "b", "label": 1},
    ]
    scores = [
        {"sample_id": "a", "phishing_probability": 0.1},
        {"sample_id": "b", "phishing_probability": 0.9},
    ]
    expected = mod.canonical_hash([
        {"sample_id": "a", "label": 0, "phishing_probability": 0.1},
        {"sample_id": "b", "label": 1, "phishing_probability": 0.9},
    ])
    old_count = mod.EXPECTED_CALIBRATION_COUNT
    try:
        mod.EXPECTED_CALIBRATION_COUNT = 2
        assert mod.build_evaluation_input_identity(
            labels=labels,
            scores=scores,
        ) == expected
    finally:
        mod.EXPECTED_CALIBRATION_COUNT = old_count


def test_next_gate_is_evaluation_not_threshold_freeze():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "EVALUATE_STAGE_C_CALIBRATION_SCORES_AND_FREEZE_THRESHOLD_"
        in src
    )
    assert '"threshold_freeze_authorized": False' in src
