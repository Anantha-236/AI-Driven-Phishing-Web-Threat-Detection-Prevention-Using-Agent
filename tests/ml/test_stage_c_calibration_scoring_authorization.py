from pathlib import Path
import json

import pytest

import ml.evaluation.stage_c_calibration_scoring_authorization as mod
from ml.evaluation.stage_c_calibration_scoring_authorization import (
    StageCCalibrationScoringAuthorizationError,
)


def test_schema_and_task18_selection_hash_are_frozen():
    assert mod.AUTH_SCHEMA == "stage-c-calibration-scoring-authorization-1"
    assert mod.EXPECTED_TASK18_SELECTION_RECORD_SHA256 == (
        "dffd5498523326c3272d32f50662a68f0671a6a51424bf8ebc2f75382eec0a10"
    )


def test_all_frozen_sha256_constants_are_full_lower_hex():
    values = [
        mod.EXPECTED_TASK18_SELECTION_RECORD_SHA256,
        mod.EXPECTED_SELECTED_ARTIFACT_SHA256,
        mod.EXPECTED_TASK17_AUTHORIZATION_SHA256,
        mod.EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
        mod.EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
        mod.EXPECTED_FEATURE_DATASET_SHA256,
    ]
    for value in values:
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_selected_candidate_is_logistic_regression():
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"
    assert mod.EXPECTED_SELECTED_CANDIDATE_FAMILY == "linear"


def test_calibration_scope_is_collection_complete_only():
    assert mod.EXPECTED_COMPLETE_CALIBRATION_COUNT == 7314
    assert mod.EXPECTED_INCOMPLETE_CALIBRATION_COUNT == 1


def test_derive_calibration_scope_does_not_reference_label_value():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    body = src[
        src.index("def derive_calibration_scope"):
        src.index("def _git_provenance")
    ]
    assert 'row["label"]' not in body
    assert '"label":' not in body


def test_task19_does_not_execute_model():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "predict_proba" not in src
    assert "predict(" not in src
    assert "pickle.load" not in src
    assert ".fit(" not in src


def test_task19_authorizes_only_selected_candidate_scoring():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"selected_candidate_loading_authorized": True' in src
    assert '"calibration_scoring_authorized": True' in src
    assert '"score_non_selected_candidate": True' in src


def test_calibration_labels_remain_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"calibration_label_access_authorized": False' in src
    assert '"calibration_labels_accessed": False' in src
    assert '"calibration_label_read": True' in src


def test_threshold_selection_remains_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_frozen": False' in src
    assert '"threshold_selection": True' in src
    assert '"threshold_freeze": True' in src


def test_selection_diagnostic_threshold_cannot_carry_over():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"selection_diagnostic_threshold_carryover_authorized": False' in src
    assert '"reuse_selection_diagnostic_threshold": True' in src


def test_selected_artifact_is_physically_sha_verified():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "sha256_file(artifact_path)" in src
    assert "artifact_path.stat().st_size" in src
    assert '"physical_artifact_verified": True' in src


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
    with pytest.raises(StageCCalibrationScoringAuthorizationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_feature_row_schema_still_contains_label_but_scope_excludes_it():
    assert "label" in mod.EXPECTED_FEATURE_ROW_FIELDS
    assert mod.EXPECTED_FEATURE_COUNT == 27


def test_authorization_action_is_label_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "CALIBRATION_FEATURES_WITH_LABELS_LOCKED" in src
