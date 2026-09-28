from pathlib import Path

import pytest

import ml.evaluation.stage_c_threshold_freeze as mod
from ml.evaluation.stage_c_threshold_freeze import (
    StageCThresholdFreezeError,
)


def test_schema_and_task23_authorization_are_frozen():
    assert mod.FREEZE_SCHEMA == "stage-c-threshold-freeze-1"
    assert mod.EXPECTED_TASK23_AUTHORIZATION_SHA256 == (
        "81882cba37003f9e5907e93daae9ba02040ba027af718dd9bf57d1e23c302031"
    )


def test_all_frozen_hash_constants_are_full_lower_hex():
    for value in (
        mod.EXPECTED_TASK23_AUTHORIZATION_SHA256,
        mod.EXPECTED_TASK23_THRESHOLD_EVIDENCE_SHA256,
        mod.EXPECTED_TASK22_EVALUATION_REPORT_SHA256,
        mod.EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256,
        mod.EXPECTED_TASK18_SELECTION_RECORD_SHA256,
        mod.EXPECTED_SELECTED_ARTIFACT_SHA256,
    ):
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_frozen_candidate_identity_is_exact():
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"
    assert mod.EXPECTED_SELECTED_CANDIDATE_FAMILY == "linear"
    assert mod.EXPECTED_SELECTED_ARTIFACT_SHA256 == (
        "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"
    )


def test_frozen_threshold_is_exact():
    assert mod.EXPECTED_THRESHOLD == 0.8637646437995518
    assert mod.EXPECTED_THRESHOLD_POINT["fp"] == 36
    assert mod.EXPECTED_THRESHOLD_POINT["tp"] == 310


def test_frozen_threshold_satisfies_primary_constraint():
    point = mod.EXPECTED_THRESHOLD_POINT
    assert point["observed_fpr"] <= mod.EXPECTED_PRIMARY_FPR_CAP
    assert point["wilson_upper_95"] <= mod.EXPECTED_PRIMARY_FPR_CAP
    assert point["primary_constraint_satisfied"] is True


def test_frozen_threshold_is_not_sentinel():
    assert (
        mod.EXPECTED_THRESHOLD_POINT[
            "threshold_is_above_max_score_sentinel"
        ]
        is False
    )


def test_task24_freezes_selection_exactly_once():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_performed": True' in src
    assert '"threshold_selected": True' in src
    assert '"threshold_frozen": True' in src


def test_task24_freezes_candidate_threshold_pair_identity():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"candidate_threshold_pair_sha256": canonical_hash(frozen_pair)' in src
    assert '"artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256' in src
    assert '"threshold": EXPECTED_THRESHOLD' in src


def test_task24_does_not_execute_or_refit_model():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "predict_proba" not in src
    assert "pickle.load" not in src
    assert ".fit(" not in src


def test_threshold_reselection_and_artifact_substitution_are_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"artifact_substitution": True' in src
    assert '"threshold_reselection": True' in src
    assert '"threshold_change": True' in src


def test_final_holdout_still_untouched_and_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"final_holdout_touched": false' in src
    assert '"final_holdout_access": true' in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "record.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCThresholdFreezeError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_final_holdout_authorization():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "ISSUE_STAGE_C_FINAL_HOLDOUT_SCORING_AUTHORIZATION_FOR_FROZEN_"
        in src
    )
