from pathlib import Path

import pytest

import ml.evaluation.stage_c_threshold_selection_authorization as mod
from ml.evaluation.stage_c_threshold_selection_authorization import (
    StageCThresholdSelectionAuthorizationError,
)


def test_schema_and_task22_hashes_are_frozen():
    assert mod.AUTH_SCHEMA == "stage-c-threshold-selection-authorization-1"
    assert mod.EXPECTED_TASK22_EVALUATION_REPORT_SHA256 == (
        "ea3de4d936246a5d7ead22851e0485cede762a63e417e5e583ab43617b167499"
    )
    assert mod.EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256 == (
        "b9e09ba9911adcba1072194ec7c7242b3fa9b34ecca19fa72efb21468ad78d6b"
    )


def test_all_frozen_hash_constants_are_full_lower_hex():
    for value in (
        mod.EXPECTED_TASK22_EVALUATION_REPORT_SHA256,
        mod.EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256,
        mod.EXPECTED_TASK21_AUTHORIZATION_SHA256,
    ):
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_candidate_and_constraint_are_frozen():
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"
    assert mod.EXPECTED_PRIMARY_FPR_CAP == 0.01
    assert mod.EXPECTED_CONFIDENCE_LEVEL == 0.95


def test_authorized_threshold_is_frozen_from_task22_evidence():
    point = mod.EXPECTED_DIAGNOSTIC_POINT
    assert point["threshold"] == 0.8637646437995518
    assert point["fp"] == 36
    assert point["tp"] == 310
    assert point["primary_constraint_satisfied"] is True
    assert point["diagnostic_only"] is True


def test_authorized_point_is_not_sentinel():
    assert (
        mod.EXPECTED_DIAGNOSTIC_POINT[
            "threshold_is_above_max_score_sentinel"
        ]
        is False
    )


def test_authorized_point_satisfies_fpr_constraints():
    point = mod.EXPECTED_DIAGNOSTIC_POINT
    assert point["observed_fpr"] <= mod.EXPECTED_PRIMARY_FPR_CAP
    assert point["wilson_upper_95"] <= mod.EXPECTED_PRIMARY_FPR_CAP


def test_task23_authorizes_selection_but_does_not_perform_it():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_authorized": True' in src
    assert '"threshold_selection_performed": False' in src
    assert '"threshold_selected": False' in src
    assert '"threshold_frozen": False' in src


def test_task23_allows_only_one_threshold_choice():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"selection_choice_count": 1' in src
    assert '"implicit_alternative_thresholds_authorized": False' in src
    assert '"recompute_threshold_sweep_authorized": False' in src


def test_task23_does_not_compute_metrics_or_rescore():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "average_precision_score" not in src
    assert "roc_auc_score" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src


def test_holdout_and_deployment_remain_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"final_holdout_touched": false' in src
    assert '"final_holdout_access": true' in src
    assert '"deployment": true' in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(
        StageCThresholdSelectionAuthorizationError,
        match="non-identical",
    ):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_threshold_freeze():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"next_gate": "FREEZE_STAGE_C_AUTHORIZED_THRESHOLD"' in src
