from pathlib import Path

import pytest

import ml.evaluation.stage_c_model_selection_authorization as mod
from ml.evaluation.stage_c_model_selection_authorization import (
    StageCModelSelectionAuthorizationError,
)


def test_schema_and_task16_hashes_are_frozen():
    assert mod.AUTH_SCHEMA == "stage-c-model-selection-authorization-1"
    assert mod.EXPECTED_TASK16_EVALUATION_REPORT_SHA256 == (
        "e66cb4780fcd2d1141e3a47008ba6d1f414d8b49a706441484522a6eee5672b1"
    )
    assert mod.EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256 == (
        "24997e9b069f46318207b973cab29551acd3dba45405e260976e17af4f3542a4"
    )


def test_candidate_eligibility_excludes_dummy_only():
    assert mod.EXPECTED_ELIGIBILITY == {
        "dummy_prior": False,
        "hist_gradient_boosting": True,
        "logistic_regression": True,
        "random_forest_compact": True,
    }


def test_selection_policy_is_recall_subject_to_primary_constraint():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"secondary_objective": "MAXIMIZE_DIAGNOSTIC_RECALL"' in src
    assert '"require_constraint_feasible": True' in src
    assert '"observed_fpr_lte": EXPECTED_PRIMARY_FPR_CAP' in src
    assert '"wilson_upper_95_lte": EXPECTED_PRIMARY_FPR_CAP' in src


def test_selection_policy_has_fail_closed_tie_rule():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"tie_policy": "FAIL_CLOSED_NO_IMPLICIT_TIEBREAKER"' in src
    assert '"implicit_tiebreak": True' in src


def test_task17_does_not_select_candidate():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"model_selection_performed": False' in src
    assert '"candidate_selected": False' in src
    assert '"model_selection_authorized": True' in src


def test_task17_does_not_freeze_diagnostic_threshold():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"threshold_selection_authorized": False' in src
    assert '"threshold_frozen": False' in src
    assert '"freeze_selection_diagnostic_threshold": True' in src


def test_task17_does_not_rank_candidates():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"candidate_ranking_required": False' in src
    assert "sorted(evidence" not in src
    assert "max(evidence" not in src
    assert "min(evidence" not in src


def test_non_objective_metrics_are_descriptive_only():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    for name in (
        '"average_precision"',
        '"roc_auc"',
        '"brier_score"',
        '"log_loss"',
        '"precision"',
    ):
        assert name in src


def test_build_selection_evidence_preserves_candidate_order():
    evals = {}
    artifacts = {}
    for cid in mod.EXPECTED_CANDIDATES:
        evals[cid] = {
            "metrics": {
                "average_precision": 0.1,
                "roc_auc": 0.5,
                "brier_score": 0.2,
                "log_loss": 0.7,
            },
            "low_fpr_diagnostics": {
                "constraint_feasible": True,
                "sweep_sha256": "a" * 64,
                "diagnostic_max_recall_point_under_primary_constraint": {
                    "threshold": 0.9,
                    "observed_fpr": 0.001,
                    "wilson_upper_95": 0.002,
                    "recall": 0.1,
                    "precision": 0.5,
                    "fp": 1,
                    "tp": 2,
                },
            },
        }
        artifacts[cid] = {
            "family": "x",
            "artifact_sha256": "b" * 64,
            "eligible_for_later_selection": mod.EXPECTED_ELIGIBILITY[cid],
        }
    evidence = mod.build_selection_evidence(evals, artifacts)
    assert [x["candidate_id"] for x in evidence] == list(mod.EXPECTED_CANDIDATES)


def test_calibration_and_final_holdout_stay_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"calibration_access_authorized": false' in src
    assert '"calibration_fitting_authorized": false' in src
    assert '"final_holdout_touched": false' in src
    assert '"calibration_access": true' in src
    assert '"final_holdout_access": true' in src


def test_no_final_holdout_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCModelSelectionAuthorizationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_primary_fpr_cap_and_confidence_are_frozen():
    assert mod.EXPECTED_PRIMARY_FPR_CAP == 0.01
    assert mod.EXPECTED_CONFIDENCE_LEVEL == 0.95


def test_task17_contains_no_model_execution():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".fit(" not in src
    assert "predict_proba" not in src
    assert "pickle.load" not in src
