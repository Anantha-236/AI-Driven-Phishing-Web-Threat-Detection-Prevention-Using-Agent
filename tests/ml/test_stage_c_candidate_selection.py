from pathlib import Path

import pytest

import ml.evaluation.stage_c_candidate_selection as mod
from ml.evaluation.stage_c_candidate_selection import StageCCandidateSelectionError


def _evidence(recalls, feasible=None):
    if feasible is None:
        feasible = {cid: True for cid in mod.EXPECTED_CANDIDATES}
    rows = []
    for cid in mod.EXPECTED_CANDIDATES:
        rows.append({
            "candidate_id": cid,
            "family": "family-" + cid,
            "artifact_sha256": "a" * 64,
            "eligible_for_model_selection": mod.EXPECTED_ELIGIBILITY[cid],
            "primary_constraint_feasible": feasible[cid],
            "diagnostic_threshold_is_not_frozen": True,
            "diagnostic_sweep_sha256": "b" * 64,
            "diagnostic_observed_fpr": 0.005 if feasible[cid] else None,
            "diagnostic_wilson_upper_95": 0.006 if feasible[cid] else None,
            "diagnostic_recall": recalls.get(cid) if feasible[cid] else None,
            "diagnostic_precision": 0.5 if feasible[cid] else None,
            "diagnostic_fp": 10 if feasible[cid] else None,
            "diagnostic_tp": 20 if feasible[cid] else None,
        })
    return rows


def test_schema_and_task17_hash_are_frozen():
    assert mod.SELECTION_SCHEMA == "stage-c-candidate-selection-1"
    assert mod.EXPECTED_TASK17_AUTHORIZATION_SHA256 == (
        "416c29e333325b0f201eecde801fdc1ee05b966a8d84c78bd24a07a626ea34"
    )


def test_selection_evidence_hash_is_frozen():
    assert mod.EXPECTED_TASK17_SELECTION_EVIDENCE_SHA256 == (
        "95b13e1b9322fb914282e02608b139220964be132cd259b69b30ba755c48ec1b"
    )


def test_dummy_is_ineligible():
    assert mod.EXPECTED_ELIGIBILITY["dummy_prior"] is False
    assert all(
        mod.EXPECTED_ELIGIBILITY[cid] is True
        for cid in (
            "hist_gradient_boosting",
            "logistic_regression",
            "random_forest_compact",
        )
    )


def test_select_candidate_maximizes_recall_only_within_eligible_feasible_pool():
    rows = _evidence({
        "dummy_prior": 1.0,
        "hist_gradient_boosting": 0.2,
        "logistic_regression": 0.3,
        "random_forest_compact": 0.25,
    })
    selected = mod.select_candidate(rows)
    assert selected["selected_candidate_id"] == "logistic_regression"
    assert selected["selection_objective_value"] == 0.3


def test_infeasible_candidate_cannot_win_even_with_higher_recall():
    feasible = {cid: True for cid in mod.EXPECTED_CANDIDATES}
    feasible["logistic_regression"] = False
    rows = _evidence({
        "dummy_prior": 0.0,
        "hist_gradient_boosting": 0.2,
        "logistic_regression": 0.99,
        "random_forest_compact": 0.25,
    }, feasible)
    selected = mod.select_candidate(rows)
    assert selected["selected_candidate_id"] == "random_forest_compact"


def test_exact_max_recall_tie_fails_closed():
    rows = _evidence({
        "dummy_prior": 0.0,
        "hist_gradient_boosting": 0.3,
        "logistic_regression": 0.3,
        "random_forest_compact": 0.2,
    })
    with pytest.raises(StageCCandidateSelectionError, match="tie"):
        mod.select_candidate(rows)


def test_empty_eligible_feasible_pool_fails_closed():
    feasible = {cid: False for cid in mod.EXPECTED_CANDIDATES}
    rows = _evidence({
        cid: 0.1 for cid in mod.EXPECTED_CANDIDATES
    }, feasible)
    with pytest.raises(StageCCandidateSelectionError, match="no eligible"):
        mod.select_candidate(rows)


def test_selection_does_not_use_non_objective_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    select_src = src[src.index("def select_candidate"):src.index(
        "def validate_task12_manifest_and_artifact"
    )]
    assert "average_precision" not in select_src
    assert "roc_auc" not in select_src
    assert "brier_score" not in select_src
    assert "log_loss" not in select_src
    assert "diagnostic_precision" not in select_src


def test_selection_does_not_freeze_diagnostic_threshold():
    rows = _evidence({
        "dummy_prior": 0.0,
        "hist_gradient_boosting": 0.2,
        "logistic_regression": 0.3,
        "random_forest_compact": 0.25,
    })
    selected = mod.select_candidate(rows)
    assert selected["selection_diagnostic_threshold_frozen"] is False
    assert selected[
        "selection_diagnostic_threshold_authorized_for_calibration"
    ] is False
    assert "diagnostic_threshold" not in selected["selection_evidence"]


def test_task18_contains_no_model_execution():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert ".fit(" not in src
    assert "predict_proba" not in src
    assert "pickle.load" not in src


def test_calibration_threshold_and_holdout_stay_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"calibration_access_authorized": false' in src
    assert '"calibration_scoring_authorized": false' in src
    assert '"calibration_fitting_authorized": false' in src
    assert '"threshold_selection_authorized": false' in src
    assert '"threshold_frozen": false' in src
    assert '"final_holdout_touched": false' in src


def test_physical_artifact_is_sha_verified():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "sha256_file(artifact_path)" in src
    assert "artifact_path.stat().st_size" in src
    assert "physical_artifact_verified" in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "selection.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCCandidateSelectionError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_candidate_order_is_frozen():
    assert mod.EXPECTED_CANDIDATES == (
        "dummy_prior",
        "hist_gradient_boosting",
        "logistic_regression",
        "random_forest_compact",
    )


def test_primary_fpr_cap_is_frozen():
    assert mod.EXPECTED_PRIMARY_FPR_CAP == 0.01
