from pathlib import Path
import json

import numpy as np
import pytest

import ml.evaluation.stage_c_selection_score_generation as mod
from ml.evaluation.stage_c_selection_score_generation import (
    StageCSelectionScoringError,
)


class FakeModel:
    classes_ = np.asarray([0, 1])

    def predict_proba(self, x):
        p = np.clip(x[:, 0].astype(float), 0.0, 1.0)
        return np.column_stack([1.0 - p, p])


def test_schema_and_frozen_task13_authorization():
    assert mod.SCORING_SCHEMA == "stage-c-selection-score-generation-1"
    assert mod.EXPECTED_AUTHORIZATION_SHA256 == (
        "a48f625c3b9c96fdebbd51729c197b1d9a87f2255f1a52db74715e4e1674a9c5"
    )


def test_selection_identity_is_frozen():
    assert mod.EXPECTED_SELECTION_COUNT == 20710
    assert mod.EXPECTED_SELECTION_SAMPLE_SET_SHA256 == (
        "0cc84274558ee32889b114633e14782fe14c9dd17e933b8faa929efeab65c0cd"
    )
    assert mod.EXPECTED_SELECTION_FEATURE_MATRIX_SHA256 == (
        "31b58dd8900bddac87a7b9bcf8916d539f8b2c4326bbfe2b45919d521b4d03b0"
    )


def test_expected_score_row_count():
    assert mod.EXPECTED_SCORE_ROWS == 82840


def test_probability_extraction_uses_positive_class():
    x = np.asarray([[0.1] + [0.0] * 26, [0.8] + [0.0] * 26])
    scores = mod.phishing_probabilities(FakeModel(), x, "fake")
    assert scores.tolist() == pytest.approx([0.1, 0.8])


def test_probability_extraction_rejects_wrong_classes():
    model = FakeModel()
    model.classes_ = np.asarray([0, 2])
    x = np.zeros((2, 27))
    with pytest.raises(StageCSelectionScoringError, match="class mapping"):
        mod.phishing_probabilities(model, x, "fake")


def test_score_dataset_schema_has_no_label():
    ids = ["a", "b"]
    vectors = {
        cid: np.asarray([0.1, 0.2], dtype=float)
        for cid in mod.EXPECTED_CANDIDATES
    }
    payload = mod.render_score_dataset(ids, vectors)
    rows = [
        json.loads(line)
        for line in payload.decode("utf-8").splitlines()
    ]
    assert len(rows) == 8
    assert set(rows[0]) == {
        "sample_id", "candidate_id", "phishing_probability"
    }
    assert all("label" not in row for row in rows)


def test_scorer_never_accesses_label_field():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert 'row["label"]' not in src
    assert "row.get(\"label\")" not in src
    assert "selection_labels_accessed\": False" in src


def test_scorer_does_not_import_or_compute_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "average_precision_score" not in src
    assert "roc_auc_score" not in src
    assert "confusion_matrix" not in src
    assert "precision_recall_curve" not in src
    assert "brier_score_loss" not in src
    assert "log_loss" not in src


def test_scorer_does_not_rank_or_choose_candidates():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"model_selection_authorized": False' in src
    assert '"candidate_selected": False' in src
    assert '"candidate_ranking": True' in src
    assert '"candidate_choice": True' in src


def test_calibration_threshold_holdout_stay_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"calibration_fitting_authorized": False' in src
    assert '"threshold_selection_authorized": False' in src
    assert '"final_holdout_touched": False' in src


def test_no_final_holdout_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_refuses_drift(tmp_path):
    path = tmp_path / "scores.jsonl"
    assert mod.atomic_frozen_bytes(path, b"x\n") == "CREATED"
    assert mod.atomic_frozen_bytes(path, b"x\n") == "EXISTING_MATCH"
    with pytest.raises(StageCSelectionScoringError, match="non-identical"):
        mod.atomic_frozen_bytes(path, b"y\n")


def test_candidate_set_sorted_and_fixed():
    assert mod.EXPECTED_CANDIDATES == (
        "dummy_prior",
        "hist_gradient_boosting",
        "logistic_regression",
        "random_forest_compact",
    )


def test_render_rejects_candidate_set_drift():
    with pytest.raises(StageCSelectionScoringError, match="candidate set"):
        mod.render_score_dataset(
            ["a"],
            {"dummy_prior": np.asarray([0.5])},
        )
