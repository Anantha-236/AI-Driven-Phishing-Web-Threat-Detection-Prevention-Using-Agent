from pathlib import Path
import json

import pytest

import ml.evaluation.stage_c_selection_scoring_authorization as mod
from ml.evaluation.stage_c_selection_scoring_authorization import (
    StageCSelectionScoringAuthorizationError,
)


def test_schema_and_frozen_task12_identities():
    assert mod.AUTH_SCHEMA == "stage-c-selection-scoring-authorization-1"
    assert mod.EXPECTED_TASK12_TRAINING_MANIFEST_SHA256 == (
        "887903dfe3af05490c0f2cc89ad3bcc9afa20a1ac495a7e4ca9fdaca44369399"
    )
    assert mod.EXPECTED_TASK12_ARTIFACT_SET_SHA256 == (
        "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"
    )


def test_selection_count_is_frozen():
    assert mod.EXPECTED_SELECTION_COUNT == 20710
    assert mod.EXPECTED_SELECTION_CLASS_COUNTS == {
        "legitimate": 19641,
        "phishing": 1069,
    }


def test_candidate_set_is_exactly_task12_set():
    assert set(mod.EXPECTED_CANDIDATES) == {
        "dummy_prior",
        "logistic_regression",
        "hist_gradient_boosting",
        "random_forest_compact",
    }
    assert mod.EXPECTED_CANDIDATES["dummy_prior"][
        "eligible_for_later_selection"
    ] is False


def test_feature_scope_uses_no_label_in_matrix_identity(tmp_path, monkeypatch):
    rows = [
        {
            "sample_id": "a",
            "partition": "selection",
            "label": 0,
            "feature_vector": [0] * 27,
            "collection_incomplete": False,
            "dropped_events": 0,
            "delivery_errors": 0,
            "history_truncated": False,
        },
        {
            "sample_id": "b",
            "partition": "selection",
            "label": 1,
            "feature_vector": [1] * 27,
            "collection_incomplete": False,
            "dropped_events": 0,
            "delivery_errors": 0,
            "history_truncated": False,
        },
    ]
    path = tmp_path / "x.jsonl"
    path.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows),
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "sha256_file", lambda p: mod.EXPECTED_FEATURE_DATASET_SHA256)
    monkeypatch.setattr(mod, "EXPECTED_MODELING_COUNT", 2)
    monkeypatch.setattr(mod, "EXPECTED_MODELING_SHA256", mod.canonical_hash(["a", "b"]))
    monkeypatch.setattr(mod, "EXPECTED_TOTAL_ROWS", 2)
    monkeypatch.setattr(mod, "EXPECTED_SELECTION_COUNT", 2)
    monkeypatch.setattr(mod, "EXPECTED_INCOMPLETE_COUNT", 0)
    expected = mod.canonical_hash(["a", "b"])
    scope = mod.derive_selection_feature_scope(
        path, expected_selection_sample_set_sha256=expected
    )
    expected_matrix = mod.canonical_hash([
        {"sample_id": "a", "feature_vector": [0] * 27},
        {"sample_id": "b", "feature_vector": [1] * 27},
    ])
    assert scope["selection_feature_matrix_sha256"] == expected_matrix


def test_task13_module_does_not_load_pickle_or_score_models():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "pickle.load" not in src
    assert "pickle.loads" not in src
    assert ".predict(" not in src
    assert ".predict_proba(" not in src


def test_task13_module_does_not_compute_selection_metrics():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "average_precision_score" not in src
    assert "roc_auc_score" not in src
    assert "confusion_matrix" not in src
    assert "brier_score_loss" not in src
    assert "log_loss" not in src


def test_label_access_and_model_selection_are_locked_in_authorization_source():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"selection_label_access_authorized": False' in src
    assert '"model_selection_authorized": False' in src
    assert '"candidate_ranking": True' in src
    assert '"candidate_choice": True' in src


def test_calibration_threshold_and_holdout_remain_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"calibration_fitting_authorized": False' in src
    assert '"threshold_selection_authorized": False' in src
    assert '"final_holdout_touched": False' in src


def test_no_final_holdout_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCSelectionScoringAuthorizationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_candidate_artifact_verification_rejects_missing_artifact(tmp_path):
    manifest = {
        "schema_version": "stage-c-candidate-training-1",
        "status": "PASS",
    }
    with pytest.raises(StageCSelectionScoringAuthorizationError):
        mod.validate_task12_manifest(manifest, candidate_root=tmp_path)
