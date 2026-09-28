from copy import deepcopy
from pathlib import Path

import pytest

import ml.data.stage_c_final_holdout_feature_extraction as mod
from ml.data.stage_c_final_holdout_feature_extraction import (
    StageCFinalHoldoutFeatureExtractionError,
)


def r(sample, label, artifact):
    return {
        "sample_id": sample,
        "label": label,
        "html_member_name": f"All_HTML/{sample}.txt",
        "html_sha256": artifact,
    }


def test_task31_authorization_hash_is_frozen():
    assert mod.EXPECTED_TASK31_AUTHORIZATION_SHA256 == (
        "f53787f6131cdb868b1ee1b55618fece41738353f9be7db7d6f9aa7abab37d04"
    )


def test_clean_scope_is_frozen():
    assert mod.EXPECTED_CLEAN_SAMPLE_COUNT == 12711
    assert mod.EXPECTED_CLEAN_CLASS_COUNTS == {
        "legitimate": 7609,
        "phishing": 5102,
    }


def test_feature_contract_is_exact_27():
    assert len(mod.EXPECTED_FEATURES) == 27
    assert len(set(mod.EXPECTED_FEATURES)) == 27
    assert mod.EXPECTED_FEATURES[0] == "document_started"
    assert mod.EXPECTED_FEATURES[-1] == "purpose_observed"


def test_batches_are_deterministic():
    rows = [
        r("c", 0, "c" * 64),
        r("a", 1, "a" * 64),
        r("b", 0, "b" * 64),
    ]
    a = mod.build_replay_batches(rows, batch_size=2)
    b = mod.build_replay_batches(list(reversed(rows)), batch_size=2)
    assert [
        (x["batch_id"], [y["sample_id"] for y in x["rows"]])
        for x in a
    ] == [
        (x["batch_id"], [y["sample_id"] for y in x["rows"]])
        for x in b
    ]


def test_batches_reject_duplicate_exact_html():
    rows = [
        r("a", 0, "a" * 64),
        r("b", 0, "a" * 64),
    ]
    with pytest.raises(
        StageCFinalHoldoutFeatureExtractionError,
        match="duplicate exact HTML",
    ):
        mod.build_replay_batches(rows, batch_size=2)


def test_batch_size_never_exceeds_collector_limit():
    rows = [r("a", 0, "a" * 64)]
    with pytest.raises(StageCFinalHoldoutFeatureExtractionError):
        mod.build_replay_batches(rows, batch_size=513)


def test_memory_plan_blinds_ground_truth():
    batch = {
        "batch_id": "batch-test",
        "rows": [
            r("phish", 1, "a" * 64),
            r("legit", 0, "b" * 64),
        ],
    }
    plan = mod._memory_plan(batch, wait_ms=250)
    assert [x["ground_truth"] for x in plan["items"]] == [0, 0]
    assert "stage-c-task32-" in plan["plan_id"]


def test_memory_plan_contains_no_raw_url_or_html():
    batch = {
        "batch_id": "batch-test",
        "rows": [r("a", 1, "a" * 64)],
    }
    item = mod._memory_plan(batch, wait_ms=250)["items"][0]
    assert set(item) == {
        "sample_id", "ground_truth", "artifact_sha256", "wait_ms"
    }
    assert "url" not in item
    assert "html_base64" not in item


def test_feature_row_closed_schema():
    row = {
        "sample_id": "s",
        "label": 1,
        "feature_vector": [0] * 27,
        "collection_incomplete": False,
        "dropped_events": 0,
        "delivery_errors": 0,
        "history_truncated": False,
    }
    mod._validate_feature_row(row)
    bad = deepcopy(row)
    bad["raw_url"] = "https://example.invalid"
    with pytest.raises(
        StageCFinalHoldoutFeatureExtractionError,
        match="prohibited",
    ):
        mod._validate_feature_row(bad)


def test_feature_row_rejects_nonfinite():
    row = {
        "sample_id": "s",
        "label": 0,
        "feature_vector": [0] * 26 + [float("nan")],
        "collection_incomplete": False,
        "dropped_events": 0,
        "delivery_errors": 0,
        "history_truncated": False,
    }
    with pytest.raises(StageCFinalHoldoutFeatureExtractionError):
        mod._validate_feature_row(row)


def test_collection_loss_must_be_explicit():
    row = {
        "sample_id": "s",
        "label": 0,
        "feature_vector": [0] * 27,
        "collection_incomplete": False,
        "dropped_events": 1,
        "delivery_errors": 0,
        "history_truncated": False,
    }
    with pytest.raises(
        StageCFinalHoldoutFeatureExtractionError,
        match="collection-incomplete",
    ):
        mod._validate_feature_row(row)


def test_no_model_scoring_or_training_dependency():
    source = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in source
    assert "predict_proba" not in source
    assert ".fit(" not in source
    assert "pickle.load" not in source
    assert "joblib.load" not in source


def test_state_declares_model_access_locked():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"model_loading_authorized": False' in source
    assert '"model_scoring_authorized": False' in source
    assert '"metrics_authorized": False' in source
    assert '"threshold_change_authorized": False' in source


def test_incomplete_rows_are_precommitted_out_of_scoring():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"incomplete_rows_scoring_authorized": False' in source
    assert '"evaluation_candidate_policy": "COLLECTION_COMPLETE_ONLY"' in source


def test_raw_html_is_memory_streamed_only():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "base64.b64encode(payload)" in source
    assert "write_bytes(payload)" not in source
    assert '"raw_html_materialized_to_disk": False' in source


def test_frozen_text_is_immutable(tmp_path):
    path = tmp_path / "x.json"
    assert mod._atomic_frozen_text(path, b"one\n") == "CREATED"
    assert mod._atomic_frozen_text(path, b"one\n") == "EXISTING_MATCH"
    with pytest.raises(StageCFinalHoldoutFeatureExtractionError):
        mod._atomic_frozen_text(path, b"two\n")
