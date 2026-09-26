from __future__ import annotations
import json
from pathlib import Path
import pytest
from ml.data.stage_c_dataset_qualification import (
    StageCDatasetQualificationError,
    build_acquisition_plan,
    validate_catalog,
)

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "ml" / "data" / "manifests" / "stage-c-dataset-candidates-v1.json"

def load():
    return json.loads(CATALOG.read_text(encoding="utf-8"))

def test_catalog_is_valid():
    assert validate_catalog(load())["stage"] == "C"

def test_recommended_pair_is_source_independent():
    result = build_acquisition_plan(load())
    assert result["source_independent"] is True
    assert result["development"]["source_id"] != result["final_holdout"]["source_id"]

def test_recommended_pair_has_strict_temporal_order():
    result = build_acquisition_plan(load())
    assert result["strict_temporal_order"]["satisfied"] is True
    assert result["strict_temporal_order"]["final_start"] > result["strict_temporal_order"]["development_end"]

def test_final_holdout_exceeds_low_fpr_resolution_minimum():
    result = build_acquisition_plan(load())
    assert result["final_holdout"]["expected_class_counts"]["legitimate"] >= 381
    assert result["final_holdout"]["expected_class_counts"]["phishing"] >= 1

def test_task3_does_not_authorize_download_or_training():
    result = build_acquisition_plan(load())
    assert result["downloads_authorized"] is False
    assert result["model_training_authorized"] is False
    assert result["deployment_authorized"] is False

def test_final_holdout_use_is_locked_before_freeze():
    result = build_acquisition_plan(load())
    prohibited = set(result["final_holdout"]["prohibited_uses_before_final_freeze"])
    assert {"MODEL_SELECTION", "CALIBRATION", "THRESHOLD_SELECTION", "MODEL_SCORING"} <= prohibited

def test_same_source_pair_is_rejected():
    data = load()
    by_id = {x["candidate_id"]: x for x in data["candidates"]}
    final_id = data["recommended_pair"]["final_holdout_candidate_id"]
    dev_id = data["recommended_pair"]["development_candidate_id"]
    by_id[final_id]["source_id"] = by_id[dev_id]["source_id"]
    with pytest.raises(StageCDatasetQualificationError, match="source_id"):
        build_acquisition_plan(data)
