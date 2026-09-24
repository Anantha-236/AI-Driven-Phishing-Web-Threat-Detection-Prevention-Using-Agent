from __future__ import annotations

import copy
import hashlib
import json

import pytest

from ml.training.stage_b_benchmark import benchmark_stage_b_models
from ml.training.stage_b_calibration import calibrate_stage_b_model
from ml.training.stage_b_final_evaluation import (
    FINAL_EVALUATION_SCHEMA,
    FinalEvaluationError,
    final_evaluate_stage_b_model,
)


def h(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def feature_dataset():
    names = ["signal_a", "signal_b", "signal_c"]
    parts = {}
    dates = {
        "train": "2026-01-01T00:00:00Z",
        "selection": "2026-02-01T00:00:00Z",
        "calibration": "2026-03-01T00:00:00Z",
        "test": "2026-04-01T00:00:00Z",
    }
    counts = {"train": 60, "selection": 30, "calibration": 40, "test": 20}
    for partition in ("train", "selection", "calibration", "test"):
        rows = []
        for i in range(counts[partition]):
            label = i % 2
            if label:
                vector = [0.72 + (i % 7) * 0.025, 0.65 + (i % 3) * 0.03, 0.18]
            else:
                vector = [0.12 + (i % 7) * 0.025, 0.22 + (i % 3) * 0.02, 0.78]
            suffix = f"{partition}-{i}"
            rows.append({
                "sample_id": f"sample-{suffix}",
                "partition": partition,
                "ground_truth": label,
                "artifact_group": f"artifact-{suffix}",
                "domain_group": f"domain-{suffix}.example",
                "brand_group": f"brand-{suffix}",
                "source_groups": [f"source-{suffix}"],
                "observed_at": dates[partition],
                "events_sha256": hashlib.sha256(suffix.encode()).hexdigest(),
                "collection_provenance": "REAL_BROWSER",
                "feature_vector": vector,
            })
        parts[partition] = {"records": rows, "sample_count": len(rows)}
    return {
        "schema_version": "stage-b-feature-dataset-1",
        "representation": "contextual-flat",
        "feature_version": "context-features-1",
        "feature_names": names,
        "feature_contract_sha256": h(
            {"feature_version": "context-features-1", "feature_names": names}
        ),
        "extractor_source_sha256": "2" * 64,
        "episode_set_sha256": "3" * 64,
        "split_schema": "stage-b-splits-1",
        "partitions": parts,
    }


def readiness(data):
    return {
        "schema_version": "stage-b-readiness-audit-1",
        "status": "PASS",
        "training_allowed": True,
        "policy_sha256": "4" * 64,
        "feature_dataset_sha256": h(data),
        "feature_dataset_identity": {
            "feature_version": data["feature_version"],
            "feature_contract_sha256": data["feature_contract_sha256"],
            "extractor_source_sha256": data["extractor_source_sha256"],
            "episode_set_sha256": data["episode_set_sha256"],
        },
        "issues": [],
    }


def chain():
    data = feature_dataset()
    gate = readiness(data)
    benchmark = benchmark_stage_b_models(data, gate)
    calibration = calibrate_stage_b_model(data, gate, benchmark)
    return data, gate, benchmark, calibration


def test_final_evaluation_opens_test_only_after_reproducing_calibration_chain():
    data, gate, benchmark, calibration = chain()
    result = final_evaluate_stage_b_model(data, gate, benchmark, calibration)
    assert result["schema_version"] == FINAL_EVALUATION_SCHEMA
    assert result["status"] == "PASS"
    assert result["reproduced_calibration_scores_sha256"] == calibration["calibration_scores_sha256"]
    assert result["data_usage"]["final_evaluation_partition"] == "test"
    assert result["data_usage"]["test_used_for_threshold_selection"] is False
    assert result["threshold_free_metrics"]["sample_count"] == 20


def test_final_threshold_is_exactly_the_calibration_selected_primary_candidate():
    data, gate, benchmark, calibration = chain()
    result = final_evaluate_stage_b_model(data, gate, benchmark, calibration)
    primary_cap = calibration["threshold_selection"]["primary_fpr_cap"]
    expected = calibration["threshold_selection"]["operating_points"][f"fpr_le_{primary_cap:g}"]["threshold"]
    assert result["fixed_operating_point"]["threshold"] == expected
    assert result["fixed_operating_point"]["threshold_source"] == "CALIBRATION_ONLY"


def test_test_labels_or_vectors_cannot_change_selected_threshold():
    data, gate, benchmark, calibration = chain()
    first = final_evaluate_stage_b_model(data, gate, benchmark, calibration)

    changed = copy.deepcopy(data)
    for row in changed["partitions"]["test"]["records"]:
        row["feature_vector"] = [1.0 - row["feature_vector"][0], 0.5, 0.5]
        row["ground_truth"] = 1 - row["ground_truth"]

    changed_gate = readiness(changed)
    changed_benchmark = benchmark_stage_b_models(changed, changed_gate)
    changed_calibration = calibrate_stage_b_model(changed, changed_gate, changed_benchmark)
    second = final_evaluate_stage_b_model(changed, changed_gate, changed_benchmark, changed_calibration)

    assert first["fixed_operating_point"]["threshold"] == second["fixed_operating_point"]["threshold"]
    assert first["selected_candidate"] == second["selected_candidate"]
    assert first["test_score_sha256"] != second["test_score_sha256"]


def test_rejects_feature_dataset_mutation_against_frozen_chain():
    data, gate, benchmark, calibration = chain()
    changed = copy.deepcopy(data)
    changed["partitions"]["test"]["records"][0]["feature_vector"][0] += 0.01
    with pytest.raises(FinalEvaluationError, match="content hash"):
        final_evaluate_stage_b_model(changed, gate, benchmark, calibration)


def test_rejects_tampered_calibration_score_hash():
    data, gate, benchmark, calibration = chain()
    changed = copy.deepcopy(calibration)
    changed["calibration_scores_sha256"] = "0" * 64
    with pytest.raises(FinalEvaluationError, match="reproduced calibration scores"):
        final_evaluate_stage_b_model(data, gate, benchmark, changed)


def test_unauthorized_calibration_threshold_remains_research_only_on_test():
    data, gate, benchmark, calibration = chain()
    assert calibration["threshold_selection"]["deployment_threshold_authorized"] is False
    result = final_evaluate_stage_b_model(data, gate, benchmark, calibration)
    assert result["fixed_operating_point"]["calibration_deployment_authorized"] is False
    assert any(w["code"] == "OPERATING_POINT_NOT_DEPLOYMENT_AUTHORIZED" for w in result["warnings"])


def test_final_report_is_deterministic_for_fixed_inputs():
    data, gate, benchmark, calibration = chain()
    first = final_evaluate_stage_b_model(data, gate, benchmark, calibration)
    second = final_evaluate_stage_b_model(data, gate, benchmark, calibration)
    assert first == second
