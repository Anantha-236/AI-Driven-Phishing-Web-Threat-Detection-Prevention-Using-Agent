from __future__ import annotations

import hashlib
import json

import pytest

from ml.training.stage_b_benchmark import benchmark_stage_b_models
from ml.training.stage_b_calibration import (
    CALIBRATION_SCHEMA,
    CalibrationError,
    calibrate_stage_b_model,
    validate_calibration_policy,
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
    return data, gate, benchmark


def stable_core(result):
    return {
        "selected_candidate": result["selected_candidate"],
        "calibration_method": result["calibration_method"],
        "calibration_metrics": result["calibration_metrics"],
        "calibration_scores_sha256": result["calibration_scores_sha256"],
        "threshold_selection": result["threshold_selection"],
        "warnings": result["warnings"],
    }


def test_refits_fixed_selected_candidate_then_uses_calibration_only():
    data, gate, benchmark = chain()
    result = calibrate_stage_b_model(data, gate, benchmark)
    assert result["schema_version"] == CALIBRATION_SCHEMA
    assert result["status"] == "PASS"
    assert result["selected_candidate"] == benchmark["selected_candidate"]
    assert result["calibration_method"] == "sigmoid"
    assert result["data_usage"]["base_refit_partitions"] == ["train", "selection"]
    assert result["data_usage"]["calibration_partition"] == "calibration"
    assert result["data_usage"]["test_partition"] == "LOCKED_NOT_USED"
    assert result["feature_dataset_sha256"] == h(data)


def test_final_test_vectors_and_labels_cannot_change_calibration_result():
    data, gate, benchmark = chain()
    first = calibrate_stage_b_model(data, gate, benchmark)

    changed = json.loads(json.dumps(data))
    for row in changed["partitions"]["test"]["records"]:
        row["feature_vector"] = [9.0, -7.0, 12.0]
        row["ground_truth"] = 1 - row["ground_truth"]

    changed_gate = readiness(changed)
    changed_benchmark = benchmark_stage_b_models(changed, changed_gate)
    second = calibrate_stage_b_model(changed, changed_gate, changed_benchmark)
    assert stable_core(first) == stable_core(second)


def test_calibration_partition_is_actually_used():
    data, gate, benchmark = chain()
    first = calibrate_stage_b_model(data, gate, benchmark)

    changed = json.loads(json.dumps(data))
    for row in changed["partitions"]["calibration"]["records"]:
        row["feature_vector"] = [v * 0.5 for v in row["feature_vector"]]
    changed_gate = readiness(changed)
    changed_benchmark = benchmark_stage_b_models(changed, changed_gate)
    second = calibrate_stage_b_model(changed, changed_gate, changed_benchmark)

    assert first["calibration_scores_sha256"] != second["calibration_scores_sha256"]


def test_low_fpr_thresholds_are_not_authorized_when_resolution_is_too_coarse():
    data, gate, benchmark = chain()
    result = calibrate_stage_b_model(data, gate, benchmark)
    threshold = result["threshold_selection"]["operating_points"]["fpr_le_0.01"]
    assert threshold["empirical_fpr_resolution"] == pytest.approx(0.05)
    assert threshold["empirically_resolved"] is False
    assert threshold["deployment_authorized"] is False
    assert result["threshold_selection"]["deployment_threshold_authorized"] is False
    assert any(
        warning["code"] == "PRIMARY_FPR_THRESHOLD_NOT_STATISTICALLY_SUPPORTED"
        for warning in result["warnings"]
    )


def test_rejects_tampered_benchmark_or_readiness_chain():
    data, gate, benchmark = chain()
    changed = json.loads(json.dumps(benchmark))
    changed["selected_candidate"] = "dummy_prior"
    with pytest.raises(CalibrationError):
        calibrate_stage_b_model(data, gate, changed)

    changed = json.loads(json.dumps(gate))
    changed["policy_sha256"] = "9" * 64
    with pytest.raises(CalibrationError, match="readiness policy"):
        calibrate_stage_b_model(data, changed, benchmark)

    changed = json.loads(json.dumps(benchmark))
    changed["feature_dataset_sha256"] = "7" * 64
    with pytest.raises(CalibrationError, match="contents"):
        calibrate_stage_b_model(data, gate, changed)


def test_policy_locks_sigmoid_and_keeps_test_unavailable():
    policy = {
        "schema_version": "stage-b-calibration-policy-1",
        "method": "isotonic",
        "primary_fpr_cap": 0.01,
        "fpr_caps": [0.01],
        "confidence_level": 0.95,
        "require_confidence_supported_threshold": True,
        "refit_partitions": ["train", "selection"],
        "calibration_partition": "calibration",
        "test_partition": "LOCKED_NOT_USED",
    }
    with pytest.raises(CalibrationError, match="locked to sigmoid"):
        validate_calibration_policy(policy)

    policy["method"] = "sigmoid"
    policy["test_partition"] = "test"
    with pytest.raises(CalibrationError, match="final test must remain locked"):
        validate_calibration_policy(policy)


def test_output_is_deterministic_for_fixed_inputs():
    data, gate, benchmark = chain()
    first = calibrate_stage_b_model(data, gate, benchmark)
    second = calibrate_stage_b_model(data, gate, benchmark)
    assert stable_core(first) == stable_core(second)
