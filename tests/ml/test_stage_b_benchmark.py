from __future__ import annotations

import hashlib
import json

import pytest

from ml.training.stage_b_benchmark import (
    BENCHMARK_SCHEMA,
    BenchmarkError,
    benchmark_stage_b_models,
)


def h(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def feature_dataset():
    names = ["signal_a", "signal_b", "signal_c"]
    parts = {}
    dates = {
        "train": "2026-01-01T00:00:00Z",
        "selection": "2026-02-01T00:00:00Z",
        "calibration": "2026-03-01T00:00:00Z",
        "test": "2026-04-01T00:00:00Z",
    }
    counts = {"train": 40, "selection": 20, "calibration": 8, "test": 8}
    for p_index, partition in enumerate(["train", "selection", "calibration", "test"]):
        rows = []
        for i in range(counts[partition]):
            label = i % 2
            # learnable but not perfectly identical vectors
            if label:
                vector = [0.8 + (i % 5) * 0.02, 0.7, 0.2]
            else:
                vector = [0.1 + (i % 5) * 0.02, 0.2, 0.8]
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
        "feature_contract_sha256": h({"feature_version": "context-features-1", "feature_names": names}),
        "extractor_source_sha256": "2" * 64,
        "episode_set_sha256": "3" * 64,
        "split_schema": "stage-b-splits-1",
        "partitions": parts,
    }


def readiness(data=None):
    data = data or feature_dataset()
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


def candidate_metrics(result):
    return {
        row["candidate_id"]: row["selection_metrics"]
        for row in result["candidates"]
    }


def test_requires_passed_matching_readiness_gate():
    data = feature_dataset()
    gate = readiness(data)
    gate["training_allowed"] = False
    gate["status"] = "FAIL"
    gate["issues"] = [{"code": "INSUFFICIENT_CLASS_SAMPLES"}]
    with pytest.raises(BenchmarkError, match="has not authorized"):
        benchmark_stage_b_models(data, gate)

    gate = readiness(data)
    gate["feature_dataset_identity"]["episode_set_sha256"] = "9" * 64
    with pytest.raises(BenchmarkError, match="does not match"):
        benchmark_stage_b_models(data, gate)

    gate = readiness(data)
    gate["feature_dataset_sha256"] = "8" * 64
    with pytest.raises(BenchmarkError, match="contents"):
        benchmark_stage_b_models(data, gate)


def test_benchmark_uses_train_for_fit_and_selection_for_candidate_choice():
    data = feature_dataset()
    result = benchmark_stage_b_models(data, readiness(data))
    assert result["schema_version"] == BENCHMARK_SCHEMA
    assert result["status"] == "PASS"
    assert result["data_usage"]["fit_partition"] == "train"
    assert result["data_usage"]["candidate_selection_partition"] == "selection"
    assert result["data_usage"]["calibration_partition"] == "LOCKED_NOT_USED"
    assert result["data_usage"]["test_partition"] == "LOCKED_NOT_USED"
    assert result["selected_candidate"] in result["candidate_ranking"]
    assert "dummy_prior" not in result["candidate_ranking"]


def test_candidate_metrics_do_not_depend_on_calibration_or_test_vectors():
    data = feature_dataset()
    first = benchmark_stage_b_models(data, readiness(data))

    changed = json.loads(json.dumps(data))
    for partition in ("calibration", "test"):
        for row in changed["partitions"][partition]["records"]:
            row["feature_vector"] = [99.0, -77.0, 123.0]
            row["ground_truth"] = 1 - row["ground_truth"]
    second = benchmark_stage_b_models(changed, readiness(changed))

    assert first["selected_candidate"] == second["selected_candidate"]
    assert candidate_metrics(first) == candidate_metrics(second)


def test_benchmark_is_deterministic_for_fixed_protocol_seed():
    data = feature_dataset()
    first = benchmark_stage_b_models(data, readiness(data))
    second = benchmark_stage_b_models(data, readiness(data))
    assert first["benchmark_protocol_sha256"] == second["benchmark_protocol_sha256"]
    assert first["candidate_ranking"] == second["candidate_ranking"]
    assert candidate_metrics(first) == candidate_metrics(second)


def test_reports_empirical_fpr_resolution_without_claiming_deployment_threshold():
    data = feature_dataset()
    result = benchmark_stage_b_models(data, readiness(data))
    selected = next(row for row in result["candidates"] if row["candidate_id"] == result["selected_candidate"])
    low = selected["selection_metrics"]["low_fpr_screening"]
    assert low["legitimate_count"] == 10
    assert low["empirical_fpr_resolution"] == pytest.approx(0.1)
    assert low["operating_points"]["fpr_le_0.01"]["allowed_false_positives"] == 0
    assert "threshold" not in low["operating_points"]["fpr_le_0.01"]
    assert any(w["code"] == "FPR_CAP_BELOW_EMPIRICAL_RESOLUTION" for w in result["warnings"])


def test_selection_rule_is_threshold_free_and_baseline_is_diagnostic_only():
    data = feature_dataset()
    result = benchmark_stage_b_models(data, readiness(data))
    assert result["selection_rule"]["primary"] == "average_precision_max"
    assert result["selection_rule"]["partition_used"] == "selection"
    baseline = next(row for row in result["candidates"] if row["candidate_id"] == "dummy_prior")
    assert baseline["eligible_for_selection"] is False


def test_rejects_failed_or_tampered_feature_contract_before_fitting():
    data = feature_dataset()
    data["feature_names"] = list(reversed(data["feature_names"]))
    with pytest.raises(BenchmarkError, match="invalid feature dataset"):
        benchmark_stage_b_models(data, readiness(data))
