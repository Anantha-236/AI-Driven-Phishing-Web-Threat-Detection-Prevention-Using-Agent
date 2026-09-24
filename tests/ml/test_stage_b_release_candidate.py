from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from ml.training.stage_b_benchmark import benchmark_stage_b_models
from ml.training.stage_b_calibration import calibrate_stage_b_model
from ml.training.stage_b_final_evaluation import final_evaluate_stage_b_model
from ml.training.stage_b_release_candidate import (
    MANIFEST_FILENAME,
    MODEL_FILENAME,
    PARITY_FILENAME,
    RELEASE_CANDIDATE_SCHEMA,
    ReleaseCandidateError,
    freeze_stage_b_release_candidate,
)


CONTEXT_FEATURES = [
    "document_started", "has_password", "has_otp", "has_payment", "has_identity",
    "purpose_authentication", "purpose_payment", "purpose_unknown", "sensitive_form_count",
    "same_origin_sensitive_target", "cross_origin_sensitive_target", "stable_sensitive_target",
    "sensitive_target_changed", "target_changed_after_interaction", "submission_target_mismatch",
    "https_downgrade_sensitive_target", "password_then_otp", "dynamic_sensitive_field",
    "foreign_frame_sensitive_field", "cross_request_near_interaction", "unknown_document_ratio",
    "known_target_ratio", "contradiction_count", "positive_evidence_count", "purpose_sensitive_mismatch",
    "purpose_context_consistent", "purpose_observed",
]


def h(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def feature_dataset():
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
            vector = [0.0] * len(CONTEXT_FEATURES)
            vector[0] = 1.0
            if label:
                vector[1] = 1.0
                vector[4] = float((i % 3) == 0)
                vector[10] = 1.0
                vector[22] = 2.0 + (i % 2)
                vector[24] = 1.0
            else:
                vector[5] = 1.0
                vector[9] = 1.0
                vector[11] = 1.0
                vector[23] = 2.0 + (i % 2)
                vector[25] = 1.0
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
        "feature_names": CONTEXT_FEATURES,
        "feature_contract_sha256": h({
            "feature_version": "context-features-1",
            "feature_names": CONTEXT_FEATURES,
        }),
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
    final = final_evaluate_stage_b_model(data, gate, benchmark, calibration)
    return data, gate, benchmark, calibration, final


def test_freezes_calibrated_onnx_without_touching_browser_assets(tmp_path: Path):
    data, gate, benchmark, calibration, final = chain()
    output = tmp_path / "release"
    result = freeze_stage_b_release_candidate(data, gate, benchmark, calibration, final, output)
    assert result["schema_version"] == RELEASE_CANDIDATE_SCHEMA
    assert result["status"] == "PASS"
    assert result["feature_names"] == CONTEXT_FEATURES
    assert result["parity"]["status"] == "PASS"
    assert result["parity"]["test_partition_used"] is False
    assert result["parity"]["maximum_absolute_probability_error"] <= result["parity"]["tolerance"]
    assert (output / MODEL_FILENAME).is_file()
    assert (output / MANIFEST_FILENAME).is_file()
    assert (output / PARITY_FILENAME).is_file()
    assert result["release_gate"]["deploy"] is False
    assert result["release_gate"]["autonomous_blocking"] is False


def test_parity_vectors_never_include_final_test(tmp_path: Path):
    data, gate, benchmark, calibration, final = chain()
    output = tmp_path / "release"
    freeze_stage_b_release_candidate(data, gate, benchmark, calibration, final, output)
    parity = json.loads((output / PARITY_FILENAME).read_text())
    assert parity["test_partition_used"] is False
    assert set(parity["partitions_used"]) == {"train", "selection", "calibration"}
    assert all(row["partition"] != "test" for row in parity["vectors"])


def test_rejects_final_evaluation_from_different_feature_dataset(tmp_path: Path):
    data, gate, benchmark, calibration, final = chain()
    changed = copy.deepcopy(final)
    changed["feature_dataset_sha256"] = "0" * 64
    with pytest.raises(ReleaseCandidateError, match="feature dataset contents"):
        freeze_stage_b_release_candidate(
            data, gate, benchmark, calibration, changed, tmp_path / "release"
        )


def test_rejects_final_report_that_claims_test_reuse(tmp_path: Path):
    data, gate, benchmark, calibration, final = chain()
    changed = copy.deepcopy(final)
    changed["data_usage"]["test_used_for_threshold_selection"] = True
    with pytest.raises(ReleaseCandidateError, match="prohibited test reuse"):
        freeze_stage_b_release_candidate(
            data, gate, benchmark, calibration, changed, tmp_path / "release"
        )


def test_unauthorized_threshold_keeps_candidate_research_only(tmp_path: Path):
    data, gate, benchmark, calibration, final = chain()
    assert calibration["threshold_selection"]["deployment_threshold_authorized"] is False
    result = freeze_stage_b_release_candidate(
        data, gate, benchmark, calibration, final, tmp_path / "release"
    )
    assert result["release_gate"]["integration_eligible"] is False
    assert any("Task 9" in reason for reason in result["release_gate"]["reasons"])


def test_refuses_to_overwrite_a_frozen_candidate(tmp_path: Path):
    data, gate, benchmark, calibration, final = chain()
    output = tmp_path / "release"
    freeze_stage_b_release_candidate(data, gate, benchmark, calibration, final, output)
    with pytest.raises(ReleaseCandidateError, match="already exists"):
        freeze_stage_b_release_candidate(data, gate, benchmark, calibration, final, output)
