from __future__ import annotations

from copy import deepcopy

import pytest

from ml.evaluation.stage_b_research_evidence import (
    ResearchEvidenceError,
    canonical_hash,
    verify_evidence_chain,
)


DATASET = "a" * 64
TEST = "b" * 64


def fixtures():
    task20 = {
        "schema_version": "stage-b-scaled-candidate-assembly-1",
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "split_count_readiness": {"status": "PASS"},
    }
    readiness = {
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "training_allowed": True,
        "production_readiness_equivalent": False,
        "feature_dataset_sha256": DATASET,
    }
    task21 = {
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "training_allowed_for_research_benchmark": True,
    }
    task22 = {
        "schema_version": "stage-b-research-benchmark-calibration-1",
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "feature_dataset_sha256": DATASET,
        "benchmark_sha256": "c" * 64,
        "calibration_sha256": "d" * 64,
        "test_partition": {
            "status": "LOCKED_NOT_USED",
            "used_for_model_selection": False,
            "used_for_calibration": False,
            "used_for_threshold_selection": False,
            "scored": False,
        },
    }
    task23 = {
        "schema_version": "stage-b-locked-research-final-evaluation-1",
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "feature_dataset_sha256": DATASET,
        "test_partition_identity_sha256": TEST,
        "test_samples": 100,
        "selected_candidate": "candidate",
        "benchmark_sha256": task22["benchmark_sha256"],
        "calibration_sha256": task22["calibration_sha256"],
        "task22_sha256": canonical_hash(task22),
        "test_use": {
            "role": "ONE_TIME_LOCKED_RESEARCH_FINAL_EVALUATION",
            "used_for_model_selection": False,
            "used_for_calibration": False,
            "used_for_threshold_selection": False,
            "eligible_for_future_tuning": False,
        },
    }
    lock = {
        "schema_version": "stage-b-locked-research-final-test-lock-1",
        "status": "FINALIZED",
        "research_only": True,
        "deployment_authorized": False,
        "feature_dataset_sha256": DATASET,
        "test_partition_identity_sha256": TEST,
        "result_sha256": canonical_hash(task23),
    }
    return task20, task21, readiness, task22, task23, lock


def test_valid_research_evidence_chain_passes():
    result = verify_evidence_chain(
        task20_report=fixtures()[0],
        task21_report=fixtures()[1],
        task21_readiness=fixtures()[2],
        task22_report=fixtures()[3],
        task23_report=fixtures()[4],
        final_lock=fixtures()[5],
    )
    assert result["status"] == "PASS"
    assert result["research_only"] is True
    assert result["deployment_authorized"] is False


def test_task22_must_not_have_scored_test():
    values = list(fixtures())
    values[3] = deepcopy(values[3])
    values[3]["test_partition"]["scored"] = True
    values[4] = deepcopy(values[4])
    values[4]["task22_sha256"] = canonical_hash(values[3])
    values[5] = deepcopy(values[5])
    values[5]["result_sha256"] = canonical_hash(values[4])
    with pytest.raises(ResearchEvidenceError, match="scored"):
        verify_evidence_chain(
            task20_report=values[0],
            task21_report=values[1],
            task21_readiness=values[2],
            task22_report=values[3],
            task23_report=values[4],
            final_lock=values[5],
        )


def test_final_lock_must_match_result_hash():
    values = list(fixtures())
    values[5] = deepcopy(values[5])
    values[5]["result_sha256"] = "0" * 64
    with pytest.raises(ResearchEvidenceError, match="result hash"):
        verify_evidence_chain(
            task20_report=values[0],
            task21_report=values[1],
            task21_readiness=values[2],
            task22_report=values[3],
            task23_report=values[4],
            final_lock=values[5],
        )


def test_feature_dataset_identity_must_match_across_chain():
    values = list(fixtures())
    values[4] = deepcopy(values[4])
    values[4]["feature_dataset_sha256"] = "f" * 64
    values[5] = deepcopy(values[5])
    values[5]["feature_dataset_sha256"] = "f" * 64
    values[5]["result_sha256"] = canonical_hash(values[4])
    with pytest.raises(ResearchEvidenceError, match="feature dataset identity"):
        verify_evidence_chain(
            task20_report=values[0],
            task21_report=values[1],
            task21_readiness=values[2],
            task22_report=values[3],
            task23_report=values[4],
            final_lock=values[5],
        )
