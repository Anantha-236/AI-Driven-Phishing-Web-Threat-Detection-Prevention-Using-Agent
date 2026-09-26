from __future__ import annotations

import pytest

import ml.training.stage_b_contextual_research_benchmark_v2 as mod
from ml.training.stage_b_contextual_research_benchmark_v2 import (
    BRAND_ROLE,
    PROTOCOL_ID,
    ContextualResearchBenchmarkError,
    _guard_benchmark,
    _guard_calibration,
    canonical_hash,
    validate_contextual_v2_readiness,
)


def validated_feature():
    return {
        "feature_version": "context-features-1",
        "feature_contract_sha256": "a" * 64,
        "extractor_source_sha256": "b" * 64,
        "episode_set_sha256": "c" * 64,
    }


def readiness_template(feature):
    return {
        "schema_version": "stage-b-readiness-audit-1",
        "status": "PASS",
        "training_allowed": True,
        "issues": [],
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "source_independence_relaxed": True,
        "production_readiness_equivalent": False,
        "deployment_authorized": False,
        "brand_group_role": BRAND_ROLE,
        "feature_dataset_identity": {
            "feature_version": feature["feature_version"],
            "feature_contract_sha256": feature[
                "feature_contract_sha256"
            ],
            "extractor_source_sha256": feature[
                "extractor_source_sha256"
            ],
            "episode_set_sha256": feature[
                "episode_set_sha256"
            ],
        },
        "feature_dataset_sha256": canonical_hash(feature),
        "policy_sha256": "d" * 64,
        "counts": {
            p: {
                "total": 200,
                "legitimate": 100,
                "phishing": 100,
            }
            for p in ("train", "selection", "calibration", "test")
        },
        "provenance_counts": {
            p: {"ARCHIVED_BROWSER_REPLAY": 200}
            for p in ("train", "selection", "calibration", "test")
        },
        "unique_group_counts": {
            "artifact_group": {
                p: 200
                for p in ("train", "selection", "calibration", "test")
            },
            "domain_group": {
                p: 190
                for p in ("train", "selection", "calibration", "test")
            },
        },
        "chronology": {
            "required": True,
            "strict_forward": True,
        },
    }


def test_v2_readiness_accepts_contextual_protocol(monkeypatch):
    feature = validated_feature()
    monkeypatch.setattr(
        mod,
        "validate_feature_dataset",
        lambda _: feature,
    )
    result = validate_contextual_v2_readiness(
        feature,
        readiness_template(feature),
    )
    assert result is feature


def test_v2_readiness_rejects_v1_protocol(monkeypatch):
    feature = validated_feature()
    monkeypatch.setattr(
        mod,
        "validate_feature_dataset",
        lambda _: feature,
    )
    readiness = readiness_template(feature)
    readiness["research_protocol"] = (
        "single-source-archive-replay-research-v1"
    )
    with pytest.raises(
        ContextualResearchBenchmarkError,
        match="unexpected contextual-v2",
    ):
        validate_contextual_v2_readiness(feature, readiness)


def test_v2_readiness_requires_brand_audit_only(monkeypatch):
    feature = validated_feature()
    monkeypatch.setattr(
        mod,
        "validate_feature_dataset",
        lambda _: feature,
    )
    readiness = readiness_template(feature)
    readiness["brand_group_role"] = "ISOLATION_DIMENSION"
    with pytest.raises(
        ContextualResearchBenchmarkError,
        match="audit-only",
    ):
        validate_contextual_v2_readiness(feature, readiness)


def test_v2_readiness_rejects_brand_as_active_isolation(monkeypatch):
    feature = validated_feature()
    monkeypatch.setattr(
        mod,
        "validate_feature_dataset",
        lambda _: feature,
    )
    readiness = readiness_template(feature)
    readiness["unique_group_counts"]["brand_group"] = {
        "train": 10,
        "selection": 10,
        "calibration": 10,
        "test": 10,
    }
    with pytest.raises(
        ContextualResearchBenchmarkError,
        match="active readiness isolation",
    ):
        validate_contextual_v2_readiness(feature, readiness)


def test_benchmark_guard_keeps_calibration_and_test_locked():
    report = {
        "schema_version": "stage-b-model-benchmark-1",
        "status": "PASS",
        "data_usage": {
            "fit_partition": "train",
            "candidate_selection_partition": "selection",
            "calibration_partition": "LOCKED_NOT_USED",
            "test_partition": "LOCKED_NOT_USED",
        },
    }
    _guard_benchmark(report)
    report["data_usage"]["test_partition"] = "test"
    with pytest.raises(
        ContextualResearchBenchmarkError,
        match="locked test",
    ):
        _guard_benchmark(report)


def test_calibration_guard_keeps_test_locked():
    report = {
        "schema_version": "stage-b-calibration-1",
        "status": "PASS",
        "data_usage": {
            "base_refit_partitions": ["train", "selection"],
            "calibration_partition": "calibration",
            "test_partition": "LOCKED_NOT_USED",
        },
    }
    _guard_calibration(report)
    report["data_usage"]["test_partition"] = "test"
    with pytest.raises(
        ContextualResearchBenchmarkError,
        match="locked test",
    ):
        _guard_calibration(report)
