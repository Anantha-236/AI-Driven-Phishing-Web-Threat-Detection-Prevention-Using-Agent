from __future__ import annotations

import pytest

import ml.training.stage_b_research_benchmark as mod
from ml.training.stage_b_research_benchmark import (
    ResearchBenchmarkError,
    _guard_benchmark,
    _guard_calibration,
    canonical_hash,
    validate_research_readiness,
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
        "research_protocol": "single-source-archive-replay-research-v1",
        "research_only": True,
        "source_independence_relaxed": True,
        "production_readiness_equivalent": False,
        "deployment_authorized": False,
        "feature_dataset_identity": {
            "feature_version": feature["feature_version"],
            "feature_contract_sha256": feature["feature_contract_sha256"],
            "extractor_source_sha256": feature["extractor_source_sha256"],
            "episode_set_sha256": feature["episode_set_sha256"],
        },
        "feature_dataset_sha256": canonical_hash(feature),
        "provenance_counts": {
            p: {"ARCHIVED_BROWSER_REPLAY": 10}
            for p in ("train", "selection", "calibration", "test")
        },
        "chronology": {"required": True, "strict_forward": True},
    }


def test_research_readiness_requires_explicit_deployment_denial(monkeypatch):
    feature = validated_feature()
    monkeypatch.setattr(mod, "validate_feature_dataset", lambda _: feature)
    r = readiness_template(feature)
    r["deployment_authorized"] = True
    with pytest.raises(ResearchBenchmarkError, match="deny deployment"):
        validate_research_readiness(feature, r)


def test_research_readiness_requires_research_protocol(monkeypatch):
    feature = validated_feature()
    monkeypatch.setattr(mod, "validate_feature_dataset", lambda _: feature)
    r = readiness_template(feature)
    r["research_protocol"] = "wrong"
    with pytest.raises(ResearchBenchmarkError, match="unexpected research"):
        validate_research_readiness(feature, r)


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
    with pytest.raises(ResearchBenchmarkError, match="locked test"):
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
    with pytest.raises(ResearchBenchmarkError, match="locked test"):
        _guard_calibration(report)
