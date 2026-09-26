"""Stage B Task 22: research-only benchmark + calibration guard.

Consumes Task-21 contextual features and research readiness. Reuses the existing
Stage B benchmark and calibration implementations, while adding a fail-closed
research protocol envelope:

- train is used for candidate fitting;
- selection is used for candidate family choice;
- calibration is used only after family choice for sigmoid calibration and
  threshold *research evidence*;
- test remains locked and untouched;
- readiness must explicitly be research-only and deployment_authorized=false;
- no release-candidate/export/browser integration path is called;
- even if calibration finite-sample statistics support an FPR cap, deployment
  remains unauthorized under this protocol.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from ml.data.stage_b_features import validate_feature_dataset
from ml.data.stage_b_readiness import READINESS_SCHEMA
from ml.training.stage_b_benchmark import (
    BENCHMARK_SCHEMA,
    BenchmarkError,
    benchmark_stage_b_models,
)
from ml.training.stage_b_calibration import (
    CALIBRATION_SCHEMA,
    CalibrationError,
    calibrate_stage_b_model,
    validate_calibration_policy,
)

RESEARCH_BENCHMARK_SCHEMA = "stage-b-research-benchmark-calibration-1"
RESEARCH_PROTOCOL = "single-source-archive-replay-research-v1"


class ResearchBenchmarkError(RuntimeError):
    pass


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def validate_research_readiness(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise ResearchBenchmarkError(f"invalid feature dataset: {exc}") from exc

    if readiness.get("schema_version") != READINESS_SCHEMA:
        raise ResearchBenchmarkError("unsupported readiness audit schema")
    if readiness.get("status") != "PASS" or readiness.get("training_allowed") is not True:
        raise ResearchBenchmarkError("research readiness has not authorized benchmarking")
    if readiness.get("issues") not in ([], None):
        raise ResearchBenchmarkError("PASS research readiness contains unresolved issues")

    if readiness.get("research_protocol") != RESEARCH_PROTOCOL:
        raise ResearchBenchmarkError("unexpected research readiness protocol")
    if readiness.get("research_only") is not True:
        raise ResearchBenchmarkError("readiness must explicitly declare research_only=true")
    if readiness.get("source_independence_relaxed") is not True:
        raise ResearchBenchmarkError("single-source archive protocol must declare relaxed source independence")
    if readiness.get("production_readiness_equivalent") is not False:
        raise ResearchBenchmarkError("research readiness must not claim production equivalence")
    if readiness.get("deployment_authorized") is not False:
        raise ResearchBenchmarkError("research readiness must explicitly deny deployment authorization")

    identity = {
        "feature_version": validated.get("feature_version"),
        "feature_contract_sha256": validated.get("feature_contract_sha256"),
        "extractor_source_sha256": validated.get("extractor_source_sha256"),
        "episode_set_sha256": validated.get("episode_set_sha256"),
    }
    if readiness.get("feature_dataset_identity") != identity:
        raise ResearchBenchmarkError("readiness does not match feature dataset identity")
    if readiness.get("feature_dataset_sha256") != canonical_hash(validated):
        raise ResearchBenchmarkError("readiness does not match feature dataset contents")

    provenance = readiness.get("provenance_counts")
    if not isinstance(provenance, Mapping):
        raise ResearchBenchmarkError("research readiness provenance counts are missing")
    for partition in ("train", "selection", "calibration", "test"):
        row = provenance.get(partition)
        if not isinstance(row, Mapping) or set(row) != {"ARCHIVED_BROWSER_REPLAY"}:
            raise ResearchBenchmarkError(
                f"{partition} readiness provenance must be ARCHIVED_BROWSER_REPLAY only"
            )

    chronology = readiness.get("chronology")
    if (
        not isinstance(chronology, Mapping)
        or chronology.get("required") is not True
        or chronology.get("strict_forward") is not True
    ):
        raise ResearchBenchmarkError("research readiness requires a strict-forward locked test")

    return validated


def _guard_benchmark(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != BENCHMARK_SCHEMA or report.get("status") != "PASS":
        raise ResearchBenchmarkError("existing benchmark implementation did not return PASS")
    usage = report.get("data_usage")
    if not isinstance(usage, Mapping):
        raise ResearchBenchmarkError("benchmark data usage missing")
    if usage.get("fit_partition") != "train":
        raise ResearchBenchmarkError("benchmark fit partition must remain train")
    if usage.get("candidate_selection_partition") != "selection":
        raise ResearchBenchmarkError("candidate choice must remain selection-only")
    if usage.get("calibration_partition") != "LOCKED_NOT_USED":
        raise ResearchBenchmarkError("benchmark touched calibration before candidate selection freeze")
    if usage.get("test_partition") != "LOCKED_NOT_USED":
        raise ResearchBenchmarkError("benchmark touched locked test")


def _guard_calibration(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != CALIBRATION_SCHEMA or report.get("status") != "PASS":
        raise ResearchBenchmarkError("existing calibration implementation did not return PASS")
    usage = report.get("data_usage")
    if not isinstance(usage, Mapping):
        raise ResearchBenchmarkError("calibration data usage missing")
    if usage.get("base_refit_partitions") != ["train", "selection"]:
        raise ResearchBenchmarkError("calibration base refit must use train+selection only")
    if usage.get("calibration_partition") != "calibration":
        raise ResearchBenchmarkError("calibration partition declaration changed")
    if usage.get("test_partition") != "LOCKED_NOT_USED":
        raise ResearchBenchmarkError("calibration touched locked test")


def run_research_benchmark_calibration(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    calibration_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    validated = validate_research_readiness(feature_data, readiness)

    try:
        benchmark = benchmark_stage_b_models(validated, readiness)
    except BenchmarkError as exc:
        raise ResearchBenchmarkError(str(exc)) from exc
    _guard_benchmark(benchmark)

    try:
        active_policy = (
            validate_calibration_policy(calibration_policy)
            if calibration_policy is not None
            else None
        )
        calibration = calibrate_stage_b_model(
            validated,
            readiness,
            benchmark,
            active_policy,
        )
    except CalibrationError as exc:
        raise ResearchBenchmarkError(str(exc)) from exc
    _guard_calibration(calibration)

    selection = benchmark.get("selection_rule")
    threshold = calibration.get("threshold_selection")
    if not isinstance(selection, Mapping) or not isinstance(threshold, Mapping):
        raise ResearchBenchmarkError("benchmark/calibration selection evidence missing")

    primary_cap = threshold.get("primary_fpr_cap")
    key = f"fpr_le_{float(primary_cap):g}"
    points = threshold.get("operating_points")
    if not isinstance(points, Mapping) or not isinstance(points.get(key), Mapping):
        raise ResearchBenchmarkError("primary research operating-point evidence missing")
    primary = dict(points[key])

    finite_sample_supported = bool(
        primary.get("empirically_resolved")
        and primary.get("confidence_supported")
        and primary.get("true_positives", 0) > 0
    )

    return {
        "schema_version": RESEARCH_BENCHMARK_SCHEMA,
        "status": "PASS",
        "research_protocol": RESEARCH_PROTOCOL,
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "test_partition": {
            "status": "LOCKED_NOT_USED",
            "used_for_model_selection": False,
            "used_for_calibration": False,
            "used_for_threshold_selection": False,
            "scored": False,
        },
        "feature_dataset_identity": {
            "feature_version": validated.get("feature_version"),
            "feature_contract_sha256": validated.get("feature_contract_sha256"),
            "extractor_source_sha256": validated.get("extractor_source_sha256"),
            "episode_set_sha256": validated.get("episode_set_sha256"),
        },
        "feature_dataset_sha256": canonical_hash(validated),
        "readiness_policy_sha256": readiness.get("policy_sha256"),
        "selected_candidate": benchmark.get("selected_candidate"),
        "candidate_ranking": benchmark.get("candidate_ranking"),
        "selection_rule": dict(selection),
        "calibration_method": calibration.get("calibration_method"),
        "primary_research_operating_point": {
            **primary,
            "finite_sample_statistical_support": finite_sample_supported,
            "deployment_authorized": False,
            "interpretation": (
                "Calibration-only research evidence. Even when the finite calibration "
                "sample supports the requested cap, the single-source archive protocol "
                "does not authorize deployment or integration."
            ),
        },
        "underlying_calibration_flag": {
            "deployment_threshold_authorized": bool(
                threshold.get("deployment_threshold_authorized")
            ),
            "interpretation": (
                "This is the existing calibration module's finite-sample statistical "
                "gate only. It is subordinate to this research protocol's "
                "deployment_authorized=false."
            ),
        },
        "benchmark_sha256": canonical_hash(benchmark),
        "calibration_sha256": canonical_hash(calibration),
        "next_gate": {
            "name": "LOCKED_RESEARCH_FINAL_TEST",
            "allowed_to_implement": True,
            "allowed_to_run_repeatedly": False,
            "requires_frozen_benchmark_and_calibration": True,
            "deployment_authority_after_pass": False,
        },
        "limitations": [
            "All records originate from one archived dataset source; source independence is intentionally relaxed.",
            "Archived browser replay does not reproduce live network, server, or user interaction context.",
            "Model family selection uses selection only; calibration and threshold research use calibration only.",
            "The test partition remains unscored in this task.",
            "Any future research final-test result is descriptive evidence for this frozen protocol and cannot authorize deployment.",
        ],
        "benchmark": benchmark,
        "calibration": calibration,
    }
