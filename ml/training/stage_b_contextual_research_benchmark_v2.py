"""Stage B Task 30: contextual research-v2 benchmark + calibration.

This is the protocol-v2 counterpart of Task 22. It reuses the proven Stage B
benchmark and calibration algorithms while enforcing the contextual v2
research envelope:

- train only for candidate fitting;
- selection only for candidate-family choice;
- calibration only after family freeze for sigmoid calibration and threshold
  research evidence;
- test remains locked and unscored;
- artifact_group + exact-host domain_group are the active isolation dimensions;
- brand_group remains audit-only and is not model-observable;
- the dataset is single-source archived-browser research;
- deployment and browser integration remain unauthorized regardless of any
  finite-sample calibration flag.

No test vectors or labels are scored by this task.
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

CONTEXTUAL_V2_BENCHMARK_SCHEMA = (
    "stage-b-contextual-research-benchmark-calibration-v2-1"
)
PROTOCOL_ID = "single-source-contextual-archive-replay-research-v2"
ACTIVE_ISOLATION = ["artifact_group", "domain_group"]
AUDIT_ONLY = ["brand_group"]
BRAND_ROLE = "AUDIT_ONLY_NOT_MODEL_OBSERVABLE"


class ContextualResearchBenchmarkError(RuntimeError):
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


def _feature_identity(feature_data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "feature_version": feature_data.get("feature_version"),
        "feature_contract_sha256": feature_data.get("feature_contract_sha256"),
        "extractor_source_sha256": feature_data.get("extractor_source_sha256"),
        "episode_set_sha256": feature_data.get("episode_set_sha256"),
    }


def validate_contextual_v2_readiness(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise ContextualResearchBenchmarkError(
            f"invalid feature dataset: {exc}"
        ) from exc

    if readiness.get("schema_version") != READINESS_SCHEMA:
        raise ContextualResearchBenchmarkError(
            "unsupported readiness audit schema"
        )
    if (
        readiness.get("status") != "PASS"
        or readiness.get("training_allowed") is not True
    ):
        raise ContextualResearchBenchmarkError(
            "contextual-v2 readiness has not authorized research benchmarking"
        )
    if readiness.get("issues") not in ([], None):
        raise ContextualResearchBenchmarkError(
            "PASS contextual-v2 readiness contains unresolved issues"
        )

    if readiness.get("research_protocol") != PROTOCOL_ID:
        raise ContextualResearchBenchmarkError(
            "unexpected contextual-v2 research protocol"
        )
    if readiness.get("research_only") is not True:
        raise ContextualResearchBenchmarkError(
            "readiness must declare research_only=true"
        )
    if readiness.get("source_independence_relaxed") is not True:
        raise ContextualResearchBenchmarkError(
            "single-source contextual research must declare relaxed source independence"
        )
    if readiness.get("production_readiness_equivalent") is not False:
        raise ContextualResearchBenchmarkError(
            "contextual-v2 research must not claim production equivalence"
        )
    if readiness.get("deployment_authorized") is not False:
        raise ContextualResearchBenchmarkError(
            "contextual-v2 readiness must deny deployment authorization"
        )
    if readiness.get("brand_group_role") != BRAND_ROLE:
        raise ContextualResearchBenchmarkError(
            "brand_group must remain audit-only and non-model-observable"
        )

    identity = _feature_identity(validated)
    if readiness.get("feature_dataset_identity") != identity:
        raise ContextualResearchBenchmarkError(
            "readiness does not match feature dataset identity"
        )
    if readiness.get("feature_dataset_sha256") != canonical_hash(validated):
        raise ContextualResearchBenchmarkError(
            "readiness does not match feature dataset contents"
        )

    provenance = readiness.get("provenance_counts")
    if not isinstance(provenance, Mapping):
        raise ContextualResearchBenchmarkError(
            "contextual-v2 provenance counts are missing"
        )
    for partition in ("train", "selection", "calibration", "test"):
        row = provenance.get(partition)
        if (
            not isinstance(row, Mapping)
            or set(row) != {"ARCHIVED_BROWSER_REPLAY"}
        ):
            raise ContextualResearchBenchmarkError(
                f"{partition} provenance must be ARCHIVED_BROWSER_REPLAY only"
            )

    chronology = readiness.get("chronology")
    if (
        not isinstance(chronology, Mapping)
        or chronology.get("required") is not True
        or chronology.get("strict_forward") is not True
    ):
        raise ContextualResearchBenchmarkError(
            "contextual-v2 readiness requires a strict-forward locked test"
        )

    unique = readiness.get("unique_group_counts")
    if not isinstance(unique, Mapping):
        raise ContextualResearchBenchmarkError(
            "contextual-v2 readiness group-count evidence is missing"
        )
    if not all(key in unique for key in ACTIVE_ISOLATION):
        raise ContextualResearchBenchmarkError(
            "contextual-v2 active-isolation evidence is incomplete"
        )
    if "brand_group" in unique:
        raise ContextualResearchBenchmarkError(
            "brand_group unexpectedly appears as an active readiness isolation dimension"
        )

    return validated


def _guard_benchmark(report: Mapping[str, Any]) -> None:
    if (
        report.get("schema_version") != BENCHMARK_SCHEMA
        or report.get("status") != "PASS"
    ):
        raise ContextualResearchBenchmarkError(
            "existing benchmark implementation did not return PASS"
        )
    usage = report.get("data_usage")
    if not isinstance(usage, Mapping):
        raise ContextualResearchBenchmarkError(
            "benchmark data usage missing"
        )
    if usage.get("fit_partition") != "train":
        raise ContextualResearchBenchmarkError(
            "benchmark fit partition must remain train"
        )
    if usage.get("candidate_selection_partition") != "selection":
        raise ContextualResearchBenchmarkError(
            "candidate choice must remain selection-only"
        )
    if usage.get("calibration_partition") != "LOCKED_NOT_USED":
        raise ContextualResearchBenchmarkError(
            "benchmark touched calibration before candidate freeze"
        )
    if usage.get("test_partition") != "LOCKED_NOT_USED":
        raise ContextualResearchBenchmarkError(
            "benchmark touched locked test"
        )


def _guard_calibration(report: Mapping[str, Any]) -> None:
    if (
        report.get("schema_version") != CALIBRATION_SCHEMA
        or report.get("status") != "PASS"
    ):
        raise ContextualResearchBenchmarkError(
            "existing calibration implementation did not return PASS"
        )
    usage = report.get("data_usage")
    if not isinstance(usage, Mapping):
        raise ContextualResearchBenchmarkError(
            "calibration data usage missing"
        )
    if usage.get("base_refit_partitions") != ["train", "selection"]:
        raise ContextualResearchBenchmarkError(
            "calibration base refit must use train+selection only"
        )
    if usage.get("calibration_partition") != "calibration":
        raise ContextualResearchBenchmarkError(
            "calibration partition declaration changed"
        )
    if usage.get("test_partition") != "LOCKED_NOT_USED":
        raise ContextualResearchBenchmarkError(
            "calibration touched locked test"
        )


def run_contextual_v2_benchmark_calibration(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    calibration_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    validated = validate_contextual_v2_readiness(
        feature_data,
        readiness,
    )

    try:
        benchmark = benchmark_stage_b_models(validated, readiness)
    except BenchmarkError as exc:
        raise ContextualResearchBenchmarkError(str(exc)) from exc
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
        raise ContextualResearchBenchmarkError(str(exc)) from exc
    _guard_calibration(calibration)

    selection = benchmark.get("selection_rule")
    threshold = calibration.get("threshold_selection")
    if not isinstance(selection, Mapping):
        raise ContextualResearchBenchmarkError(
            "benchmark selection evidence missing"
        )
    if not isinstance(threshold, Mapping):
        raise ContextualResearchBenchmarkError(
            "calibration threshold evidence missing"
        )

    primary_cap = threshold.get("primary_fpr_cap")
    try:
        key = f"fpr_le_{float(primary_cap):g}"
    except (TypeError, ValueError) as exc:
        raise ContextualResearchBenchmarkError(
            "invalid primary calibration FPR cap"
        ) from exc

    points = threshold.get("operating_points")
    if (
        not isinstance(points, Mapping)
        or not isinstance(points.get(key), Mapping)
    ):
        raise ContextualResearchBenchmarkError(
            "primary contextual-v2 operating-point evidence missing"
        )
    primary = dict(points[key])

    finite_sample_supported = bool(
        primary.get("empirically_resolved")
        and primary.get("confidence_supported")
        and primary.get("true_positives", 0) > 0
    )

    counts = readiness.get("counts")
    chronology = readiness.get("chronology")

    return {
        "schema_version": CONTEXTUAL_V2_BENCHMARK_SCHEMA,
        "status": "PASS",
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "source_independence_relaxed": True,
        "active_isolation_dimensions": list(ACTIVE_ISOLATION),
        "audit_only_dimensions": list(AUDIT_ONLY),
        "brand_group_role": BRAND_ROLE,
        "partition_counts": counts,
        "chronology": chronology,
        "test_partition": {
            "status": "LOCKED_NOT_USED",
            "used_for_model_selection": False,
            "used_for_calibration": False,
            "used_for_threshold_selection": False,
            "scored": False,
        },
        "feature_dataset_identity": _feature_identity(validated),
        "feature_dataset_sha256": canonical_hash(validated),
        "readiness_sha256": canonical_hash(readiness),
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
                "Calibration-only contextual-v2 research evidence. Statistical "
                "support here never authorizes deployment, browser integration, "
                "or production-equivalent claims."
            ),
        },
        "underlying_calibration_flag": {
            "deployment_threshold_authorized": bool(
                threshold.get("deployment_threshold_authorized")
            ),
            "interpretation": (
                "This preserves the base calibration module's statistical flag "
                "as provenance only. The contextual-v2 envelope overrides it "
                "with deployment_authorized=false."
            ),
        },
        "benchmark_sha256": canonical_hash(benchmark),
        "calibration_sha256": canonical_hash(calibration),
        "next_gate": {
            "name": "CONTEXTUAL_V2_LOCKED_RESEARCH_FINAL_TEST",
            "allowed_to_implement": True,
            "allowed_to_run_repeatedly": False,
            "requires_frozen_benchmark_and_calibration": True,
            "deployment_authority_after_pass": False,
        },
        "limitations": [
            "All records originate from one archived dataset source; source independence is explicitly relaxed.",
            "Archived browser replay does not reproduce live network, server, or user interaction context.",
            "Brand identity is audit-only and is not an active v2 isolation dimension or model feature.",
            "Model-family selection uses selection only; calibration and threshold research use calibration only.",
            "The test partition remains completely unscored in this task.",
            "Calibration-set low-FPR evidence is finite-sample evidence, not a population FPR guarantee.",
            "Any later locked research final-test result remains non-deployable under this protocol.",
        ],
        "benchmark": benchmark,
        "calibration": calibration,
    }
