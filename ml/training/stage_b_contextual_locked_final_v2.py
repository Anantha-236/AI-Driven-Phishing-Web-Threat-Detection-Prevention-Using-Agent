"""Stage B Task 31: one-time locked contextual-v2 research final test.

Task 31 is the first contextual-v2 layer allowed to score the test partition.
It delegates model fitting/calibration/scoring to the existing proven
`stage_b_final_evaluation` engine and adds protocol-v2 chain validation plus a
dataset-specific one-time lock.

A PASS means the procedure completed successfully. It is not a deployment
authorization and is not, by itself, a performance verdict.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ml.data.stage_b_features import validate_feature_dataset
from ml.training.stage_b_final_evaluation import (
    FINAL_EVALUATION_SCHEMA,
    FinalEvaluationError,
    final_evaluate_stage_b_model,
)
from ml.training.stage_b_calibration import validate_calibration_policy

TASK30_SCHEMA = "stage-b-contextual-research-benchmark-calibration-v2-1"
TASK31_SCHEMA = "stage-b-contextual-locked-research-final-v2-1"
LOCK_SCHEMA = "stage-b-contextual-final-test-lock-v2-1"
PROTOCOL_ID = "single-source-contextual-archive-replay-research-v2"
BRAND_ROLE = "AUDIT_ONLY_NOT_MODEL_OBSERVABLE"


class ContextualLockedFinalError(RuntimeError):
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


def _test_partition_fingerprint(
    feature_data: Mapping[str, Any],
) -> dict[str, Any]:
    partitions = feature_data.get("partitions")
    if not isinstance(partitions, Mapping):
        raise ContextualLockedFinalError(
            "feature dataset partitions missing"
        )
    test = partitions.get("test")
    if not isinstance(test, Mapping):
        raise ContextualLockedFinalError(
            "feature dataset test partition missing"
        )
    rows = test.get("records")
    if not isinstance(rows, list) or not rows:
        raise ContextualLockedFinalError(
            "feature dataset test partition is empty"
        )

    material = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise ContextualLockedFinalError(
                "invalid test-partition record"
            )
        sample_id = raw.get("sample_id")
        label = raw.get("ground_truth")
        vector = raw.get("feature_vector")
        if (
            not isinstance(sample_id, str)
            or label not in (0, 1)
            or not isinstance(vector, list)
        ):
            raise ContextualLockedFinalError(
                "invalid test-partition record identity"
            )
        material.append({
            "sample_id": sample_id,
            "ground_truth": label,
            "feature_vector": vector,
        })

    material.sort(key=lambda row: row["sample_id"])
    return {
        "sample_count": len(material),
        "sha256": canonical_hash(material),
    }


def validate_contextual_final_chain(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    task30_report: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
        active_policy = validate_calibration_policy(policy)
    except Exception as exc:
        raise ContextualLockedFinalError(
            f"invalid final-test input chain: {exc}"
        ) from exc

    if task30_report.get("schema_version") != TASK30_SCHEMA:
        raise ContextualLockedFinalError(
            "unsupported Task 30 contextual-v2 report schema"
        )
    if task30_report.get("status") != "PASS":
        raise ContextualLockedFinalError(
            "Task 30 report must be frozen PASS before final test"
        )
    if task30_report.get("research_protocol") != PROTOCOL_ID:
        raise ContextualLockedFinalError(
            "Task 30 protocol identity mismatch"
        )
    if task30_report.get("research_only") is not True:
        raise ContextualLockedFinalError(
            "Task 30 must remain research-only"
        )
    if task30_report.get("deployment_authorized") is not False:
        raise ContextualLockedFinalError(
            "Task 30 unexpectedly authorizes deployment"
        )
    if task30_report.get("integration_eligible") is not False:
        raise ContextualLockedFinalError(
            "Task 30 unexpectedly authorizes integration"
        )
    if task30_report.get("brand_group_role") != BRAND_ROLE:
        raise ContextualLockedFinalError(
            "Task 30 brand audit-only guard mismatch"
        )

    test_guard = task30_report.get("test_partition")
    if (
        not isinstance(test_guard, Mapping)
        or test_guard.get("status") != "LOCKED_NOT_USED"
        or test_guard.get("scored") is not False
        or test_guard.get("used_for_model_selection") is not False
        or test_guard.get("used_for_calibration") is not False
        or test_guard.get("used_for_threshold_selection") is not False
    ):
        raise ContextualLockedFinalError(
            "Task 30 did not preserve the locked test contract"
        )

    if canonical_hash(benchmark) != task30_report.get(
        "benchmark_sha256"
    ):
        raise ContextualLockedFinalError(
            "benchmark no longer matches frozen Task 30 report"
        )
    if canonical_hash(calibration) != task30_report.get(
        "calibration_sha256"
    ):
        raise ContextualLockedFinalError(
            "calibration no longer matches frozen Task 30 report"
        )

    if task30_report.get("feature_dataset_sha256") != canonical_hash(
        validated
    ):
        raise ContextualLockedFinalError(
            "feature dataset no longer matches frozen Task 30 report"
        )
    if task30_report.get("readiness_sha256") != canonical_hash(
        readiness
    ):
        raise ContextualLockedFinalError(
            "readiness no longer matches frozen Task 30 report"
        )

    selected = task30_report.get("selected_candidate")
    if selected != benchmark.get("selected_candidate"):
        raise ContextualLockedFinalError(
            "Task 30 selected candidate does not match benchmark"
        )
    if selected != calibration.get("selected_candidate"):
        raise ContextualLockedFinalError(
            "Task 30 selected candidate does not match calibration"
        )

    threshold_flag = task30_report.get(
        "underlying_calibration_flag"
    )
    if not isinstance(threshold_flag, Mapping):
        raise ContextualLockedFinalError(
            "Task 30 calibration-threshold provenance missing"
        )
    if (
        threshold_flag.get("deployment_threshold_authorized")
        is not False
    ):
        raise ContextualLockedFinalError(
            "Task 31 requires the recorded non-deployable research threshold"
        )

    readiness_guard = {
        "research_protocol": readiness.get("research_protocol"),
        "research_only": readiness.get("research_only"),
        "deployment_authorized": readiness.get(
            "deployment_authorized"
        ),
        "brand_group_role": readiness.get("brand_group_role"),
    }
    expected_readiness_guard = {
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "deployment_authorized": False,
        "brand_group_role": BRAND_ROLE,
    }
    if readiness_guard != expected_readiness_guard:
        raise ContextualLockedFinalError(
            "readiness contextual-v2 research guard mismatch"
        )

    return {
        "validated_features": validated,
        "active_policy": active_policy,
        "test_partition": _test_partition_fingerprint(validated),
    }


def build_lock_material(
    *,
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    task30_report: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    policy: Mapping[str, Any],
    test_partition: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": LOCK_SCHEMA,
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "deployment_authorized": False,
        "feature_dataset_sha256": canonical_hash(feature_data),
        "readiness_sha256": canonical_hash(readiness),
        "task30_report_sha256": canonical_hash(task30_report),
        "benchmark_sha256": canonical_hash(benchmark),
        "calibration_sha256": canonical_hash(calibration),
        "calibration_policy_sha256": canonical_hash(policy),
        "test_partition_sample_count": test_partition[
            "sample_count"
        ],
        "test_partition_sha256": test_partition["sha256"],
        "selected_candidate": task30_report[
            "selected_candidate"
        ],
        "primary_fpr_cap": task30_report[
            "primary_research_operating_point"
        ]["fpr_cap"],
        "primary_threshold": task30_report[
            "primary_research_operating_point"
        ]["threshold"],
        "test_use": "FINAL_EVALUATION_ONLY",
        "repeated_tuning_prohibited": True,
    }


def create_or_validate_lock(
    lock_path: Path,
    lock_material: Mapping[str, Any],
) -> str:
    expected = canonical_hash(lock_material)
    if lock_path.exists():
        try:
            existing = json.loads(
                lock_path.read_text(encoding="utf-8")
            )
        except Exception as exc:
            raise ContextualLockedFinalError(
                f"existing final-test lock is unreadable: {lock_path}"
            ) from exc
        if canonical_hash(existing) != expected:
            raise ContextualLockedFinalError(
                "final-test lock exists for a different evidence chain; "
                "refusing to score test"
            )
        return "EXISTING_MATCH"

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    temp = lock_path.with_suffix(lock_path.suffix + ".tmp")
    payload = json.dumps(
        lock_material,
        indent=2,
        sort_keys=True,
    ) + "\n"
    temp.write_text(payload, encoding="utf-8")
    try:
        # Atomic create semantics: if another process already created the lock,
        # validate that lock rather than replacing it.
        temp.replace(lock_path)
    finally:
        temp.unlink(missing_ok=True)

    stored = json.loads(lock_path.read_text(encoding="utf-8"))
    if canonical_hash(stored) != expected:
        raise ContextualLockedFinalError(
            "final-test lock verification failed after creation"
        )
    return "CREATED"


def run_contextual_locked_final(
    *,
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    task30_report: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    chain = validate_contextual_final_chain(
        feature_data,
        readiness,
        task30_report,
        benchmark,
        calibration,
        policy,
    )

    try:
        base = final_evaluate_stage_b_model(
            chain["validated_features"],
            readiness,
            benchmark,
            calibration,
            chain["active_policy"],
        )
    except FinalEvaluationError as exc:
        raise ContextualLockedFinalError(str(exc)) from exc

    if (
        base.get("schema_version") != FINAL_EVALUATION_SCHEMA
        or base.get("status") != "PASS"
    ):
        raise ContextualLockedFinalError(
            "base locked final evaluator did not return PASS"
        )

    usage = base.get("data_usage")
    if (
        not isinstance(usage, Mapping)
        or usage.get("final_evaluation_partition") != "test"
        or usage.get("test_role") != "FINAL_EVALUATION_ONLY"
        or usage.get("test_used_for_model_selection") is not False
        or usage.get("test_used_for_calibration") is not False
        or usage.get("test_used_for_threshold_selection") is not False
    ):
        raise ContextualLockedFinalError(
            "base final evaluator violated locked-test usage contract"
        )

    fixed = base.get("fixed_operating_point")
    if not isinstance(fixed, Mapping):
        raise ContextualLockedFinalError(
            "base final operating-point evidence missing"
        )

    primary_cap = float(
        task30_report["primary_research_operating_point"]["fpr_cap"]
    )
    final_fpr = float(fixed["observed_fpr"])
    final_upper = float(fixed["fpr_wilson_95"][1])

    return {
        "schema_version": TASK31_SCHEMA,
        "status": "PASS",
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "selected_candidate": base["selected_candidate"],
        "calibration_method": base["calibration_method"],
        "test_samples": usage["test_samples"],
        "test_score_sha256": base["test_score_sha256"],
        "threshold_free_metrics": base[
            "threshold_free_metrics"
        ],
        "fixed_operating_point": {
            **dict(fixed),
            "research_fpr_cap": primary_cap,
            "observed_fpr_within_research_cap":
                final_fpr <= primary_cap,
            "wilson_95_upper_within_research_cap":
                final_upper <= primary_cap,
            "deployment_authorized": False,
        },
        "warnings": list(base.get("warnings", [])),
        "test_contract": {
            "role": "FINAL_EVALUATION_ONLY",
            "model_family_frozen_before_test": True,
            "calibration_method_frozen_before_test": True,
            "threshold_frozen_before_test": True,
            "test_used_for_model_selection": False,
            "test_used_for_calibration": False,
            "test_used_for_threshold_selection": False,
            "repeated_tuning_after_test_prohibited": True,
        },
        "evidence_chain": {
            "feature_dataset_sha256": canonical_hash(
                chain["validated_features"]
            ),
            "readiness_sha256": canonical_hash(readiness),
            "task30_report_sha256": canonical_hash(
                task30_report
            ),
            "benchmark_sha256": canonical_hash(benchmark),
            "calibration_sha256": canonical_hash(
                calibration
            ),
            "calibration_policy_sha256": canonical_hash(
                chain["active_policy"]
            ),
            "test_partition_sha256": chain[
                "test_partition"
            ]["sha256"],
        },
        "limitations": [
            "This is a one-time research final-test evaluation on one archived dataset source.",
            "A PASS status means the locked evaluation procedure completed successfully; it is not deployment authorization.",
            "The calibration operating point lacked 95% finite-sample support at the 1% FPR cap before test exposure.",
            "The final-test result must not be used to retune model family, calibration method, or threshold and then be rescored as if still locked.",
            "Archived replay does not establish live-web population performance or production safety.",
        ],
        "base_final_evaluation": base,
    }
