"""Locked Stage B final-test evaluation.

This is the first Stage B layer allowed to score the final-test partition.
Model family, calibration method, and operating thresholds are all fixed by
Tasks 8 and 9 before test scores are computed.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.data.stage_b_features import validate_feature_dataset
from ml.data.stage_b_readiness import READINESS_SCHEMA
from ml.training.stage_b_benchmark import BENCHMARK_SCHEMA
from ml.training.stage_b_calibration import (
    CALIBRATION_SCHEMA,
    DEFAULT_CALIBRATION_POLICY,
    _feature_identity,
    _rows,
    _scores_hash,
    _selected_spec,
    _xy,
    validate_calibration_policy,
)

FINAL_EVALUATION_SCHEMA = "stage-b-final-evaluation-1"


class FinalEvaluationError(ValueError):
    """Raised when the locked final-test chain cannot be verified."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _wilson_interval(successes: int, count: int) -> tuple[float, float]:
    if count <= 0:
        raise FinalEvaluationError("Wilson interval requires a positive denominator")
    z = 1.959963984540054
    p = successes / count
    denominator = 1 + z * z / count
    center = (p + z * z / (2 * count)) / denominator
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * count)) / count) / denominator
    return max(0.0, center - half), min(1.0, center + half)


def _probability_metrics(labels: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    clipped = np.clip(np.asarray(scores, dtype=float), 1e-12, 1 - 1e-12)
    return {
        "sample_count": int(len(labels)),
        "average_precision": float(average_precision_score(labels, clipped)),
        "roc_auc": float(roc_auc_score(labels, clipped)),
        "brier_score": float(brier_score_loss(labels, clipped)),
        "log_loss": float(
            log_loss(labels, np.column_stack([1 - clipped, clipped]), labels=[0, 1])
        ),
    }


def _threshold_metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    predicted = np.asarray(scores, dtype=float) >= float(threshold)
    tn, fp, fn, tp = (
        int(v) for v in confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
    )
    negatives = tn + fp
    positives = tp + fn
    low, high = _wilson_interval(fp, negatives)
    return {
        "threshold": float(threshold),
        "sample_count": int(len(labels)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "observed_fpr": float(fp / negatives),
        "observed_fnr": float(fn / positives),
        "fpr_wilson_95": [float(low), float(high)],
        "legitimate_count": negatives,
        "phishing_count": positives,
        "empirical_fpr_resolution": float(1.0 / negatives),
    }


def _validate_chain(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    dataset_hash = _canonical_hash(feature_data)
    identity = _feature_identity(feature_data)

    if readiness.get("schema_version") != READINESS_SCHEMA:
        raise FinalEvaluationError("unsupported readiness audit schema")
    if readiness.get("status") != "PASS" or readiness.get("training_allowed") is not True:
        raise FinalEvaluationError("readiness gate has not authorized the Stage B chain")
    if readiness.get("issues") not in ([], None):
        raise FinalEvaluationError("PASS readiness audit contains unresolved issues")
    if readiness.get("feature_dataset_identity") != identity:
        raise FinalEvaluationError("readiness identity does not match feature dataset")
    if readiness.get("feature_dataset_sha256") != dataset_hash:
        raise FinalEvaluationError("readiness content hash does not match feature dataset")

    if benchmark.get("schema_version") != BENCHMARK_SCHEMA or benchmark.get("status") != "PASS":
        raise FinalEvaluationError("valid PASS benchmark report is required")
    if benchmark.get("feature_dataset_identity") != identity:
        raise FinalEvaluationError("benchmark identity does not match feature dataset")
    if benchmark.get("feature_dataset_sha256") != dataset_hash:
        raise FinalEvaluationError("benchmark content hash does not match feature dataset")
    if benchmark.get("readiness_policy_sha256") != readiness.get("policy_sha256"):
        raise FinalEvaluationError("benchmark does not match readiness policy")

    if calibration.get("schema_version") != CALIBRATION_SCHEMA or calibration.get("status") != "PASS":
        raise FinalEvaluationError("valid PASS calibration report is required")
    if calibration.get("feature_dataset_identity") != identity:
        raise FinalEvaluationError("calibration identity does not match feature dataset")
    if calibration.get("feature_dataset_sha256") != dataset_hash:
        raise FinalEvaluationError("calibration content hash does not match feature dataset")
    if calibration.get("readiness_policy_sha256") != readiness.get("policy_sha256"):
        raise FinalEvaluationError("calibration does not match readiness policy")
    if calibration.get("benchmark_protocol_sha256") != benchmark.get("benchmark_protocol_sha256"):
        raise FinalEvaluationError("calibration does not match benchmark protocol")
    if calibration.get("selected_candidate") != benchmark.get("selected_candidate"):
        raise FinalEvaluationError("calibration selected candidate does not match benchmark")
    if calibration.get("calibration_policy_sha256") != _canonical_hash(policy):
        raise FinalEvaluationError("calibration policy does not match final-evaluation policy")

    usage = calibration.get("data_usage")
    if not isinstance(usage, Mapping) or usage.get("test_partition") != "LOCKED_NOT_USED":
        raise FinalEvaluationError("calibration did not keep final test locked")
    threshold_selection = calibration.get("threshold_selection")
    if not isinstance(threshold_selection, Mapping) or threshold_selection.get("partition_used") != "calibration":
        raise FinalEvaluationError("threshold selection was not calibration-only")


def final_evaluate_stage_b_model(
    feature_data: Mapping[str, Any],
    readiness_audit: Mapping[str, Any],
    benchmark_report: Mapping[str, Any],
    calibration_report: Mapping[str, Any],
    calibration_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise FinalEvaluationError(f"invalid feature dataset: {exc}") from exc

    active_policy = validate_calibration_policy(
        calibration_policy or DEFAULT_CALIBRATION_POLICY
    )
    _validate_chain(
        validated,
        readiness_audit,
        benchmark_report,
        calibration_report,
        active_policy,
    )

    selected_candidate = str(benchmark_report["selected_candidate"])
    spec = _selected_spec(selected_candidate)

    x_refit, y_refit = _xy(validated, ("train", "selection"))
    calibration_rows = _rows(validated, "calibration")
    x_calibration, y_calibration = _xy(validated, ("calibration",))

    base_model = spec.factory()
    base_model.fit(x_refit, y_refit)
    calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model),
        method=active_policy["method"],
    )
    calibrator.fit(x_calibration, y_calibration)

    reproduced_calibration_scores = np.asarray(
        calibrator.predict_proba(x_calibration)[:, 1], dtype=float
    )
    reproduced_calibration_hash = _scores_hash(
        calibration_rows, reproduced_calibration_scores
    )
    if reproduced_calibration_hash != calibration_report.get("calibration_scores_sha256"):
        raise FinalEvaluationError(
            "reproduced calibration scores do not match Task 9 calibration hash"
        )

    test_rows = _rows(validated, "test")
    x_test, y_test = _xy(validated, ("test",))
    test_scores = np.asarray(calibrator.predict_proba(x_test)[:, 1], dtype=float)
    if test_scores.shape != y_test.shape or not np.isfinite(test_scores).all():
        raise FinalEvaluationError("calibrated final-test probabilities are invalid")

    threshold_selection = calibration_report["threshold_selection"]
    primary_cap = float(threshold_selection["primary_fpr_cap"])
    primary_key = f"fpr_le_{primary_cap:g}"
    operating_points = threshold_selection.get("operating_points")
    if not isinstance(operating_points, Mapping) or primary_key not in operating_points:
        raise FinalEvaluationError("Task 9 primary operating point is missing")
    primary = operating_points[primary_key]
    if not isinstance(primary, Mapping) or type(primary.get("threshold")) not in (int, float):
        raise FinalEvaluationError("Task 9 primary threshold is invalid")
    threshold = float(primary["threshold"])

    threshold_metrics = _threshold_metrics(y_test, test_scores, threshold)
    threshold_metrics.update({
        "fpr_cap_selected_on_calibration": primary_cap,
        "calibration_deployment_authorized": bool(
            threshold_selection.get("deployment_threshold_authorized")
        ),
        "threshold_source": "CALIBRATION_ONLY",
        "test_used_for_threshold_selection": False,
    })

    score_material = [
        {"sample_id": row["sample_id"], "score": round(float(score), 12)}
        for row, score in sorted(
            zip(test_rows, test_scores, strict=True),
            key=lambda pair: pair[0]["sample_id"],
        )
    ]

    warnings: list[dict[str, Any]] = []
    if not threshold_metrics["calibration_deployment_authorized"]:
        warnings.append({
            "code": "OPERATING_POINT_NOT_DEPLOYMENT_AUTHORIZED",
            "interpretation": (
                "The fixed calibration threshold is evaluated on final test for research reporting only; "
                "Task 9 did not authorize the low-FPR deployment claim."
            ),
        })
    if threshold_metrics["fpr_wilson_95"][1] > primary_cap:
        warnings.append({
            "code": "FINAL_TEST_FPR_CONFIDENCE_BOUND_EXCEEDS_CALIBRATION_CAP",
            "fpr_cap": primary_cap,
            "wilson_95_fpr_upper": threshold_metrics["fpr_wilson_95"][1],
            "interpretation": (
                "The finite final-test sample does not support a population claim at the calibration FPR cap."
            ),
        })

    result = {
        "schema_version": FINAL_EVALUATION_SCHEMA,
        "status": "PASS",
        "selected_candidate": selected_candidate,
        "candidate_family": spec.family,
        "candidate_parameters": dict(spec.parameters),
        "calibration_method": active_policy["method"],
        "feature_dataset_sha256": _canonical_hash(validated),
        "feature_dataset_identity": _feature_identity(validated),
        "readiness_policy_sha256": readiness_audit["policy_sha256"],
        "benchmark_protocol_sha256": benchmark_report["benchmark_protocol_sha256"],
        "calibration_policy_sha256": calibration_report["calibration_policy_sha256"],
        "reproduced_calibration_scores_sha256": reproduced_calibration_hash,
        "data_usage": {
            "base_refit_partitions": ["train", "selection"],
            "calibration_partition": "calibration",
            "final_evaluation_partition": "test",
            "test_role": "FINAL_EVALUATION_ONLY",
            "test_used_for_model_selection": False,
            "test_used_for_calibration": False,
            "test_used_for_threshold_selection": False,
            "test_samples": int(len(y_test)),
        },
        "test_score_sha256": _canonical_hash(score_material),
        "threshold_free_metrics": _probability_metrics(y_test, test_scores),
        "fixed_operating_point": threshold_metrics,
        "warnings": warnings,
        "limitations": [
            "The final test is used only after model family, calibration method, and operating threshold are fixed.",
            "Observed final-test error rates are finite-sample estimates, not population guarantees.",
            "A Task 9 threshold that was not deployment-authorized remains research-only even if final-test observations look favorable.",
            "Repeated inspection of the same final test for subsequent tuning would invalidate its role as a locked final evaluation set.",
        ],
    }
    return result
