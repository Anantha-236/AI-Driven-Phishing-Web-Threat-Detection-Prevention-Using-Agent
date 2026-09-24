"""Stage B probability calibration and calibration-only threshold selection.

The selected model family is fixed by Task 8. This stage refits that fixed
candidate on train + selection, calibrates probabilities on calibration only,
and never scores the final test partition.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score

from ml.data.stage_b_features import validate_feature_dataset
from ml.data.stage_b_readiness import READINESS_SCHEMA
from ml.training.stage_b_benchmark import (
    BENCHMARK_SCHEMA,
    RANDOM_SEED,
    SCREENING_FPR_CAPS,
    _candidate_specs,
)

CALIBRATION_SCHEMA = "stage-b-calibration-1"
CALIBRATION_POLICY_SCHEMA = "stage-b-calibration-policy-1"
DEFAULT_CALIBRATION_POLICY = {
    "schema_version": CALIBRATION_POLICY_SCHEMA,
    "method": "sigmoid",
    "primary_fpr_cap": 0.01,
    "fpr_caps": [0.01, 0.005, 0.001],
    "confidence_level": 0.95,
    "require_confidence_supported_threshold": True,
    "refit_partitions": ["train", "selection"],
    "calibration_partition": "calibration",
    "test_partition": "LOCKED_NOT_USED",
}


class CalibrationError(ValueError):
    """Raised when Stage B calibration would violate the locked protocol."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def validate_calibration_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema_version", "method", "primary_fpr_cap", "fpr_caps",
        "confidence_level", "require_confidence_supported_threshold",
        "refit_partitions", "calibration_partition", "test_partition", "notes",
    }
    unexpected = set(policy) - allowed
    if unexpected:
        raise CalibrationError(
            f"unexpected calibration policy fields: {', '.join(sorted(unexpected))}"
        )
    if policy.get("schema_version") != CALIBRATION_POLICY_SCHEMA:
        raise CalibrationError("unsupported calibration policy schema")
    if policy.get("method") != "sigmoid":
        raise CalibrationError("Stage B calibration method is locked to sigmoid")
    caps = policy.get("fpr_caps")
    if (
        not isinstance(caps, list)
        or not caps
        or any(type(v) not in (int, float) or not 0 < float(v) < 1 for v in caps)
    ):
        raise CalibrationError("calibration policy requires FPR caps between 0 and 1")
    caps = [float(v) for v in caps]
    if len(caps) != len(set(caps)):
        raise CalibrationError("calibration FPR caps must be unique")
    primary = policy.get("primary_fpr_cap")
    if type(primary) not in (int, float) or float(primary) not in caps:
        raise CalibrationError("primary_fpr_cap must be one of fpr_caps")
    confidence = policy.get("confidence_level")
    if type(confidence) not in (int, float) or float(confidence) != 0.95:
        raise CalibrationError("Stage B currently supports the locked 95% Wilson interval")
    if type(policy.get("require_confidence_supported_threshold")) is not bool:
        raise CalibrationError("require_confidence_supported_threshold must be boolean")
    if policy.get("refit_partitions") != ["train", "selection"]:
        raise CalibrationError("selected candidate must be refit on train + selection only")
    if policy.get("calibration_partition") != "calibration":
        raise CalibrationError("calibration partition is locked")
    if policy.get("test_partition") != "LOCKED_NOT_USED":
        raise CalibrationError("final test must remain locked")
    normalized = json.loads(json.dumps(policy))
    normalized["fpr_caps"] = caps
    normalized["primary_fpr_cap"] = float(primary)
    normalized["confidence_level"] = float(confidence)
    return normalized


def _feature_identity(feature_data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "feature_version": feature_data.get("feature_version"),
        "feature_contract_sha256": feature_data.get("feature_contract_sha256"),
        "extractor_source_sha256": feature_data.get("extractor_source_sha256"),
        "episode_set_sha256": feature_data.get("episode_set_sha256"),
    }


def _validate_chain(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    benchmark: Mapping[str, Any],
) -> None:
    identity = _feature_identity(feature_data)
    if readiness.get("schema_version") != READINESS_SCHEMA:
        raise CalibrationError("unsupported readiness audit schema")
    if readiness.get("status") != "PASS" or readiness.get("training_allowed") is not True:
        raise CalibrationError("Stage B readiness gate has not authorized calibration")
    if readiness.get("issues") not in ([], None):
        raise CalibrationError("PASS readiness audit must not contain unresolved issues")
    if readiness.get("feature_dataset_identity") != identity:
        raise CalibrationError("readiness audit does not match feature dataset")
    dataset_hash = _canonical_hash(feature_data)
    if readiness.get("feature_dataset_sha256") != dataset_hash:
        raise CalibrationError("readiness audit does not match feature dataset contents")

    if benchmark.get("schema_version") != BENCHMARK_SCHEMA or benchmark.get("status") != "PASS":
        raise CalibrationError("valid PASS benchmark report is required")
    if benchmark.get("feature_dataset_identity") != identity:
        raise CalibrationError("benchmark report does not match feature dataset")
    if benchmark.get("feature_dataset_sha256") != dataset_hash:
        raise CalibrationError("benchmark report does not match feature dataset contents")
    if benchmark.get("readiness_policy_sha256") != readiness.get("policy_sha256"):
        raise CalibrationError("benchmark report does not match readiness policy")
    if benchmark.get("data_usage") != {
        "fit_partition": "train",
        "candidate_selection_partition": "selection",
        "calibration_partition": "LOCKED_NOT_USED",
        "test_partition": "LOCKED_NOT_USED",
        "train_samples": benchmark.get("data_usage", {}).get("train_samples"),
        "selection_samples": benchmark.get("data_usage", {}).get("selection_samples"),
    }:
        raise CalibrationError("benchmark data-use declaration is invalid")

    selected = benchmark.get("selected_candidate")
    ranking = benchmark.get("candidate_ranking")
    if not isinstance(selected, str) or not selected:
        raise CalibrationError("benchmark selected_candidate is missing")
    if not isinstance(ranking, list) or selected not in ranking:
        raise CalibrationError("selected candidate is not in benchmark ranking")
    candidate_rows = benchmark.get("candidates")
    if not isinstance(candidate_rows, list):
        raise CalibrationError("benchmark candidate records are missing")
    selected_rows = [
        row for row in candidate_rows
        if isinstance(row, Mapping) and row.get("candidate_id") == selected
    ]
    if len(selected_rows) != 1 or selected_rows[0].get("eligible_for_selection") is not True:
        raise CalibrationError("benchmark selected candidate is not eligible")

    expected_protocol = _canonical_hash({
        "seed": RANDOM_SEED,
        "screening_fpr_caps": SCREENING_FPR_CAPS,
        "candidates": [
            {
                "candidate_id": spec.candidate_id,
                "family": spec.family,
                "eligible_for_selection": spec.eligible_for_selection,
                "parameters": dict(spec.parameters),
            }
            for spec in _candidate_specs()
        ],
    })
    if benchmark.get("benchmark_protocol_sha256") != expected_protocol:
        raise CalibrationError("benchmark protocol does not match current candidate configuration")


def _rows(feature_data: Mapping[str, Any], partition: str) -> list[Mapping[str, Any]]:
    payload = feature_data["partitions"][partition]
    rows = payload.get("records") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list) or not rows:
        raise CalibrationError(f"partition {partition} is empty")
    return rows


def _xy(feature_data: Mapping[str, Any], partitions: tuple[str, ...]) -> tuple[np.ndarray, np.ndarray]:
    rows = [row for partition in partitions for row in _rows(feature_data, partition)]
    x = np.asarray([row["feature_vector"] for row in rows], dtype=np.float64)
    y = np.asarray([row["ground_truth"] for row in rows], dtype=np.int64)
    if x.ndim != 2 or y.ndim != 1 or len(x) != len(y) or set(y.tolist()) != {0, 1}:
        raise CalibrationError("calibration pipeline requires finite vectors from both classes")
    if not np.isfinite(x).all():
        raise CalibrationError("calibration pipeline contains non-finite features")
    return x, y


def _selected_spec(candidate_id: str):
    matches = [spec for spec in _candidate_specs() if spec.candidate_id == candidate_id]
    if len(matches) != 1 or not matches[0].eligible_for_selection:
        raise CalibrationError("selected benchmark candidate is unavailable")
    return matches[0]


def _ece(labels: np.ndarray, scores: np.ndarray, bins: int = 10) -> float:
    boundaries = np.linspace(0.0, 1.0, bins + 1)
    value = 0.0
    for lower, upper in zip(boundaries[:-1], boundaries[1:]):
        mask = (scores >= lower) & (scores <= upper if upper == 1 else scores < upper)
        count = int(mask.sum())
        if not count:
            continue
        value += (count / len(labels)) * abs(
            float(scores[mask].mean()) - float(labels[mask].mean())
        )
    return float(value)


def _probability_metrics(labels: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    clipped = np.clip(np.asarray(scores, dtype=float), 1e-12, 1 - 1e-12)
    return {
        "sample_count": int(len(labels)),
        "legitimate_count": int((labels == 0).sum()),
        "phishing_count": int((labels == 1).sum()),
        "average_precision": float(average_precision_score(labels, clipped)),
        "roc_auc": float(roc_auc_score(labels, clipped)),
        "brier_score": float(brier_score_loss(labels, clipped)),
        "log_loss": float(
            log_loss(labels, np.column_stack([1 - clipped, clipped]), labels=[0, 1])
        ),
        "expected_calibration_error_10_bins": _ece(labels, clipped, bins=10),
    }


def _wilson_interval(successes: int, count: int) -> tuple[float, float]:
    if count <= 0:
        raise CalibrationError("Wilson interval requires a positive denominator")
    z = 1.959963984540054
    p = successes / count
    denominator = 1 + z * z / count
    center = (p + z * z / (2 * count)) / denominator
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * count)) / count) / denominator
    return max(0.0, center - half), min(1.0, center + half)


def _threshold_candidates(labels: np.ndarray, scores: np.ndarray, caps: list[float]) -> dict[str, Any]:
    negatives = int((labels == 0).sum())
    positives = int((labels == 1).sum())
    if not negatives or not positives:
        raise CalibrationError("threshold selection requires both classes")
    clipped = np.clip(np.asarray(scores, dtype=float), 1e-12, 1 - 1e-12)
    thresholds = sorted({1.0, 0.0, *(float(v) for v in clipped)}, reverse=True)
    resolution = 1.0 / negatives
    results: dict[str, Any] = {}

    for cap in caps:
        feasible: list[dict[str, Any]] = []
        for threshold in thresholds:
            pred = clipped >= threshold
            fp = int(((pred == 1) & (labels == 0)).sum())
            observed_fpr = fp / negatives
            if observed_fpr > cap + 1e-15:
                continue
            tp = int(((pred == 1) & (labels == 1)).sum())
            predicted_positive = int(pred.sum())
            recall = tp / positives
            precision = tp / predicted_positive if predicted_positive else 0.0
            _, upper = _wilson_interval(fp, negatives)
            feasible.append({
                "threshold": float(threshold),
                "recall": float(recall),
                "precision": float(precision),
                "observed_fpr": float(observed_fpr),
                "false_positives": fp,
                "true_positives": tp,
                "wilson_95_fpr_upper": float(upper),
            })
        if not feasible:
            raise CalibrationError("no threshold satisfies an empirical FPR cap")
        best = max(
            feasible,
            key=lambda row: (
                row["recall"],
                row["precision"],
                -row["observed_fpr"],
                row["threshold"],
            ),
        )
        empirically_resolved = resolution <= cap
        confidence_supported = best["wilson_95_fpr_upper"] <= cap
        deployment_authorized = (
            empirically_resolved
            and confidence_supported
            and best["true_positives"] > 0
        )
        results[f"fpr_le_{cap:g}"] = {
            "fpr_cap": cap,
            "empirical_fpr_resolution": float(resolution),
            "empirically_resolved": empirically_resolved,
            "confidence_supported": confidence_supported,
            "deployment_authorized": deployment_authorized,
            **best,
            "interpretation": (
                "Threshold was selected on calibration only. Authorization additionally requires "
                "empirical FPR resolution and a two-sided Wilson 95% upper bound at or below the cap."
            ),
        }
    return results


def _scores_hash(rows: list[Mapping[str, Any]], scores: np.ndarray) -> str:
    material = [
        {
            "sample_id": row["sample_id"],
            "score": round(float(score), 12),
        }
        for row, score in sorted(
            zip(rows, scores, strict=True),
            key=lambda pair: pair[0]["sample_id"],
        )
    ]
    return _canonical_hash(material)


def calibrate_stage_b_model(
    feature_data: Mapping[str, Any],
    readiness_audit: Mapping[str, Any],
    benchmark_report: Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise CalibrationError(f"invalid feature dataset: {exc}") from exc
    _validate_chain(validated, readiness_audit, benchmark_report)
    active_policy = validate_calibration_policy(policy or DEFAULT_CALIBRATION_POLICY)

    selected_candidate = str(benchmark_report["selected_candidate"])
    spec = _selected_spec(selected_candidate)

    x_refit, y_refit = _xy(validated, ("train", "selection"))
    calibration_rows = _rows(validated, "calibration")
    x_calibration, y_calibration = _xy(validated, ("calibration",))

    base_model = spec.factory()
    base_model.fit(x_refit, y_refit)
    raw_scores = np.asarray(base_model.predict_proba(x_calibration)[:, 1], dtype=float)
    if raw_scores.shape != y_calibration.shape or not np.isfinite(raw_scores).all():
        raise CalibrationError("selected candidate produced invalid raw calibration scores")

    calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model),
        method=active_policy["method"],
    )
    calibrator.fit(x_calibration, y_calibration)
    calibrated_scores = np.asarray(
        calibrator.predict_proba(x_calibration)[:, 1],
        dtype=float,
    )
    if calibrated_scores.shape != y_calibration.shape or not np.isfinite(calibrated_scores).all():
        raise CalibrationError("calibrator produced invalid probabilities")

    thresholds = _threshold_candidates(
        y_calibration,
        calibrated_scores,
        active_policy["fpr_caps"],
    )
    primary_key = f"fpr_le_{active_policy['primary_fpr_cap']:g}"
    primary = thresholds[primary_key]
    if active_policy["require_confidence_supported_threshold"]:
        selected_operating_point = primary if primary["deployment_authorized"] else None
    else:
        selected_operating_point = primary

    warnings: list[dict[str, Any]] = []
    if selected_operating_point is None:
        warnings.append({
            "code": "PRIMARY_FPR_THRESHOLD_NOT_STATISTICALLY_SUPPORTED",
            "fpr_cap": active_policy["primary_fpr_cap"],
            "calibration_legitimate_count": int((y_calibration == 0).sum()),
            "empirical_fpr_resolution": float(1.0 / int((y_calibration == 0).sum())),
            "interpretation": (
                "Calibration produced an empirical threshold candidate, but the current "
                "calibration set is not sufficient to authorize the primary low-FPR claim."
            ),
        })
    if _probability_metrics(y_calibration, calibrated_scores)["brier_score"] > _probability_metrics(y_calibration, raw_scores)["brier_score"]:
        warnings.append({
            "code": "SIGMOID_CALIBRATION_DID_NOT_IMPROVE_BRIER_ON_CALIBRATION_SET",
            "interpretation": "Calibration remains protocol-locked; this warning prevents claiming improvement from this finite calibration set.",
        })

    result = {
        "schema_version": CALIBRATION_SCHEMA,
        "status": "PASS",
        "selected_candidate": selected_candidate,
        "candidate_family": spec.family,
        "candidate_parameters": dict(spec.parameters),
        "calibration_method": active_policy["method"],
        "calibration_policy_sha256": _canonical_hash(active_policy),
        "benchmark_protocol_sha256": benchmark_report["benchmark_protocol_sha256"],
        "feature_dataset_identity": _feature_identity(validated),
        "feature_dataset_sha256": _canonical_hash(validated),
        "readiness_policy_sha256": readiness_audit["policy_sha256"],
        "data_usage": {
            "base_refit_partitions": ["train", "selection"],
            "calibration_partition": "calibration",
            "test_partition": "LOCKED_NOT_USED",
            "base_refit_samples": int(len(y_refit)),
            "calibration_samples": int(len(y_calibration)),
        },
        "calibration_metrics": {
            "raw": _probability_metrics(y_calibration, raw_scores),
            "sigmoid": _probability_metrics(y_calibration, calibrated_scores),
        },
        "calibration_scores_sha256": _scores_hash(calibration_rows, calibrated_scores),
        "threshold_selection": {
            "partition_used": "calibration",
            "primary_fpr_cap": active_policy["primary_fpr_cap"],
            "operating_points": thresholds,
            "selected_operating_point": selected_operating_point,
            "deployment_threshold_authorized": selected_operating_point is not None,
        },
        "warnings": warnings,
        "limitations": [
            "The selected candidate family was fixed by Task 8 before calibration.",
            "The base estimator is refit on train + selection only after model-family selection is complete.",
            "Probability calibration and threshold selection use calibration only.",
            "Final-test vectors and labels are not scored in this stage.",
            "A calibration-set threshold candidate is not a population FPR guarantee.",
            "Deployment authorization requires both empirical FPR resolution and a Wilson 95% FPR upper bound at or below the requested cap.",
        ],
    }
    return result
