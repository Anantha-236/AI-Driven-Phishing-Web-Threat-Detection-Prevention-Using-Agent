"""Stage B benchmark framework using train for fitting and selection for model choice only.

Calibration and final-test partitions remain locked for later stages. The benchmark
requires a PASS result from the Stage B readiness gate before fitting candidates.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Any, Callable, Mapping

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.data.stage_b_features import PARTITIONS, validate_feature_dataset
from ml.data.stage_b_readiness import READINESS_SCHEMA

BENCHMARK_SCHEMA = "stage-b-model-benchmark-1"
RANDOM_SEED = 236
SCREENING_FPR_CAPS = (0.01, 0.005, 0.001)


class BenchmarkError(ValueError):
    """Raised when benchmarking would violate the locked Stage B protocol."""


@dataclass(frozen=True)
class CandidateSpec:
    candidate_id: str
    family: str
    eligible_for_selection: bool
    factory: Callable[[], Any]
    parameters: Mapping[str, Any]


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _candidate_specs() -> tuple[CandidateSpec, ...]:
    return (
        CandidateSpec(
            candidate_id="dummy_prior",
            family="diagnostic_baseline",
            eligible_for_selection=False,
            factory=lambda: DummyClassifier(strategy="prior"),
            parameters={"strategy": "prior"},
        ),
        CandidateSpec(
            candidate_id="logistic_regression",
            family="linear",
            eligible_for_selection=True,
            factory=lambda: Pipeline([
                ("scale", StandardScaler()),
                ("model", LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    max_iter=2000,
                    solver="lbfgs",
                    random_state=RANDOM_SEED,
                )),
            ]),
            parameters={
                "scaler": "StandardScaler",
                "C": 1.0,
                "class_weight": "balanced",
                "max_iter": 2000,
                "solver": "lbfgs",
                "random_state": RANDOM_SEED,
            },
        ),
        CandidateSpec(
            candidate_id="hist_gradient_boosting",
            family="boosting",
            eligible_for_selection=True,
            factory=lambda: HistGradientBoostingClassifier(
                learning_rate=0.05,
                max_iter=120,
                max_leaf_nodes=15,
                min_samples_leaf=10,
                l2_regularization=1.0,
                random_state=RANDOM_SEED,
            ),
            parameters={
                "learning_rate": 0.05,
                "max_iter": 120,
                "max_leaf_nodes": 15,
                "min_samples_leaf": 10,
                "l2_regularization": 1.0,
                "random_state": RANDOM_SEED,
            },
        ),
        CandidateSpec(
            candidate_id="random_forest_compact",
            family="bagged_trees",
            eligible_for_selection=True,
            factory=lambda: RandomForestClassifier(
                n_estimators=128,
                max_depth=8,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                max_features="sqrt",
                random_state=RANDOM_SEED,
                n_jobs=1,
            ),
            parameters={
                "n_estimators": 128,
                "max_depth": 8,
                "min_samples_leaf": 2,
                "class_weight": "balanced_subsample",
                "max_features": "sqrt",
                "random_state": RANDOM_SEED,
                "n_jobs": 1,
            },
        ),
    )


def _readiness_identity_matches(feature_data: Mapping[str, Any], readiness: Mapping[str, Any]) -> None:
    if readiness.get("schema_version") != READINESS_SCHEMA:
        raise BenchmarkError("unsupported readiness audit schema")
    if readiness.get("training_allowed") is not True or readiness.get("status") != "PASS":
        raise BenchmarkError("Stage B readiness gate has not authorized benchmarking")
    if readiness.get("issues") not in ([], None):
        raise BenchmarkError("PASS readiness audit must not contain unresolved issues")
    expected = {
        "feature_version": feature_data.get("feature_version"),
        "feature_contract_sha256": feature_data.get("feature_contract_sha256"),
        "extractor_source_sha256": feature_data.get("extractor_source_sha256"),
        "episode_set_sha256": feature_data.get("episode_set_sha256"),
    }
    if readiness.get("feature_dataset_identity") != expected:
        raise BenchmarkError("readiness audit does not match the feature dataset identity")
    dataset_hash = _canonical_hash(feature_data)
    if readiness.get("feature_dataset_sha256") != dataset_hash:
        raise BenchmarkError("readiness audit does not match the feature dataset contents")


def _xy(feature_data: Mapping[str, Any], partition: str) -> tuple[np.ndarray, np.ndarray]:
    rows = feature_data["partitions"][partition]["records"]
    x = np.asarray([row["feature_vector"] for row in rows], dtype=np.float64)
    y = np.asarray([row["ground_truth"] for row in rows], dtype=np.int64)
    if x.ndim != 2 or y.ndim != 1 or len(x) != len(y) or len(set(y.tolist())) != 2:
        raise BenchmarkError(f"partition {partition} must contain finite vectors from both classes")
    if not np.isfinite(x).all():
        raise BenchmarkError(f"partition {partition} contains non-finite features")
    return x, y


def _selection_screening_points(labels: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    negatives = int((labels == 0).sum())
    positives = int((labels == 1).sum())
    if negatives == 0 or positives == 0:
        raise BenchmarkError("selection metrics require both classes")

    unique_thresholds = [math.inf] + sorted({float(v) for v in scores}, reverse=True) + [-math.inf]
    results: dict[str, Any] = {}
    for cap in SCREENING_FPR_CAPS:
        max_fp = math.floor(cap * negatives + 1e-12)
        best = {"recall": 0.0, "precision": 0.0, "observed_fpr": 0.0, "false_positives": 0}
        for threshold in unique_thresholds:
            pred = scores >= threshold
            fp = int(((pred == 1) & (labels == 0)).sum())
            if fp > max_fp:
                continue
            tp = int(((pred == 1) & (labels == 1)).sum())
            predicted_positive = int(pred.sum())
            recall = tp / positives
            precision = tp / predicted_positive if predicted_positive else 0.0
            candidate = {
                "recall": float(recall),
                "precision": float(precision),
                "observed_fpr": float(fp / negatives),
                "false_positives": fp,
            }
            if (candidate["recall"], candidate["precision"], -candidate["observed_fpr"]) > (
                best["recall"], best["precision"], -best["observed_fpr"]
            ):
                best = candidate
        results[f"fpr_le_{cap:g}"] = {
            "fpr_cap": cap,
            "allowed_false_positives": max_fp,
            **best,
            "interpretation": "Selection-set screening only; no deployment threshold is selected here.",
        }
    return {
        "legitimate_count": negatives,
        "phishing_count": positives,
        "empirical_fpr_resolution": 1.0 / negatives,
        "operating_points": results,
    }


def _selection_metrics(labels: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    clipped = np.clip(scores.astype(float), 1e-12, 1 - 1e-12)
    return {
        "average_precision": float(average_precision_score(labels, clipped)),
        "roc_auc": float(roc_auc_score(labels, clipped)),
        "brier_score": float(brier_score_loss(labels, clipped)),
        "log_loss": float(log_loss(labels, np.column_stack([1 - clipped, clipped]), labels=[0, 1])),
        "low_fpr_screening": _selection_screening_points(labels, clipped),
    }


def _rank_key(candidate: Mapping[str, Any]) -> tuple[float, float, float, str]:
    metrics = candidate["selection_metrics"]
    return (
        float(metrics["average_precision"]),
        float(metrics["roc_auc"]),
        -float(metrics["log_loss"]),
        str(candidate["candidate_id"]),
    )


def benchmark_stage_b_models(
    feature_data: Mapping[str, Any],
    readiness_audit: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise BenchmarkError(f"invalid feature dataset: {exc}") from exc
    _readiness_identity_matches(validated, readiness_audit)

    x_train, y_train = _xy(validated, "train")
    x_selection, y_selection = _xy(validated, "selection")

    candidates: list[dict[str, Any]] = []
    for spec in _candidate_specs():
        model = spec.factory()
        model.fit(x_train, y_train)
        if not hasattr(model, "predict_proba"):
            raise BenchmarkError(f"candidate {spec.candidate_id} does not expose predict_proba")
        scores = np.asarray(model.predict_proba(x_selection)[:, 1], dtype=float)
        if scores.shape != y_selection.shape or not np.isfinite(scores).all():
            raise BenchmarkError(f"candidate {spec.candidate_id} produced invalid selection scores")
        candidates.append({
            "candidate_id": spec.candidate_id,
            "family": spec.family,
            "eligible_for_selection": spec.eligible_for_selection,
            "parameters": dict(spec.parameters),
            "selection_metrics": _selection_metrics(y_selection, scores),
        })

    eligible = [row for row in candidates if row["eligible_for_selection"]]
    if not eligible:
        raise BenchmarkError("no eligible benchmark candidates are configured")
    selected = max(eligible, key=_rank_key)
    baseline = next(row for row in candidates if row["candidate_id"] == "dummy_prior")

    selection_negatives = int((y_selection == 0).sum())
    warnings: list[dict[str, Any]] = []
    resolution = 1.0 / selection_negatives
    for cap in SCREENING_FPR_CAPS:
        if resolution > cap:
            warnings.append({
                "code": "FPR_CAP_BELOW_EMPIRICAL_RESOLUTION",
                "fpr_cap": cap,
                "selection_legitimate_count": selection_negatives,
                "empirical_fpr_resolution": resolution,
                "interpretation": "This selection set cannot empirically resolve the requested FPR cap except as a zero-false-positive screen.",
            })
    if selected["selection_metrics"]["average_precision"] <= baseline["selection_metrics"]["average_precision"]:
        warnings.append({
            "code": "SELECTED_CANDIDATE_DOES_NOT_BEAT_PRIOR_BASELINE_AP",
            "selected_candidate": selected["candidate_id"],
        })

    candidate_order = sorted(
        [row for row in candidates if row["eligible_for_selection"]],
        key=_rank_key,
        reverse=True,
    )

    result = {
        "schema_version": BENCHMARK_SCHEMA,
        "status": "PASS",
        "selected_candidate": selected["candidate_id"],
        "selection_rule": {
            "primary": "average_precision_max",
            "secondary": "roc_auc_max",
            "tertiary": "log_loss_min",
            "tie_break": "candidate_id_lexical",
            "partition_used": "selection",
        },
        "data_usage": {
            "fit_partition": "train",
            "candidate_selection_partition": "selection",
            "calibration_partition": "LOCKED_NOT_USED",
            "test_partition": "LOCKED_NOT_USED",
            "train_samples": int(len(y_train)),
            "selection_samples": int(len(y_selection)),
        },
        "feature_dataset_identity": {
            "feature_version": validated.get("feature_version"),
            "feature_contract_sha256": validated.get("feature_contract_sha256"),
            "extractor_source_sha256": validated.get("extractor_source_sha256"),
            "episode_set_sha256": validated.get("episode_set_sha256"),
        },
        "feature_dataset_sha256": _canonical_hash(validated),
        "readiness_policy_sha256": readiness_audit.get("policy_sha256"),
        "benchmark_protocol_sha256": _canonical_hash({
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
        }),
        "candidate_ranking": [row["candidate_id"] for row in candidate_order],
        "candidates": sorted(candidates, key=lambda row: row["candidate_id"]),
        "warnings": warnings,
        "limitations": [
            "Candidate fitting uses train only and candidate choice uses selection only.",
            "Calibration and final-test partitions are intentionally untouched by benchmark scoring.",
            "Selection low-FPR values are screening summaries only; deployment thresholds are reserved for the calibration partition.",
            "Benchmark PASS does not establish calibration quality, final-test performance, or real-world generalization.",
        ],
    }
    return result
