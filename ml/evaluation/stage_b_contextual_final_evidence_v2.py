"""Stage B Task 32: seal the consumed contextual-v2 final test and perform
read-only descriptive error analysis.

This task MUST NOT change model family, model parameters, calibration method,
threshold, features, labels, or split membership.

The final test has already been consumed. Task 32 may deterministically
reproduce the frozen test probabilities for descriptive analysis only, and only
when the reproduced test-score hash exactly matches the frozen Task 31 report.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from statistics import mean, median
from typing import Any, Mapping, Sequence

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from ml.data.stage_b_features import validate_feature_dataset
from ml.training.stage_b_calibration import (
    _rows,
    _scores_hash,
    _selected_spec,
    _xy,
    validate_calibration_policy,
)
from ml.training.stage_b_contextual_locked_final_v2 import (
    BRAND_ROLE,
    LOCK_SCHEMA,
    PROTOCOL_ID,
    TASK31_SCHEMA,
    canonical_hash,
)

EVIDENCE_SCHEMA = "stage-b-contextual-v2-final-evidence-seal-1"
ERROR_ANALYSIS_SCHEMA = "stage-b-contextual-v2-read-only-error-analysis-1"


class FinalEvidenceSealError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FinalEvidenceSealError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalEvidenceSealError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise FinalEvidenceSealError(
            f"JSON root must be an object: {path}"
        )
    return value


def _require_hex(name: str, value: Any, length: int = 64) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(c not in "0123456789abcdefABCDEF" for c in value)
    ):
        raise FinalEvidenceSealError(
            f"{name} must be a {length}-character hexadecimal digest"
        )
    return value.lower()


def verify_final_evidence_chain(
    *,
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    task30_report: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    calibration_policy: Mapping[str, Any],
    final_lock: Mapping[str, Any],
    final_report: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
        active_policy = validate_calibration_policy(calibration_policy)
    except Exception as exc:
        raise FinalEvidenceSealError(
            f"invalid frozen evidence input: {exc}"
        ) from exc

    if final_lock.get("schema_version") != LOCK_SCHEMA:
        raise FinalEvidenceSealError("final-test lock schema mismatch")
    if final_lock.get("research_protocol") != PROTOCOL_ID:
        raise FinalEvidenceSealError("final-test lock protocol mismatch")
    if final_lock.get("research_only") is not True:
        raise FinalEvidenceSealError("final-test lock lost research-only guard")
    if final_lock.get("deployment_authorized") is not False:
        raise FinalEvidenceSealError(
            "final-test lock unexpectedly authorizes deployment"
        )
    if final_lock.get("repeated_tuning_prohibited") is not True:
        raise FinalEvidenceSealError(
            "final-test lock does not prohibit repeated tuning"
        )

    if final_report.get("schema_version") != TASK31_SCHEMA:
        raise FinalEvidenceSealError("Task 31 final report schema mismatch")
    if final_report.get("status") != "PASS":
        raise FinalEvidenceSealError("Task 31 final report is not PASS")
    if final_report.get("research_protocol") != PROTOCOL_ID:
        raise FinalEvidenceSealError("Task 31 protocol mismatch")
    if final_report.get("research_only") is not True:
        raise FinalEvidenceSealError("Task 31 lost research-only guard")
    if final_report.get("deployment_authorized") is not False:
        raise FinalEvidenceSealError(
            "Task 31 unexpectedly authorizes deployment"
        )
    if final_report.get("integration_eligible") is not False:
        raise FinalEvidenceSealError(
            "Task 31 unexpectedly authorizes integration"
        )
    if final_report.get("production_readiness_equivalent") is not False:
        raise FinalEvidenceSealError(
            "Task 31 unexpectedly claims production equivalence"
        )

    contract = final_report.get("test_contract")
    if not isinstance(contract, Mapping):
        raise FinalEvidenceSealError("Task 31 test contract missing")
    expected_flags = {
        "role": "FINAL_EVALUATION_ONLY",
        "model_family_frozen_before_test": True,
        "calibration_method_frozen_before_test": True,
        "threshold_frozen_before_test": True,
        "test_used_for_model_selection": False,
        "test_used_for_calibration": False,
        "test_used_for_threshold_selection": False,
        "repeated_tuning_after_test_prohibited": True,
    }
    for key, expected in expected_flags.items():
        if contract.get(key) != expected:
            raise FinalEvidenceSealError(
                f"Task 31 test contract mismatch: {key}"
            )

    dataset_hash = canonical_hash(validated)
    if final_lock.get("feature_dataset_sha256") != dataset_hash:
        raise FinalEvidenceSealError(
            "final lock feature dataset identity mismatch"
        )
    chain = final_report.get("evidence_chain")
    if not isinstance(chain, Mapping):
        raise FinalEvidenceSealError("Task 31 evidence chain missing")
    if chain.get("feature_dataset_sha256") != dataset_hash:
        raise FinalEvidenceSealError(
            "final report feature dataset identity mismatch"
        )

    identities = {
        "readiness_sha256": canonical_hash(readiness),
        "task30_report_sha256": canonical_hash(task30_report),
        "benchmark_sha256": canonical_hash(benchmark),
        "calibration_sha256": canonical_hash(calibration),
        "calibration_policy_sha256": canonical_hash(active_policy),
    }
    for key, expected in identities.items():
        if final_lock.get(key) != expected:
            raise FinalEvidenceSealError(
                f"final lock evidence identity mismatch: {key}"
            )
        if chain.get(key) != expected:
            raise FinalEvidenceSealError(
                f"final report evidence identity mismatch: {key}"
            )

    if final_report.get("final_test_lock_sha256") != canonical_hash(
        final_lock
    ):
        raise FinalEvidenceSealError(
            "Task 31 report does not canonically bind the final lock"
        )

    test_partition_sha = _require_hex(
        "test_partition_sha256",
        chain.get("test_partition_sha256"),
    )
    if final_lock.get("test_partition_sha256") != test_partition_sha:
        raise FinalEvidenceSealError(
            "lock/report test-partition identity mismatch"
        )

    score_sha = _require_hex(
        "test_score_sha256",
        final_report.get("test_score_sha256"),
    )

    fixed = final_report.get("fixed_operating_point")
    if not isinstance(fixed, Mapping):
        raise FinalEvidenceSealError(
            "Task 31 fixed operating point missing"
        )

    threshold = fixed.get("threshold")
    if type(threshold) not in (int, float) or not math.isfinite(
        float(threshold)
    ):
        raise FinalEvidenceSealError("Task 31 threshold is invalid")

    if final_lock.get("primary_threshold") != threshold:
        raise FinalEvidenceSealError(
            "final lock/report threshold mismatch"
        )

    selected = final_report.get("selected_candidate")
    if not isinstance(selected, str) or not selected:
        raise FinalEvidenceSealError(
            "Task 31 selected candidate is invalid"
        )
    if final_lock.get("selected_candidate") != selected:
        raise FinalEvidenceSealError(
            "final lock/report candidate mismatch"
        )

    readiness_guard = {
        "research_protocol": readiness.get("research_protocol"),
        "research_only": readiness.get("research_only"),
        "deployment_authorized": readiness.get("deployment_authorized"),
        "brand_group_role": readiness.get("brand_group_role"),
    }
    if readiness_guard != {
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "deployment_authorized": False,
        "brand_group_role": BRAND_ROLE,
    }:
        raise FinalEvidenceSealError(
            "readiness contextual-v2 guard mismatch"
        )

    return {
        "validated_features": validated,
        "active_policy": active_policy,
        "dataset_sha256": dataset_hash,
        "test_partition_sha256": test_partition_sha,
        "test_score_sha256": score_sha,
        "selected_candidate": selected,
        "threshold": float(threshold),
    }


def reproduce_frozen_test_scores(
    *,
    feature_data: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    policy: Mapping[str, Any],
    expected_test_score_sha256: str,
) -> tuple[list[dict[str, Any]], np.ndarray, np.ndarray]:
    selected_candidate = str(benchmark["selected_candidate"])
    if selected_candidate != calibration.get("selected_candidate"):
        raise FinalEvidenceSealError(
            "benchmark/calibration selected-candidate mismatch"
        )

    spec = _selected_spec(selected_candidate)
    x_refit, y_refit = _xy(feature_data, ("train", "selection"))
    calibration_rows = _rows(feature_data, "calibration")
    x_calibration, y_calibration = _xy(
        feature_data,
        ("calibration",),
    )

    base_model = spec.factory()
    base_model.fit(x_refit, y_refit)
    calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model),
        method=policy["method"],
    )
    calibrator.fit(x_calibration, y_calibration)

    reproduced_calibration_scores = np.asarray(
        calibrator.predict_proba(x_calibration)[:, 1],
        dtype=float,
    )
    reproduced_calibration_hash = _scores_hash(
        calibration_rows,
        reproduced_calibration_scores,
    )
    if reproduced_calibration_hash != calibration.get(
        "calibration_scores_sha256"
    ):
        raise FinalEvidenceSealError(
            "reproduced calibration scores no longer match frozen calibration"
        )

    test_rows = _rows(feature_data, "test")
    x_test, y_test = _xy(feature_data, ("test",))
    scores = np.asarray(
        calibrator.predict_proba(x_test)[:, 1],
        dtype=float,
    )
    if scores.shape != y_test.shape or not np.isfinite(scores).all():
        raise FinalEvidenceSealError(
            "reproduced test probabilities are invalid"
        )

    score_material = [
        {
            "sample_id": row["sample_id"],
            "score": round(float(score), 12),
        }
        for row, score in sorted(
            zip(test_rows, scores, strict=True),
            key=lambda pair: pair[0]["sample_id"],
        )
    ]
    reproduced_hash = canonical_hash(score_material)
    if reproduced_hash != expected_test_score_sha256:
        raise FinalEvidenceSealError(
            "reproduced test-score hash differs from frozen Task 31 result; "
            "read-only analysis is prohibited"
        )

    return test_rows, y_test, scores


def _safe_float(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise FinalEvidenceSealError(
            "non-finite value encountered during analysis"
        )
    return value


def _quantiles(values: Sequence[float]) -> dict[str, float] | None:
    if not values:
        return None
    array = np.asarray(values, dtype=float)
    return {
        "min": _safe_float(np.min(array)),
        "p25": _safe_float(np.quantile(array, 0.25)),
        "median": _safe_float(np.median(array)),
        "p75": _safe_float(np.quantile(array, 0.75)),
        "max": _safe_float(np.max(array)),
        "mean": _safe_float(np.mean(array)),
    }


def _feature_contrasts(
    *,
    feature_names: Sequence[str],
    rows: Sequence[Mapping[str, Any]],
    mask_a: np.ndarray,
    mask_b: np.ndarray,
    label_a: str,
    label_b: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    if mask_a.sum() == 0 or mask_b.sum() == 0:
        return []

    matrix = np.asarray(
        [row["feature_vector"] for row in rows],
        dtype=float,
    )
    a = matrix[mask_a]
    b = matrix[mask_b]

    pooled = matrix[np.logical_or(mask_a, mask_b)]
    scale = np.std(pooled, axis=0)
    raw_delta = np.mean(a, axis=0) - np.mean(b, axis=0)
    standardized = np.divide(
        raw_delta,
        scale,
        out=np.zeros_like(raw_delta),
        where=scale > 1e-12,
    )

    ranking = np.argsort(np.abs(standardized))[::-1][:limit]
    result: list[dict[str, Any]] = []
    for index in ranking:
        result.append({
            "feature": str(feature_names[index]),
            f"{label_a}_mean": _safe_float(np.mean(a[:, index])),
            f"{label_b}_mean": _safe_float(np.mean(b[:, index])),
            "mean_difference": _safe_float(raw_delta[index]),
            "standardized_difference": _safe_float(
                standardized[index]
            ),
        })
    return result


def build_read_only_error_analysis(
    *,
    feature_data: Mapping[str, Any],
    test_rows: Sequence[Mapping[str, Any]],
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    test_score_sha256: str,
) -> dict[str, Any]:
    feature_names = feature_data.get("feature_names")
    if (
        not isinstance(feature_names, list)
        or not feature_names
        or not all(isinstance(name, str) for name in feature_names)
    ):
        raise FinalEvidenceSealError(
            "feature_names missing from validated feature dataset"
        )

    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    predicted = scores >= float(threshold)

    tn = np.logical_and(labels == 0, ~predicted)
    fp = np.logical_and(labels == 0, predicted)
    fn = np.logical_and(labels == 1, ~predicted)
    tp = np.logical_and(labels == 1, predicted)

    groups = {
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "true_positive": tp,
    }

    score_summary = {
        name: _quantiles(scores[mask].tolist())
        for name, mask in groups.items()
    }

    margin = np.abs(scores - float(threshold))
    margin_summary = {
        name: _quantiles(margin[mask].tolist())
        for name, mask in groups.items()
    }

    # No sample IDs, host/domain names, brand names, URLs, HTML, or event
    # payloads are emitted. The analysis is deliberately aggregate-only.
    return {
        "schema_version": ERROR_ANALYSIS_SCHEMA,
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "test_already_consumed": True,
        "analysis_role": "DESCRIPTIVE_ONLY_NO_TUNING_AUTHORITY",
        "frozen_threshold": float(threshold),
        "verified_test_score_sha256": test_score_sha256,
        "sample_counts": {
            name: int(mask.sum())
            for name, mask in groups.items()
        },
        "score_distribution_by_outcome": score_summary,
        "absolute_threshold_margin_by_outcome": margin_summary,
        "feature_contrasts": {
            "false_positive_vs_true_negative": _feature_contrasts(
                feature_names=feature_names,
                rows=test_rows,
                mask_a=fp,
                mask_b=tn,
                label_a="false_positive",
                label_b="true_negative",
            ),
            "false_negative_vs_true_positive": _feature_contrasts(
                feature_names=feature_names,
                rows=test_rows,
                mask_a=fn,
                mask_b=tp,
                label_a="false_negative",
                label_b="true_positive",
            ),
        },
        "privacy": {
            "aggregate_only": True,
            "sample_ids_emitted": False,
            "domains_emitted": False,
            "brands_emitted": False,
            "urls_emitted": False,
            "raw_html_emitted": False,
            "event_payloads_emitted": False,
        },
        "interpretation_guard": (
            "These descriptive contrasts may motivate hypotheses for a NEW "
            "experimental generation, but must not be used to retune Stage B "
            "v2 and then rescore the same consumed test as a fresh final test."
        ),
    }


def build_final_evidence_seal(
    *,
    verification: Mapping[str, Any],
    final_lock: Mapping[str, Any],
    final_report: Mapping[str, Any],
    lock_file_sha256: str,
    final_report_file_sha256: str,
    pre_final_commit: str,
    pre_final_tag: str | None,
    tag_target_commit: str | None,
    error_analysis: Mapping[str, Any],
) -> dict[str, Any]:
    lock_file_sha256 = _require_hex(
        "lock_file_sha256",
        lock_file_sha256,
    )
    final_report_file_sha256 = _require_hex(
        "final_report_file_sha256",
        final_report_file_sha256,
    )
    pre_final_commit = _require_hex(
        "pre_final_commit",
        pre_final_commit,
        40,
    )

    if (
        pre_final_tag is not None
        and tag_target_commit is not None
        and tag_target_commit.lower() != pre_final_commit
    ):
        raise FinalEvidenceSealError(
            "pre-final tag does not resolve to the expected pre-final commit"
        )

    fixed = final_report["fixed_operating_point"]
    cm = fixed["confusion_matrix"]

    return {
        "schema_version": EVIDENCE_SCHEMA,
        "status": "PASS",
        "research_protocol": PROTOCOL_ID,
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "final_test_consumed": True,
        "future_tuning_on_same_test_prohibited": True,
        "pre_final_git": {
            "commit": pre_final_commit,
            "tag": pre_final_tag,
            "tag_target_commit": tag_target_commit,
        },
        "file_hashes_sha256": {
            "final_test_lock": lock_file_sha256,
            "final_evaluation": final_report_file_sha256,
        },
        "canonical_evidence_hashes": {
            "final_test_lock": canonical_hash(final_lock),
            "final_evaluation": canonical_hash(final_report),
            "feature_dataset": verification["dataset_sha256"],
            "test_partition": verification[
                "test_partition_sha256"
            ],
            "test_scores": verification["test_score_sha256"],
        },
        "frozen_model": {
            "selected_candidate": verification[
                "selected_candidate"
            ],
            "calibration_method": final_report[
                "calibration_method"
            ],
            "threshold": verification["threshold"],
        },
        "locked_test_result": {
            "samples": final_report["test_samples"],
            "confusion_matrix": dict(cm),
            "precision": fixed["precision"],
            "recall": fixed["recall"],
            "observed_fpr": fixed["observed_fpr"],
            "fpr_wilson_95": fixed["fpr_wilson_95"],
            "average_precision": final_report[
                "threshold_free_metrics"
            ]["average_precision"],
            "roc_auc": final_report[
                "threshold_free_metrics"
            ]["roc_auc"],
            "brier_score": final_report[
                "threshold_free_metrics"
            ]["brier_score"],
            "research_fpr_cap": fixed[
                "research_fpr_cap"
            ],
            "observed_fpr_within_research_cap": fixed[
                "observed_fpr_within_research_cap"
            ],
            "wilson_95_upper_within_research_cap": fixed[
                "wilson_95_upper_within_research_cap"
            ],
        },
        "error_analysis_sha256": canonical_hash(error_analysis),
        "conclusion": {
            "procedure_status": "PASS",
            "research_fpr_objective_supported": bool(
                fixed["observed_fpr_within_research_cap"]
                and fixed[
                    "wilson_95_upper_within_research_cap"
                ]
            ),
            "deployment_authorized": False,
        },
        "limitations": [
            "The final test is already consumed and cannot be reused as an untouched final evaluation after tuning.",
            "The research protocol uses one archived dataset source and is not production-readiness equivalent.",
            "The Task 32 error analysis is descriptive and aggregate-only.",
            "Any model, feature, calibration, or threshold change must begin a new experimental generation with a new untouched final holdout.",
        ],
    }
