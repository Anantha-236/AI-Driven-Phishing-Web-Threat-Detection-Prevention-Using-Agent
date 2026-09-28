"""Stage C Task 22 — evaluate frozen calibration scores and freeze threshold analysis.

Consumes Task-21 authorization, verifies the exact frozen calibration score/label
identities, computes descriptive metrics, and freezes the deterministic low-FPR
threshold sweep. No threshold is selected or frozen here.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import subprocess
from typing import Any, Mapping

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score

EVALUATION_SCHEMA = "stage-c-calibration-evaluation-1"
EXPECTED_AUTHORIZATION_SHA256 = "7fc833b8fb9e4a8d90d744102e38fcc7fbcbd2bf7e572b51c0fb36b9198bb518"
EXPECTED_SCORE_DATASET_SHA256 = "2b4db7e3d47f52994cc67a6f660a1e8603b710c48458fffd5c5923ac35c762fa"
EXPECTED_SCORE_VECTOR_SHA256 = "461dc8101677adf4964d4e8cbb8408d523a6c9523270f1978c803dc332e51467"
EXPECTED_LABEL_VECTOR_SHA256 = "9111a86fa2c563825c4f0463713781930ea3ef072fbdfe85a9e693e0741ecf14"
EXPECTED_EVALUATION_INPUT_SHA256 = "651644c1f5fe766b1ed9009cd326d97add6f63c0b70dbf0442234719ab45028b"
EXPECTED_SAMPLE_SET_SHA256 = "4ecace3342256b1a97fd419b4ec18cc6fdbd07b0e216482847ef959fd63e135e"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_CALIBRATION_COUNT = 7314
EXPECTED_LABEL_COUNTS = {"legitimate": 5584, "phishing": 1730}
EXPECTED_PRIMARY_FPR_CAP = 0.01
EXPECTED_CONFIDENCE_LEVEL = 0.95
WILSON_Z_95 = 1.959963984540054
EXPECTED_NUMPY_VERSION = "2.5.2"
EXPECTED_SKLEARN_VERSION = "1.9.0"
EXPECTED_SCORE_ROW_FIELDS = {"sample_id", "phishing_probability"}
EXPECTED_FEATURE_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector", "collection_incomplete",
    "dropped_events", "delivery_errors", "history_truncated",
}


class StageCCalibrationEvaluationError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_without(value: Mapping[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return canonical_hash(copy)


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCCalibrationEvaluationError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCalibrationEvaluationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCCalibrationEvaluationError(f"JSON root must be object: {path}")
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCCalibrationEvaluationError(
                f"refusing to replace non-identical frozen Task-22 output: {path}"
            )
        return "EXISTING_MATCH"
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with tmp.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return "CREATED"


def validate_authorization(auth: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-calibration-label-evaluation-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "model_scoring_performed": True,
        "calibration_feature_scoring_complete": True,
        "calibration_label_access_authorized": True,
        "calibration_label_verification_performed": True,
        "calibration_metric_computation_authorized": True,
        "calibration_metrics_computed": False,
        "calibration_fitting_authorized": False,
        "threshold_analysis_authorized": True,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "EVALUATE_FROZEN_CALIBRATION_SCORES_AGAINST_FROZEN_"
            "CALIBRATION_LABELS_AND_ANALYZE_LOW_FPR_THRESHOLDS"
        ),
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "next_gate": (
            "EVALUATE_STAGE_C_CALIBRATION_SCORES_AND_FREEZE_THRESHOLD_"
            "ANALYSIS_WITHOUT_THRESHOLD_SELECTION"
        ),
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCCalibrationEvaluationError(f"Task-21 authorization guard mismatch: {key}")
    if hash_without(auth, "authorization_sha256") != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCCalibrationEvaluationError("Task-21 canonical authorization hash mismatch")

    scope = auth.get("evaluation_scope")
    analysis = auth.get("authorized_metrics_and_analysis")
    experiment = auth.get("experiment_constraints")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(isinstance(x, Mapping) for x in (scope, analysis, experiment, bindings, prohibitions)):
        raise StageCCalibrationEvaluationError("Task-21 authorization sections missing")

    checks = [
        (scope.get("calibration_sample_count") == EXPECTED_CALIBRATION_COUNT, "sample count"),
        (scope.get("calibration_sample_set_sha256") == EXPECTED_SAMPLE_SET_SHA256, "sample set"),
        (scope.get("calibration_label_counts") == EXPECTED_LABEL_COUNTS, "label counts"),
        (scope.get("calibration_label_vector_sha256") == EXPECTED_LABEL_VECTOR_SHA256, "label vector"),
        (scope.get("score_dataset_sha256") == EXPECTED_SCORE_DATASET_SHA256, "score dataset"),
        (scope.get("score_vector_sha256") == EXPECTED_SCORE_VECTOR_SHA256, "score vector"),
        (scope.get("evaluation_input_sha256") == EXPECTED_EVALUATION_INPUT_SHA256, "evaluation input"),
        (analysis.get("average_precision") is True, "AP authorization"),
        (analysis.get("roc_auc") is True, "ROC authorization"),
        (analysis.get("brier_score") is True, "Brier authorization"),
        (analysis.get("log_loss") is True, "log-loss authorization"),
        (analysis.get("low_fpr_threshold_sweep") is True, "sweep authorization"),
        (analysis.get("primary_fpr_cap") == EXPECTED_PRIMARY_FPR_CAP, "analysis FPR cap"),
        (analysis.get("threshold_freeze_authorized") is False, "threshold-freeze authorization"),
        (experiment.get("primary_metric") == "false_positive_rate", "primary metric"),
        (experiment.get("primary_fpr_cap") == EXPECTED_PRIMARY_FPR_CAP, "experiment FPR cap"),
        (experiment.get("confidence_level") == EXPECTED_CONFIDENCE_LEVEL, "confidence"),
        (experiment.get("secondary_metric") == "recall", "secondary metric"),
        (bindings.get("task20_score_dataset_sha256") == EXPECTED_SCORE_DATASET_SHA256, "Task-20 dataset binding"),
        (bindings.get("task20_score_vector_sha256") == EXPECTED_SCORE_VECTOR_SHA256, "Task-20 vector binding"),
        (bindings.get("feature_dataset_sha256") == EXPECTED_FEATURE_DATASET_SHA256, "feature dataset binding"),
        (prohibitions.get("model_refit") is True, "refit prohibition"),
        (prohibitions.get("score_regeneration") is True, "score regeneration prohibition"),
        (prohibitions.get("calibration_fitting") is True, "calibration fitting prohibition"),
        (prohibitions.get("threshold_freeze") is True, "threshold freeze prohibition"),
        (prohibitions.get("reuse_selection_diagnostic_threshold") is True, "selection threshold prohibition"),
        (prohibitions.get("final_holdout_access") is True, "holdout prohibition"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCCalibrationEvaluationError(f"Task-21 authorization changed: {name}")


def load_evaluation_input(
    *, feature_dataset_path: Path, score_dataset_path: Path
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCCalibrationEvaluationError("feature dataset SHA-256 mismatch")
    if sha256_file(score_dataset_path) != EXPECTED_SCORE_DATASET_SHA256:
        raise StageCCalibrationEvaluationError("calibration score dataset SHA-256 mismatch")

    score_rows: list[dict[str, Any]] = []
    with score_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCalibrationEvaluationError(
                    f"invalid score JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_SCORE_ROW_FIELDS:
                raise StageCCalibrationEvaluationError("score row closed-schema mismatch")
            sid = row["sample_id"]
            score = row["phishing_probability"]
            if not isinstance(sid, str) or not sid:
                raise StageCCalibrationEvaluationError("score sample_id invalid")
            if type(score) not in (int, float) or not math.isfinite(score):
                raise StageCCalibrationEvaluationError("score value invalid")
            score = float(score)
            if not 0.0 <= score <= 1.0:
                raise StageCCalibrationEvaluationError("score outside [0,1]")
            score_rows.append({"sample_id": sid, "phishing_probability": score})

    if len(score_rows) != EXPECTED_CALIBRATION_COUNT:
        raise StageCCalibrationEvaluationError("calibration score count changed")
    sample_ids = [row["sample_id"] for row in score_rows]
    if sample_ids != sorted(sample_ids) or len(set(sample_ids)) != len(sample_ids):
        raise StageCCalibrationEvaluationError("calibration score order/uniqueness changed")
    if canonical_hash(sample_ids) != EXPECTED_SAMPLE_SET_SHA256:
        raise StageCCalibrationEvaluationError("calibration sample-set identity changed")
    if canonical_hash(score_rows) != EXPECTED_SCORE_VECTOR_SHA256:
        raise StageCCalibrationEvaluationError("calibration score-vector identity changed")

    wanted = set(sample_ids)
    labels: list[dict[str, Any]] = []
    seen_all: set[str] = set()
    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCalibrationEvaluationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_FEATURE_ROW_FIELDS:
                raise StageCCalibrationEvaluationError("feature row closed-schema mismatch")
            sid = row["sample_id"]
            if not isinstance(sid, str) or not sid or sid in seen_all:
                raise StageCCalibrationEvaluationError("feature sample_id invalid/duplicate")
            seen_all.add(sid)
            if sid in wanted:
                if row["partition"] != "calibration" or row["collection_incomplete"]:
                    raise StageCCalibrationEvaluationError(
                        "authorized calibration sample changed partition/completeness"
                    )
                if row["label"] not in (0, 1):
                    raise StageCCalibrationEvaluationError("calibration label invalid")
                labels.append({"sample_id": sid, "label": int(row["label"])})

    labels.sort(key=lambda x: x["sample_id"])
    if [x["sample_id"] for x in labels] != sample_ids:
        raise StageCCalibrationEvaluationError("calibration label coverage changed")
    if canonical_hash(labels) != EXPECTED_LABEL_VECTOR_SHA256:
        raise StageCCalibrationEvaluationError("calibration label-vector identity changed")

    label_counts = {
        "legitimate": sum(x["label"] == 0 for x in labels),
        "phishing": sum(x["label"] == 1 for x in labels),
    }
    if label_counts != EXPECTED_LABEL_COUNTS:
        raise StageCCalibrationEvaluationError("calibration label counts changed")

    label_by_id = {x["sample_id"]: x["label"] for x in labels}
    joined = [
        {
            "sample_id": row["sample_id"],
            "label": label_by_id[row["sample_id"]],
            "phishing_probability": row["phishing_probability"],
        }
        for row in score_rows
    ]
    if canonical_hash(joined) != EXPECTED_EVALUATION_INPUT_SHA256:
        raise StageCCalibrationEvaluationError("calibration evaluation-input identity changed")

    y = np.asarray([label_by_id[sid] for sid in sample_ids], dtype=np.int64)
    scores = np.asarray([row["phishing_probability"] for row in score_rows], dtype=np.float64)
    return y, scores, {
        "calibration_sample_count": EXPECTED_CALIBRATION_COUNT,
        "calibration_sample_set_sha256": EXPECTED_SAMPLE_SET_SHA256,
        "calibration_label_counts": EXPECTED_LABEL_COUNTS,
        "calibration_label_vector_sha256": EXPECTED_LABEL_VECTOR_SHA256,
        "score_dataset_sha256": EXPECTED_SCORE_DATASET_SHA256,
        "score_vector_sha256": EXPECTED_SCORE_VECTOR_SHA256,
        "evaluation_input_sha256": EXPECTED_EVALUATION_INPUT_SHA256,
    }


def wilson_upper_95(false_positives: int, legitimate_count: int) -> float:
    if type(false_positives) is not int or type(legitimate_count) is not int:
        raise StageCCalibrationEvaluationError("Wilson counts must be integers")
    if legitimate_count <= 0 or false_positives < 0 or false_positives > legitimate_count:
        raise StageCCalibrationEvaluationError("Wilson counts invalid")
    p = false_positives / legitimate_count
    z2 = WILSON_Z_95 * WILSON_Z_95
    denom = 1.0 + z2 / legitimate_count
    center = p + z2 / (2.0 * legitimate_count)
    spread = WILSON_Z_95 * math.sqrt(
        p * (1.0 - p) / legitimate_count
        + z2 / (4.0 * legitimate_count * legitimate_count)
    )
    return (center + spread) / denom


def low_fpr_threshold_sweep(y: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    if y.ndim != 1 or scores.ndim != 1 or len(y) != len(scores):
        raise StageCCalibrationEvaluationError("threshold sweep arrays invalid")
    if len(y) != EXPECTED_CALIBRATION_COUNT or set(y.tolist()) != {0, 1}:
        raise StageCCalibrationEvaluationError("threshold sweep labels invalid")
    if not np.isfinite(scores).all() or np.any(scores < 0.0) or np.any(scores > 1.0):
        raise StageCCalibrationEvaluationError("threshold sweep scores invalid")

    positive_count = int(np.sum(y == 1))
    legitimate_count = int(np.sum(y == 0))
    order = np.argsort(-scores, kind="mergesort")
    sorted_scores = scores[order]
    sorted_y = y[order]
    sentinel_threshold = math.nextafter(float(sorted_scores[0]), math.inf)
    points: list[dict[str, Any]] = []

    def make_point(threshold: float, tp: int, fp: int, *, sentinel: bool) -> dict[str, Any]:
        fn = positive_count - tp
        tn = legitimate_count - fp
        fpr = fp / legitimate_count
        recall = tp / positive_count
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        wilson = wilson_upper_95(fp, legitimate_count)
        compliant = fpr <= EXPECTED_PRIMARY_FPR_CAP and wilson <= EXPECTED_PRIMARY_FPR_CAP
        return {
            "threshold": threshold,
            "threshold_is_above_max_score_sentinel": sentinel,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "observed_fpr": fpr,
            "wilson_upper_95": wilson,
            "recall": recall,
            "precision": precision,
            "primary_constraint_satisfied": compliant,
        }

    tp = fp = 0
    points.append(make_point(sentinel_threshold, tp, fp, sentinel=True))
    i = 0
    n = len(sorted_scores)
    while i < n:
        threshold = float(sorted_scores[i])
        j = i
        while j < n and float(sorted_scores[j]) == threshold:
            if int(sorted_y[j]) == 1:
                tp += 1
            else:
                fp += 1
            j += 1
        points.append(make_point(threshold, tp, fp, sentinel=False))
        i = j

    compliant = [p for p in points if p["primary_constraint_satisfied"]]
    diagnostic = None
    if compliant:
        diagnostic = max(
            compliant,
            key=lambda p: (p["recall"], -p["observed_fpr"], p["threshold"]),
        )
        diagnostic = dict(diagnostic)
        diagnostic["threshold_selected"] = False
        diagnostic["threshold_frozen"] = False
        diagnostic["diagnostic_only"] = True

    return {
        "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
        "point_count": len(points),
        "sweep_sha256": canonical_hash(points),
        "primary_fpr_cap": EXPECTED_PRIMARY_FPR_CAP,
        "confidence_level": EXPECTED_CONFIDENCE_LEVEL,
        "constraint_feasible": diagnostic is not None,
        "diagnostic_max_recall_point_under_primary_constraint": diagnostic,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
    }


def evaluate_calibration(y: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    if y.ndim != 1 or scores.ndim != 1 or len(y) != len(scores):
        raise StageCCalibrationEvaluationError("calibration evaluation arrays invalid")
    if len(y) != EXPECTED_CALIBRATION_COUNT or set(y.tolist()) != {0, 1}:
        raise StageCCalibrationEvaluationError("calibration evaluation labels invalid")
    if not np.isfinite(scores).all():
        raise StageCCalibrationEvaluationError("calibration scores non-finite")

    metrics = {
        "average_precision": float(average_precision_score(y, scores)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "brier_score": float(brier_score_loss(y, scores)),
        "log_loss": float(log_loss(y, scores, labels=[0, 1])),
    }
    if any(not math.isfinite(v) for v in metrics.values()):
        raise StageCCalibrationEvaluationError("calibration metric non-finite")

    return {
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "calibration_sample_count": len(y),
        "calibration_legitimate_count": int(np.sum(y == 0)),
        "calibration_phishing_count": int(np.sum(y == 1)),
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "score_mean": float(np.mean(scores)),
        "metrics": metrics,
        "threshold_analysis": low_fpr_threshold_sweep(y, scores),
        "threshold_selected": False,
        "threshold_frozen": False,
    }


def _environment() -> dict[str, str]:
    versions = {
        "python": platform.python_version(),
        "numpy": importlib.metadata.version("numpy"),
        "scikit-learn": importlib.metadata.version("scikit-learn"),
    }
    if versions["numpy"] != EXPECTED_NUMPY_VERSION:
        raise StageCCalibrationEvaluationError(
            f"numpy version changed: {versions['numpy']} != {EXPECTED_NUMPY_VERSION}"
        )
    if versions["scikit-learn"] != EXPECTED_SKLEARN_VERSION:
        raise StageCCalibrationEvaluationError(
            "scikit-learn version changed: "
            f"{versions['scikit-learn']} != {EXPECTED_SKLEARN_VERSION}"
        )
    return versions


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_calibration_evaluation.py",
        "ml/evaluation/evaluate_stage_c_calibration.py",
        "ml/evaluation/stage_c_calibration_label_evaluation_authorization.py",
        "ml/evaluation/stage_c_calibration_score_generation.py",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            capture_output=True, text=True, encoding="utf-8", check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCCalibrationEvaluationError("invalid Git HEAD identity")
        for relative in paths:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"],
                cwd=repo_root, capture_output=True, check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *paths], cwd=repo_root
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCCalibrationEvaluationError(
            "Task-22 and bound evaluation files must be committed before evaluation"
        ) from exc
    if dirty != 0:
        raise StageCCalibrationEvaluationError(
            "Task-22/bound evaluation files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task22_module_sha256": sha256_file(repo_root / paths[0]),
        "task22_cli_sha256": sha256_file(repo_root / paths[1]),
        "task21_module_sha256": sha256_file(repo_root / paths[2]),
        "task20_module_sha256": sha256_file(repo_root / paths[3]),
    }


def evaluate_stage_c_calibration(
    *, repo_root: Path, feature_dataset_path: Path, score_dataset_path: Path,
    authorization_path: Path, output_root: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    validate_authorization(auth)
    y, scores, input_identity = load_evaluation_input(
        feature_dataset_path=feature_dataset_path,
        score_dataset_path=score_dataset_path,
    )
    environment = _environment()
    git = _git_provenance(repo_root)
    evaluation = evaluate_calibration(y, scores)
    analysis_sha256 = canonical_hash(evaluation)

    report = {
        "schema_version": EVALUATION_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "calibration_metric_computation_authorized": True,
        "calibration_metrics_computed": True,
        "threshold_analysis_authorized": True,
        "threshold_analysis_performed": True,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "calibration_fitting_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "score_dataset_sha256": EXPECTED_SCORE_DATASET_SHA256,
        "evaluation_input": input_identity,
        "primary_objective": {
            "metric": "false_positive_rate",
            "fpr_cap": EXPECTED_PRIMARY_FPR_CAP,
            "confidence_level": EXPECTED_CONFIDENCE_LEVEL,
            "require_observed_fpr_at_or_below_cap": True,
            "require_wilson_upper_at_or_below_cap": True,
            "secondary_metric": "recall",
        },
        "calibration_evaluation": evaluation,
        "threshold_analysis_sha256": analysis_sha256,
        "environment": environment,
        "git_provenance": git,
        "limitations": [
            "Task 22 computes frozen calibration metrics and threshold analysis only.",
            "The diagnostic maximum-recall compliant point is evidence only.",
            "No threshold is selected or frozen.",
            "No calibrator is fit and the model is not refit.",
            "The final holdout remains untouched.",
            "PASS does not authorize deployment.",
        ],
        "next_gate": (
            "ISSUE_STAGE_C_THRESHOLD_SELECTION_AUTHORIZATION_FROM_FROZEN_"
            "CALIBRATION_ANALYSIS"
        ),
    }
    report["evaluation_report_sha256"] = canonical_hash(report)
    report_path = output_root / "calibration-evaluation-report-v1.json"
    state = frozen_write_json(report_path, report)
    point = evaluation["threshold_analysis"][
        "diagnostic_max_recall_point_under_primary_constraint"
    ]
    return {
        "status": "PASS",
        "report": str(report_path),
        "state": state,
        "evaluation_report_sha256": report["evaluation_report_sha256"],
        "threshold_analysis_sha256": analysis_sha256,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "calibration_sample_count": EXPECTED_CALIBRATION_COUNT,
        "metrics": evaluation["metrics"],
        "calibration_metrics_computed": True,
        "threshold_analysis_performed": True,
        "constraint_feasible": evaluation["threshold_analysis"]["constraint_feasible"],
        "diagnostic_max_recall_point_under_primary_constraint": point,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "next_gate": report["next_gate"],
    }
