"""Stage C Task 16 — evaluate frozen selection scores without model selection.

This task computes per-candidate selection metrics and low-FPR diagnostic
operating points from the exact Task-15-authorized evaluation input.

It does NOT rank candidates, choose a candidate, freeze a threshold, access
calibration, refit a model, deploy, or access the final holdout.
"""
from __future__ import annotations

from collections import Counter
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
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    log_loss,
    roc_auc_score,
)

EVALUATION_SCHEMA = "stage-c-selection-evaluation-1"

EXPECTED_AUTHORIZATION_SHA256 = "d70f1ec228a91beba90a424528eaa3e0cda5a0a59213e5b0ee8a4adce42fb491"
EXPECTED_TASK15_GIT_HEAD = "ebce6ac9358071828ecb0782185aa55c209ee6d3"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_SCORE_DATASET_SHA256 = "92bc6429d8a61f3aeed206967c9df526e60388859e742be5eaa3ea0faad822d8"
EXPECTED_SELECTION_COUNT = 20710
EXPECTED_SELECTION_SAMPLE_SET_SHA256 = "0cc84274558ee32889b114633e14782fe14c9dd17e933b8faa929efeab65c0cd"
EXPECTED_SELECTION_LABEL_COUNTS = {"legitimate": 19641, "phishing": 1069}
EXPECTED_SELECTION_LABEL_VECTOR_SHA256 = "691d1e47db54666978079e5df7f9968bc6c705d40fbf0903f9d46a48efc04511"
EXPECTED_EVALUATION_INPUT_SHA256 = "19364663b75166b6fcdc9bd0a24fe8cfe102a3fae80920cd7fe7027082778d33"
EXPECTED_CANDIDATE_COUNT = 4
EXPECTED_SCORE_ROWS = 82840
EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"
EXPECTED_PRIMARY_FPR_CAP = 0.01
EXPECTED_CONFIDENCE_LEVEL = 0.95
WILSON_Z_95 = 1.959963984540054
EXPECTED_NUMPY_VERSION = "2.5.2"
EXPECTED_SKLEARN_VERSION = "1.9.0"

EXPECTED_CANDIDATES = (
    "dummy_prior",
    "hist_gradient_boosting",
    "logistic_regression",
    "random_forest_compact",
)

EXPECTED_FEATURE_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}
EXPECTED_SCORE_ROW_FIELDS = {
    "sample_id", "candidate_id", "phishing_probability",
}


class StageCSelectionEvaluationError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


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
        raise StageCSelectionEvaluationError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCSelectionEvaluationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCSelectionEvaluationError(f"JSON root must be object: {path}")
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCSelectionEvaluationError(
                f"refusing to replace non-identical frozen Task-16 output: {path}"
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


def validate_authorization(auth: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-selection-label-evaluation-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": True,
        "model_scoring_authorized": True,
        "selection_feature_scoring_complete": True,
        "selection_label_access_authorized": True,
        "selection_label_verification_performed": True,
        "selection_metric_computation_authorized": True,
        "selection_metrics_computed": False,
        "model_selection_authorized": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "EVALUATE_FROZEN_SELECTION_SCORES_AGAINST_FROZEN_SELECTION_LABELS"
        ),
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "next_gate": (
            "EVALUATE_STAGE_C_FROZEN_SELECTION_SCORES_WITHOUT_MODEL_SELECTION"
        ),
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCSelectionEvaluationError(
                f"Task-15 authorization guard mismatch: {key}"
            )
    if hash_without(auth, "authorization_sha256") != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCSelectionEvaluationError(
            "Task-15 canonical authorization hash mismatch"
        )

    scope = auth.get("evaluation_scope")
    metrics = auth.get("authorized_metrics")
    experiment = auth.get("experiment_constraints")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(
        isinstance(x, Mapping)
        for x in (scope, metrics, experiment, bindings, prohibitions)
    ):
        raise StageCSelectionEvaluationError(
            "Task-15 authorization sections missing"
        )

    checks = [
        (scope.get("selection_sample_count") == EXPECTED_SELECTION_COUNT, "selection count"),
        (
            scope.get("selection_sample_set_sha256")
            == EXPECTED_SELECTION_SAMPLE_SET_SHA256,
            "selection identity",
        ),
        (
            scope.get("selection_label_counts")
            == EXPECTED_SELECTION_LABEL_COUNTS,
            "selection label counts",
        ),
        (
            scope.get("selection_label_vector_sha256")
            == EXPECTED_SELECTION_LABEL_VECTOR_SHA256,
            "selection label-vector identity",
        ),
        (scope.get("score_row_count") == EXPECTED_SCORE_ROWS, "score row count"),
        (
            scope.get("score_dataset_sha256") == EXPECTED_SCORE_DATASET_SHA256,
            "score dataset identity",
        ),
        (scope.get("candidate_count") == EXPECTED_CANDIDATE_COUNT, "candidate count"),
        (
            scope.get("candidate_artifact_set_sha256")
            == EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
            "candidate artifact set",
        ),
        (
            scope.get("evaluation_input_sha256")
            == EXPECTED_EVALUATION_INPUT_SHA256,
            "evaluation-input identity",
        ),
        (scope.get("join_key") == "sample_id", "join key"),
        (scope.get("label_field") == "label", "label field"),
        (scope.get("score_field") == "phishing_probability", "score field"),
        (metrics.get("average_precision") is True, "AP authorization"),
        (metrics.get("roc_auc") is True, "ROC-AUC authorization"),
        (metrics.get("brier_score") is True, "Brier authorization"),
        (metrics.get("log_loss") is True, "log-loss authorization"),
        (
            metrics.get("low_fpr_threshold_sweep_for_diagnostics") is True,
            "diagnostic sweep authorization",
        ),
        (metrics.get("observed_fpr") is True, "FPR authorization"),
        (metrics.get("wilson_upper_95") is True, "Wilson authorization"),
        (metrics.get("recall") is True, "recall authorization"),
        (
            metrics.get("primary_fpr_cap") == EXPECTED_PRIMARY_FPR_CAP,
            "FPR cap",
        ),
        (
            metrics.get("threshold_freeze_authorized") is False,
            "threshold freeze lock",
        ),
        (
            experiment.get("primary_metric") == "false_positive_rate",
            "primary metric",
        ),
        (
            experiment.get("primary_fpr_cap") == EXPECTED_PRIMARY_FPR_CAP,
            "experiment FPR cap",
        ),
        (
            experiment.get("confidence_level") == EXPECTED_CONFIDENCE_LEVEL,
            "confidence level",
        ),
        (
            experiment.get("require_observed_fpr_at_or_below_cap") is True,
            "observed FPR constraint",
        ),
        (
            experiment.get("require_wilson_upper_at_or_below_cap") is True,
            "Wilson constraint",
        ),
        (experiment.get("secondary_metric") == "recall", "secondary metric"),
        (
            bindings.get("feature_dataset_sha256")
            == EXPECTED_FEATURE_DATASET_SHA256,
            "feature dataset binding",
        ),
        (prohibitions.get("model_refit") is True, "model-refit prohibition"),
        (prohibitions.get("candidate_ranking") is True, "ranking prohibition"),
        (prohibitions.get("candidate_choice") is True, "candidate-choice prohibition"),
        (prohibitions.get("model_selection") is True, "model-selection prohibition"),
        (prohibitions.get("calibration_access") is True, "calibration prohibition"),
        (prohibitions.get("threshold_freeze") is True, "threshold-freeze prohibition"),
        (prohibitions.get("final_holdout_access") is True, "holdout prohibition"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCSelectionEvaluationError(
                f"Task-15 authorization changed: {name}"
            )

    candidate_score_hashes = scope.get("candidate_score_vector_sha256")
    if not isinstance(candidate_score_hashes, Mapping):
        raise StageCSelectionEvaluationError(
            "Task-15 candidate score identities missing"
        )
    if set(candidate_score_hashes) != set(EXPECTED_CANDIDATES):
        raise StageCSelectionEvaluationError(
            "Task-15 candidate score identity set changed"
        )
    if any(
        not isinstance(candidate_score_hashes[cid], str)
        or len(candidate_score_hashes[cid]) != 64
        for cid in EXPECTED_CANDIDATES
    ):
        raise StageCSelectionEvaluationError(
            "Task-15 candidate score identity invalid"
        )
    return dict(candidate_score_hashes)


def load_evaluation_input(
    *,
    feature_dataset_path: Path,
    score_dataset_path: Path,
    expected_candidate_score_hashes: Mapping[str, str],
) -> tuple[np.ndarray, dict[str, np.ndarray], dict[str, Any]]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCSelectionEvaluationError(
            "Task-10 feature dataset SHA-256 mismatch"
        )
    if sha256_file(score_dataset_path) != EXPECTED_SCORE_DATASET_SHA256:
        raise StageCSelectionEvaluationError(
            "Task-14 score dataset SHA-256 mismatch"
        )

    label_rows: list[dict[str, Any]] = []
    seen_all: set[str] = set()
    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCSelectionEvaluationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_FEATURE_ROW_FIELDS:
                raise StageCSelectionEvaluationError(
                    "feature row closed-schema mismatch"
                )
            sid = row["sample_id"]
            part = row["partition"]
            label = row["label"]
            incomplete = row["collection_incomplete"]
            if not isinstance(sid, str) or not sid or sid in seen_all:
                raise StageCSelectionEvaluationError(
                    "duplicate/invalid feature sample_id"
                )
            if part not in {"train", "selection", "calibration"}:
                raise StageCSelectionEvaluationError("feature partition invalid")
            if label not in (0, 1):
                raise StageCSelectionEvaluationError("feature label invalid")
            if type(incomplete) is not bool:
                raise StageCSelectionEvaluationError(
                    "feature collection flag invalid"
                )
            seen_all.add(sid)
            if part == "selection" and not incomplete:
                label_rows.append({"sample_id": sid, "label": int(label)})

    if len(seen_all) != 73777:
        raise StageCSelectionEvaluationError("full feature row count changed")

    label_rows.sort(key=lambda x: x["sample_id"])
    sample_ids = [row["sample_id"] for row in label_rows]
    if len(sample_ids) != EXPECTED_SELECTION_COUNT:
        raise StageCSelectionEvaluationError("selection label count changed")
    if canonical_hash(sample_ids) != EXPECTED_SELECTION_SAMPLE_SET_SHA256:
        raise StageCSelectionEvaluationError(
            "selection sample-set identity changed"
        )
    if canonical_hash(label_rows) != EXPECTED_SELECTION_LABEL_VECTOR_SHA256:
        raise StageCSelectionEvaluationError(
            "selection label-vector identity changed"
        )
    counts = Counter(row["label"] for row in label_rows)
    if {"legitimate": counts[0], "phishing": counts[1]} != EXPECTED_SELECTION_LABEL_COUNTS:
        raise StageCSelectionEvaluationError(
            "selection label counts changed"
        )

    sample_id_set = set(sample_ids)
    scores_by_candidate: dict[str, list[dict[str, Any]]] = {
        cid: [] for cid in EXPECTED_CANDIDATES
    }
    seen_pairs: set[tuple[str, str]] = set()
    observed_order: list[tuple[str, str]] = []

    with score_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCSelectionEvaluationError(
                    f"invalid score JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_SCORE_ROW_FIELDS:
                raise StageCSelectionEvaluationError(
                    "score row closed-schema mismatch"
                )
            sid = row["sample_id"]
            cid = row["candidate_id"]
            score = row["phishing_probability"]
            if sid not in sample_id_set:
                raise StageCSelectionEvaluationError(
                    "score references non-selection sample"
                )
            if cid not in EXPECTED_CANDIDATES:
                raise StageCSelectionEvaluationError(
                    "score candidate identity changed"
                )
            if type(score) not in (int, float) or not math.isfinite(score):
                raise StageCSelectionEvaluationError(
                    "score probability invalid"
                )
            score = float(score)
            if score < 0.0 or score > 1.0:
                raise StageCSelectionEvaluationError(
                    "score probability outside [0,1]"
                )
            pair = (sid, cid)
            if pair in seen_pairs:
                raise StageCSelectionEvaluationError(
                    "duplicate sample/candidate score row"
                )
            seen_pairs.add(pair)
            observed_order.append(pair)
            scores_by_candidate[cid].append({
                "sample_id": sid,
                "phishing_probability": score,
            })

    if len(seen_pairs) != EXPECTED_SCORE_ROWS:
        raise StageCSelectionEvaluationError("score row count changed")
    expected_order = [
        (sid, cid)
        for sid in sample_ids
        for cid in EXPECTED_CANDIDATES
    ]
    if observed_order != expected_order:
        raise StageCSelectionEvaluationError("score dataset order changed")

    score_arrays: dict[str, np.ndarray] = {}
    for cid in EXPECTED_CANDIDATES:
        rows = scores_by_candidate[cid]
        if len(rows) != EXPECTED_SELECTION_COUNT:
            raise StageCSelectionEvaluationError(
                f"candidate score count changed: {cid}"
            )
        actual_sha = canonical_hash(rows)
        if actual_sha != expected_candidate_score_hashes[cid]:
            raise StageCSelectionEvaluationError(
                f"candidate score-vector identity changed: {cid}"
            )
        score_arrays[cid] = np.asarray(
            [row["phishing_probability"] for row in rows],
            dtype=np.float64,
        )

    label_by_id = {
        row["sample_id"]: int(row["label"])
        for row in label_rows
    }
    joined = []
    for index, sid in enumerate(sample_ids):
        for cid in EXPECTED_CANDIDATES:
            joined.append({
                "sample_id": sid,
                "candidate_id": cid,
                "label": label_by_id[sid],
                "phishing_probability": float(score_arrays[cid][index]),
            })
    joined.sort(key=lambda x: (x["sample_id"], x["candidate_id"]))
    if canonical_hash(joined) != EXPECTED_EVALUATION_INPUT_SHA256:
        raise StageCSelectionEvaluationError(
            "evaluation-input identity changed"
        )

    y = np.asarray([row["label"] for row in label_rows], dtype=np.int64)
    return y, score_arrays, {
        "selection_sample_count": EXPECTED_SELECTION_COUNT,
        "selection_sample_set_sha256": EXPECTED_SELECTION_SAMPLE_SET_SHA256,
        "selection_label_counts": EXPECTED_SELECTION_LABEL_COUNTS,
        "selection_label_vector_sha256": EXPECTED_SELECTION_LABEL_VECTOR_SHA256,
        "evaluation_input_sha256": EXPECTED_EVALUATION_INPUT_SHA256,
    }


def wilson_upper_95(false_positives: int, legitimate_count: int) -> float:
    if type(false_positives) is not int or type(legitimate_count) is not int:
        raise StageCSelectionEvaluationError("Wilson counts must be integers")
    if legitimate_count <= 0 or false_positives < 0 or false_positives > legitimate_count:
        raise StageCSelectionEvaluationError("Wilson counts invalid")
    p = false_positives / legitimate_count
    z2 = WILSON_Z_95 * WILSON_Z_95
    denom = 1.0 + z2 / legitimate_count
    center = p + z2 / (2.0 * legitimate_count)
    spread = WILSON_Z_95 * math.sqrt(
        p * (1.0 - p) / legitimate_count
        + z2 / (4.0 * legitimate_count * legitimate_count)
    )
    return (center + spread) / denom


def low_fpr_diagnostic_sweep(
    y: np.ndarray,
    scores: np.ndarray,
) -> dict[str, Any]:
    if y.ndim != 1 or scores.ndim != 1 or len(y) != len(scores):
        raise StageCSelectionEvaluationError("diagnostic sweep arrays invalid")
    if len(y) == 0 or set(y.tolist()) != {0, 1}:
        raise StageCSelectionEvaluationError("diagnostic sweep labels invalid")
    if not np.isfinite(scores).all() or np.any(scores < 0.0) or np.any(scores > 1.0):
        raise StageCSelectionEvaluationError("diagnostic sweep scores invalid")

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
        compliant = (
            fpr <= EXPECTED_PRIMARY_FPR_CAP
            and wilson <= EXPECTED_PRIMARY_FPR_CAP
        )
        return {
            "threshold": threshold,
            "threshold_is_above_max_score_sentinel": sentinel,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "observed_fpr": fpr,
            "wilson_upper_95": wilson,
            "recall": recall,
            "precision": precision,
            "primary_constraint_satisfied": compliant,
        }

    tp = 0
    fp = 0
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

    compliant = [
        point for point in points
        if point["primary_constraint_satisfied"]
    ]
    diagnostic = None
    if compliant:
        diagnostic = max(
            compliant,
            key=lambda point: (
                point["recall"],
                -point["observed_fpr"],
                point["threshold"],
            ),
        )
        diagnostic = dict(diagnostic)
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
        "threshold_frozen": False,
    }


def evaluate_candidate(
    y: np.ndarray,
    scores: np.ndarray,
    candidate_id: str,
) -> dict[str, Any]:
    if candidate_id not in EXPECTED_CANDIDATES:
        raise StageCSelectionEvaluationError("candidate identity invalid")
    if y.ndim != 1 or scores.ndim != 1 or len(y) != len(scores):
        raise StageCSelectionEvaluationError("candidate evaluation arrays invalid")
    if len(y) != EXPECTED_SELECTION_COUNT:
        raise StageCSelectionEvaluationError("candidate evaluation count changed")
    if set(y.tolist()) != {0, 1}:
        raise StageCSelectionEvaluationError("candidate labels invalid")
    if not np.isfinite(scores).all():
        raise StageCSelectionEvaluationError("candidate scores non-finite")

    metrics = {
        "average_precision": float(average_precision_score(y, scores)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "brier_score": float(brier_score_loss(y, scores)),
        "log_loss": float(log_loss(y, scores, labels=[0, 1])),
    }
    if any(not math.isfinite(value) for value in metrics.values()):
        raise StageCSelectionEvaluationError(
            f"non-finite candidate metric: {candidate_id}"
        )

    return {
        "candidate_id": candidate_id,
        "selection_sample_count": len(y),
        "selection_legitimate_count": int(np.sum(y == 0)),
        "selection_phishing_count": int(np.sum(y == 1)),
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "score_mean": float(np.mean(scores)),
        "metrics": metrics,
        "low_fpr_diagnostics": low_fpr_diagnostic_sweep(y, scores),
        "candidate_rank": None,
        "candidate_selected": False,
        "threshold_frozen": False,
    }


def _environment() -> dict[str, str]:
    versions = {
        "python": platform.python_version(),
        "numpy": importlib.metadata.version("numpy"),
        "scikit-learn": importlib.metadata.version("scikit-learn"),
    }
    if versions["numpy"] != EXPECTED_NUMPY_VERSION:
        raise StageCSelectionEvaluationError(
            f"numpy version changed: {versions['numpy']} != {EXPECTED_NUMPY_VERSION}"
        )
    if versions["scikit-learn"] != EXPECTED_SKLEARN_VERSION:
        raise StageCSelectionEvaluationError(
            "scikit-learn version changed: "
            f"{versions['scikit-learn']} != {EXPECTED_SKLEARN_VERSION}"
        )
    return versions


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_selection_evaluation.py",
        "ml/evaluation/evaluate_stage_c_selection.py",
        "ml/evaluation/stage_c_selection_label_evaluation_authorization.py",
        "ml/evaluation/stage_c_selection_score_generation.py",
        "ml/data/manifests/stage-c-experiment-contract-v1.json",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCSelectionEvaluationError("invalid Git HEAD identity")
        for relative in paths:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"],
                cwd=repo_root,
                capture_output=True,
                check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *paths],
            cwd=repo_root,
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCSelectionEvaluationError(
            "Task-16 and bound evaluation files must be committed before evaluation"
        ) from exc
    if dirty != 0:
        raise StageCSelectionEvaluationError(
            "Task-16/bound evaluation files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task16_module_sha256": sha256_file(repo_root / paths[0]),
        "task16_cli_sha256": sha256_file(repo_root / paths[1]),
        "task15_module_sha256": sha256_file(repo_root / paths[2]),
        "task14_module_sha256": sha256_file(repo_root / paths[3]),
        "experiment_contract_file_sha256": sha256_file(repo_root / paths[4]),
    }


def evaluate_stage_c_selection(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    score_dataset_path: Path,
    authorization_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    expected_score_hashes = validate_authorization(auth)
    y, score_arrays, input_identity = load_evaluation_input(
        feature_dataset_path=feature_dataset_path,
        score_dataset_path=score_dataset_path,
        expected_candidate_score_hashes=expected_score_hashes,
    )
    environment = _environment()
    git = _git_provenance(repo_root)

    candidate_evaluations = [
        evaluate_candidate(y, score_arrays[cid], cid)
        for cid in EXPECTED_CANDIDATES
    ]

    evaluation_set_sha256 = canonical_hash(candidate_evaluations)
    report = {
        "schema_version": EVALUATION_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selection_metric_computation_authorized": True,
        "selection_metrics_computed": True,
        "model_selection_authorized": False,
        "candidate_ranking_performed": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
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
        "candidate_order": list(EXPECTED_CANDIDATES),
        "candidate_order_semantics": "FIXED_CANDIDATE_ID_ORDER_NOT_PERFORMANCE_RANKING",
        "candidate_evaluations": candidate_evaluations,
        "candidate_evaluation_set_sha256": evaluation_set_sha256,
        "environment": environment,
        "git_provenance": git,
        "limitations": [
            "Selection metrics are descriptive frozen evidence; Task 16 does not rank or choose a candidate.",
            "Any threshold reported by the low-FPR sweep is diagnostic only and is not frozen.",
            "Calibration rows are not accessed.",
            "No model is refit.",
            "The final holdout remains untouched.",
            "PASS does not authorize deployment.",
        ],
        "next_gate": (
            "ISSUE_STAGE_C_MODEL_SELECTION_AUTHORIZATION_FROM_FROZEN_SELECTION_EVALUATION"
        ),
    }
    report["evaluation_report_sha256"] = canonical_hash(report)
    report_path = output_root / "selection-evaluation-report-v1.json"
    state = frozen_write_json(report_path, report)

    return {
        "status": "PASS",
        "report": str(report_path),
        "state": state,
        "evaluation_report_sha256": report["evaluation_report_sha256"],
        "candidate_evaluation_set_sha256": evaluation_set_sha256,
        "selection_sample_count": EXPECTED_SELECTION_COUNT,
        "candidate_count": EXPECTED_CANDIDATE_COUNT,
        "selection_metrics_computed": True,
        "model_selection_authorized": False,
        "candidate_ranking_performed": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "next_gate": report["next_gate"],
    }
