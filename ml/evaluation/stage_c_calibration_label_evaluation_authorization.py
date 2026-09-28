"""Stage C Task 21 — authorize controlled calibration-label evaluation."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-calibration-label-evaluation-authorization-1"

EXPECTED_TASK20_SCORE_DATASET_SHA256 = "2b4db7e3d47f52994cc67a6f660a1e8603b710c48458fffd5c5923ac35c762fa"
EXPECTED_TASK20_SCORE_VECTOR_SHA256 = "461dc8101677adf4964d4e8cbb8408d523a6c9523270f1978c803dc332e51467"
EXPECTED_TASK20_SCORING_MANIFEST_SHA256 = "913807455a49397e36458d54b9224f31d183a82e2b80cd7bf4e29318366a117d"
EXPECTED_TASK19_AUTHORIZATION_SHA256 = "d0ecd7710d8341077ff3cb428e11f1f632cd189a0fc5c36b438fcb9cb734bfeb"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_CALIBRATION_COUNT = 7314
EXPECTED_CALIBRATION_SAMPLE_SET_SHA256 = "4ecace3342256b1a97fd419b4ec18cc6fdbd07b0e216482847ef959fd63e135e"
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_ARTIFACT_SHA256 = "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"
EXPECTED_TOTAL_ROWS = 73777

EXPECTED_SCORE_ROW_FIELDS = {"sample_id", "phishing_probability"}
EXPECTED_FEATURE_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}


class StageCCalibrationLabelEvaluationAuthorizationError(ValueError):
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
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            f"JSON root must be object: {path}"
        )
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCCalibrationLabelEvaluationAuthorizationError(
                f"refusing to replace non-identical frozen Task-21 output: {path}"
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


def validate_task20_manifest(
    manifest: Mapping[str, Any],
    *,
    score_dataset_path: Path,
) -> None:
    expected = {
        "schema_version": "stage-c-calibration-score-generation-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "selected_candidate_artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "model_scoring_authorized": True,
        "model_scoring_performed": True,
        "calibration_feature_scoring_complete": True,
        "calibration_label_access_authorized": False,
        "calibration_labels_accessed": False,
        "calibration_metrics_computed": False,
        "calibration_fitting_authorized": False,
        "calibration_fitting_performed": False,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK19_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "calibration_sample_count": EXPECTED_CALIBRATION_COUNT,
        "calibration_sample_set_sha256": EXPECTED_CALIBRATION_SAMPLE_SET_SHA256,
        "score_row_count": EXPECTED_CALIBRATION_COUNT,
        "score_dataset_sha256": EXPECTED_TASK20_SCORE_DATASET_SHA256,
        "score_vector_sha256": EXPECTED_TASK20_SCORE_VECTOR_SHA256,
        "scoring_manifest_sha256": EXPECTED_TASK20_SCORING_MANIFEST_SHA256,
        "next_gate": (
            "ISSUE_STAGE_C_CALIBRATION_LABEL_EVALUATION_AUTHORIZATION_"
            "FOR_FROZEN_SCORES"
        ),
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise StageCCalibrationLabelEvaluationAuthorizationError(
                f"Task-20 manifest guard mismatch: {key}"
            )
    if hash_without(manifest, "scoring_manifest_sha256") != EXPECTED_TASK20_SCORING_MANIFEST_SHA256:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "Task-20 canonical scoring-manifest hash mismatch"
        )
    if sha256_file(score_dataset_path) != EXPECTED_TASK20_SCORE_DATASET_SHA256:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "Task-20 score dataset SHA-256 mismatch"
        )


def scan_calibration_scores(score_dataset_path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    observed_order: list[str] = []

    with score_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    f"invalid score JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_SCORE_ROW_FIELDS:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "score row closed-schema mismatch"
                )
            sid = row["sample_id"]
            score = row["phishing_probability"]
            if not isinstance(sid, str) or not sid or sid in seen:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "duplicate/invalid score sample_id"
                )
            if type(score) not in (int, float) or not math.isfinite(score):
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "score probability invalid"
                )
            score = float(score)
            if not 0.0 <= score <= 1.0:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "score probability outside [0,1]"
                )
            seen.add(sid)
            observed_order.append(sid)
            rows.append({"sample_id": sid, "phishing_probability": score})

    if len(rows) != EXPECTED_CALIBRATION_COUNT:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "calibration score row count changed"
        )
    sample_ids = sorted(seen)
    if observed_order != sample_ids:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "calibration score order changed"
        )
    if canonical_hash(sample_ids) != EXPECTED_CALIBRATION_SAMPLE_SET_SHA256:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "calibration score sample-set identity changed"
        )
    if canonical_hash(rows) != EXPECTED_TASK20_SCORE_VECTOR_SHA256:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "calibration score-vector identity changed"
        )
    return {"sample_ids": sample_ids, "score_rows": rows}


def derive_calibration_labels(
    feature_dataset_path: Path,
    *,
    expected_sample_ids: list[str],
) -> dict[str, Any]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "Task-10 feature dataset SHA-256 mismatch"
        )

    expected_id_set = set(expected_sample_ids)
    seen_all: set[str] = set()
    labels: list[dict[str, Any]] = []

    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_FEATURE_ROW_FIELDS:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "feature row closed-schema mismatch"
                )
            sid = row["sample_id"]
            part = row["partition"]
            label = row["label"]
            incomplete = row["collection_incomplete"]
            if not isinstance(sid, str) or not sid or sid in seen_all:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "duplicate/invalid feature sample_id"
                )
            if part not in {"train", "selection", "calibration"}:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "feature partition invalid"
                )
            if label not in (0, 1):
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "feature label invalid"
                )
            if type(incomplete) is not bool:
                raise StageCCalibrationLabelEvaluationAuthorizationError(
                    "feature collection flag invalid"
                )
            seen_all.add(sid)
            if sid in expected_id_set:
                if part != "calibration" or incomplete:
                    raise StageCCalibrationLabelEvaluationAuthorizationError(
                        "authorized calibration sample changed partition/completeness"
                    )
                labels.append({"sample_id": sid, "label": int(label)})

    if len(seen_all) != EXPECTED_TOTAL_ROWS:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "full feature row count changed"
        )
    labels.sort(key=lambda row: row["sample_id"])
    if [row["sample_id"] for row in labels] != expected_sample_ids:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "calibration label sample coverage changed"
        )

    counts = Counter(row["label"] for row in labels)
    return {
        "calibration_label_count": len(labels),
        "calibration_label_counts": {
            "legitimate": counts[0],
            "phishing": counts[1],
        },
        "calibration_label_vector_sha256": canonical_hash(labels),
        "labels": labels,
    }


def build_evaluation_input_identity(
    *,
    labels: list[Mapping[str, Any]],
    scores: list[Mapping[str, Any]],
) -> str:
    label_by_id = {
        str(row["sample_id"]): int(row["label"])
        for row in labels
    }
    joined: list[dict[str, Any]] = []
    for row in scores:
        sid = str(row["sample_id"])
        if sid not in label_by_id:
            raise StageCCalibrationLabelEvaluationAuthorizationError(
                "score/label join coverage mismatch"
            )
        joined.append({
            "sample_id": sid,
            "label": label_by_id[sid],
            "phishing_probability": float(row["phishing_probability"]),
        })
    joined.sort(key=lambda row: row["sample_id"])
    if len(joined) != EXPECTED_CALIBRATION_COUNT:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "calibration evaluation join row count changed"
        )
    return canonical_hash(joined)


def validate_experiment_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != "stage-c-experiment-contract-1":
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "experiment contract schema changed"
        )
    if contract.get("stage") != "C" or contract.get("protocol_id") != "low-fpr-generalization-v1":
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "experiment contract identity changed"
        )
    if contract.get("research_only") is not True or contract.get("deployment_authorized") is not False:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "experiment contract safety state changed"
        )
    objective = contract.get("objective")
    holdout = contract.get("holdout_contract")
    development = contract.get("development_contract")
    if not all(isinstance(x, Mapping) for x in (objective, holdout, development)):
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "experiment contract sections missing"
        )
    checks = [
        (objective.get("primary_metric") == "false_positive_rate", "primary metric"),
        (objective.get("primary_fpr_cap") == 0.01, "primary FPR cap"),
        (objective.get("confidence_level") == 0.95, "confidence level"),
        (objective.get("require_observed_fpr_at_or_below_cap") is True, "observed FPR requirement"),
        (objective.get("require_wilson_upper_at_or_below_cap") is True, "Wilson requirement"),
        (objective.get("secondary_metric") == "recall", "secondary metric"),
        (holdout.get("calibration_use_prohibited") is True, "holdout calibration prohibition"),
        (holdout.get("threshold_selection_use_prohibited") is True, "holdout threshold prohibition"),
        (development.get("test_locked_until_candidate_and_threshold_frozen") is True, "test lock"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCCalibrationLabelEvaluationAuthorizationError(
                f"experiment contract changed: {name}"
            )
    return {
        "experiment_contract_sha256": canonical_hash(contract),
        "primary_metric": "false_positive_rate",
        "primary_fpr_cap": 0.01,
        "confidence_level": 0.95,
        "require_observed_fpr_at_or_below_cap": True,
        "require_wilson_upper_at_or_below_cap": True,
        "secondary_metric": "recall",
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_calibration_label_evaluation_authorization.py",
        "ml/evaluation/authorize_stage_c_calibration_label_evaluation.py",
        "ml/evaluation/stage_c_calibration_score_generation.py",
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
            raise StageCCalibrationLabelEvaluationAuthorizationError(
                "invalid Git HEAD identity"
            )
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
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "Task-21 and bound evaluation files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCCalibrationLabelEvaluationAuthorizationError(
            "Task-21/bound evaluation files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task21_module_sha256": sha256_file(repo_root / paths[0]),
        "task21_cli_sha256": sha256_file(repo_root / paths[1]),
        "task20_module_sha256": sha256_file(repo_root / paths[2]),
        "experiment_contract_file_sha256": sha256_file(repo_root / paths[3]),
    }


def issue_calibration_label_evaluation_authorization(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    score_dataset_path: Path,
    score_manifest_path: Path,
    experiment_contract_path: Path,
) -> dict[str, Any]:
    manifest = load_json(score_manifest_path)
    experiment = load_json(experiment_contract_path)

    validate_task20_manifest(manifest, score_dataset_path=score_dataset_path)
    score_scope = scan_calibration_scores(score_dataset_path)
    label_scope = derive_calibration_labels(
        feature_dataset_path,
        expected_sample_ids=score_scope["sample_ids"],
    )
    evaluation_input_sha = build_evaluation_input_identity(
        labels=label_scope["labels"],
        scores=score_scope["score_rows"],
    )
    experiment_binding = validate_experiment_contract(experiment)
    git = _git_provenance(repo_root)

    authorization = {
        "schema_version": AUTH_SCHEMA,
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
        "evaluation_scope": {
            "calibration_sample_count": EXPECTED_CALIBRATION_COUNT,
            "calibration_sample_set_sha256": EXPECTED_CALIBRATION_SAMPLE_SET_SHA256,
            "calibration_label_counts": label_scope["calibration_label_counts"],
            "calibration_label_vector_sha256": label_scope[
                "calibration_label_vector_sha256"
            ],
            "score_row_count": EXPECTED_CALIBRATION_COUNT,
            "score_dataset_sha256": EXPECTED_TASK20_SCORE_DATASET_SHA256,
            "score_vector_sha256": EXPECTED_TASK20_SCORE_VECTOR_SHA256,
            "evaluation_input_sha256": evaluation_input_sha,
            "join_key": "sample_id",
            "label_field": "label",
            "score_field": "phishing_probability",
        },
        "authorized_metrics_and_analysis": {
            "average_precision": True,
            "roc_auc": True,
            "brier_score": True,
            "log_loss": True,
            "low_fpr_threshold_sweep": True,
            "observed_fpr": True,
            "wilson_upper_95": True,
            "recall": True,
            "precision": True,
            "primary_fpr_cap": experiment_binding["primary_fpr_cap"],
            "threshold_freeze_authorized": False,
        },
        "experiment_constraints": experiment_binding,
        "identity_bindings": {
            "task19_authorization_sha256": EXPECTED_TASK19_AUTHORIZATION_SHA256,
            "task20_score_dataset_sha256": EXPECTED_TASK20_SCORE_DATASET_SHA256,
            "task20_score_vector_sha256": EXPECTED_TASK20_SCORE_VECTOR_SHA256,
            "task20_scoring_manifest_sha256": EXPECTED_TASK20_SCORING_MANIFEST_SHA256,
            "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
            **git,
        },
        "prohibitions": {
            "model_refit": True,
            "score_regeneration": True,
            "calibration_fitting": True,
            "threshold_freeze": True,
            "reuse_selection_diagnostic_threshold": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "EVALUATE_STAGE_C_CALIBRATION_SCORES_AND_FREEZE_THRESHOLD_"
            "ANALYSIS_WITHOUT_THRESHOLD_SELECTION"
        ),
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
