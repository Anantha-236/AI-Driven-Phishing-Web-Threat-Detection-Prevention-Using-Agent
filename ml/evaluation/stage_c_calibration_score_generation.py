"""Stage C Task 20 — generate selected-candidate calibration scores.

This task consumes the frozen Task-19 authorization, re-derives the exact
collection-complete calibration feature matrix without reading labels, verifies
and trusted-locally loads only the selected logistic-regression artifact, and
writes a frozen probability vector.

Output rows contain only:
  - sample_id
  - phishing_probability

Task 20 computes no calibration metric, reads no calibration label, fits
nothing, chooses/freezes no threshold, deploys nothing, and does not access the
final holdout.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import pickle
import platform
import subprocess
from typing import Any, Mapping

import numpy as np

SCORING_SCHEMA = "stage-c-calibration-score-generation-1"

EXPECTED_AUTHORIZATION_SHA256 = "d0ecd7710d8341077ff3cb428e11f1f632cd189a0fc5c36b438fcb9cb734bfeb"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_CANDIDATE_FAMILY = "linear"
EXPECTED_SELECTED_ARTIFACT_SHA256 = "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"

EXPECTED_CALIBRATION_COUNT = 7314
EXPECTED_CALIBRATION_SAMPLE_SET_SHA256 = "4ecace3342256b1a97fd419b4ec18cc6fdbd07b0e216482847ef959fd63e135e"
EXPECTED_CALIBRATION_FEATURE_MATRIX_SHA256 = "5b5340bdc658b0da44e3d04849cfc21d0f9c3804f55050e93240d326c51d2f41"
EXPECTED_FEATURE_COUNT = 27
EXPECTED_TOTAL_ROWS = 73777
EXPECTED_NUMPY_VERSION = "2.5.2"
EXPECTED_SKLEARN_VERSION = "1.9.0"

EXPECTED_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}


class StageCCalibrationScoringError(ValueError):
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
        raise StageCCalibrationScoringError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCalibrationScoringError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCCalibrationScoringError(
            f"JSON root must be object: {path}"
        )
    return value


def atomic_frozen_bytes(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCCalibrationScoringError(
                f"refusing to replace non-identical frozen Task-20 output: {path}"
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


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return atomic_frozen_bytes(path, payload)


def validate_authorization(auth: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-calibration-scoring-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "selected_candidate_family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
        "selected_candidate_artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "selected_candidate_loading_authorized": True,
        "calibration_access_authorized": True,
        "calibration_scoring_authorized": True,
        "calibration_label_access_authorized": False,
        "calibration_labels_accessed": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
        "selection_diagnostic_threshold_carryover_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "GENERATE_SELECTED_CANDIDATE_PROBABILITY_SCORES_ON_COMPLETE_"
            "CALIBRATION_FEATURES_WITH_LABELS_LOCKED"
        ),
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "next_gate": (
            "SCORE_STAGE_C_SELECTED_CANDIDATE_ON_CALIBRATION_FEATURES_"
            "WITH_LABELS_LOCKED"
        ),
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCCalibrationScoringError(
                f"Task-19 authorization guard mismatch: {key}"
            )
    if hash_without(auth, "authorization_sha256") != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCCalibrationScoringError(
            "Task-19 canonical authorization hash mismatch"
        )

    scope = auth.get("calibration_scoring_scope")
    artifact = auth.get("selected_candidate_artifact")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(
        isinstance(x, Mapping)
        for x in (scope, artifact, bindings, prohibitions)
    ):
        raise StageCCalibrationScoringError(
            "Task-19 authorization sections missing"
        )

    checks = [
        (
            scope.get("authorized_partition") == "calibration",
            "calibration partition",
        ),
        (
            scope.get("authorized_sample_count") == EXPECTED_CALIBRATION_COUNT,
            "calibration sample count",
        ),
        (
            scope.get("authorized_sample_set_sha256")
            == EXPECTED_CALIBRATION_SAMPLE_SET_SHA256,
            "calibration sample-set identity",
        ),
        (
            scope.get("authorized_feature_matrix_sha256")
            == EXPECTED_CALIBRATION_FEATURE_MATRIX_SHA256,
            "calibration feature-matrix identity",
        ),
        (scope.get("feature_count") == EXPECTED_FEATURE_COUNT, "feature count"),
        (
            scope.get("row_order") == "SAMPLE_ID_ASCENDING",
            "calibration row order",
        ),
        (
            scope.get("model_observable_fields") == ["feature_vector"],
            "model observable fields",
        ),
        (
            scope.get("join_only_fields") == ["sample_id"],
            "join-only fields",
        ),
        (
            scope.get("calibration_label_access_authorized") is False,
            "calibration label lock",
        ),
        (
            scope.get("collection_incomplete_rows_authorized") is False,
            "collection-incomplete lock",
        ),
        (
            artifact.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID,
            "selected candidate artifact",
        ),
        (
            artifact.get("family") == EXPECTED_SELECTED_CANDIDATE_FAMILY,
            "selected candidate family",
        ),
        (
            artifact.get("artifact_sha256") == EXPECTED_SELECTED_ARTIFACT_SHA256,
            "selected artifact identity",
        ),
        (
            artifact.get("physical_artifact_verified") is True,
            "selected artifact verification",
        ),
        (
            bindings.get("feature_dataset_sha256")
            == EXPECTED_FEATURE_DATASET_SHA256,
            "feature dataset binding",
        ),
        (prohibitions.get("model_refit") is True, "refit prohibition"),
        (
            prohibitions.get("score_non_selected_candidate") is True,
            "non-selected candidate prohibition",
        ),
        (
            prohibitions.get("calibration_label_read") is True,
            "calibration-label prohibition",
        ),
        (
            prohibitions.get("calibration_metric_computation") is True,
            "metric prohibition",
        ),
        (
            prohibitions.get("calibration_fitting") is True,
            "calibration fitting prohibition",
        ),
        (
            prohibitions.get("threshold_selection") is True,
            "threshold-selection prohibition",
        ),
        (
            prohibitions.get("threshold_freeze") is True,
            "threshold-freeze prohibition",
        ),
        (
            prohibitions.get("reuse_selection_diagnostic_threshold") is True,
            "selection-threshold carryover prohibition",
        ),
        (
            prohibitions.get("final_holdout_access") is True,
            "holdout prohibition",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCCalibrationScoringError(
                f"Task-19 authorization changed: {name}"
            )

    size = artifact.get("artifact_size_bytes")
    if type(size) is not int or size <= 0:
        raise StageCCalibrationScoringError(
            "selected artifact size invalid"
        )
    return dict(artifact)


def load_calibration_features(
    feature_dataset_path: Path,
) -> tuple[list[str], np.ndarray, str]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCCalibrationScoringError(
            "Task-10 feature dataset SHA-256 mismatch"
        )

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_rows = 0
    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCalibrationScoringError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_ROW_FIELDS:
                raise StageCCalibrationScoringError(
                    "feature row closed-schema mismatch"
                )

            sid = row["sample_id"]
            part = row["partition"]
            vector = row["feature_vector"]
            incomplete = row["collection_incomplete"]
            dropped = row["dropped_events"]
            history = row["history_truncated"]

            if not isinstance(sid, str) or not sid or sid in seen:
                raise StageCCalibrationScoringError(
                    "duplicate/invalid sample_id"
                )
            if part not in {"train", "selection", "calibration"}:
                raise StageCCalibrationScoringError("partition invalid")
            if not isinstance(vector, list) or len(vector) != EXPECTED_FEATURE_COUNT:
                raise StageCCalibrationScoringError(
                    "feature vector shape changed"
                )
            if any(
                type(x) not in (int, float) or not math.isfinite(x)
                for x in vector
            ):
                raise StageCCalibrationScoringError(
                    "feature vector contains non-finite value"
                )
            if type(incomplete) is not bool or type(history) is not bool:
                raise StageCCalibrationScoringError(
                    "collection flags invalid"
                )
            if type(dropped) is not int or dropped < 0:
                raise StageCCalibrationScoringError(
                    "dropped-event count invalid"
                )
            if incomplete is not (dropped > 0 or history):
                raise StageCCalibrationScoringError(
                    "collection-loss metadata mismatch"
                )

            seen.add(sid)
            total_rows += 1
            if part == "calibration" and not incomplete:
                # Calibration labels remain intentionally unread.
                rows.append({
                    "sample_id": sid,
                    "feature_vector": list(vector),
                })

    if total_rows != EXPECTED_TOTAL_ROWS:
        raise StageCCalibrationScoringError(
            "full feature row count changed"
        )

    rows.sort(key=lambda x: x["sample_id"])
    sample_ids = [row["sample_id"] for row in rows]
    if len(sample_ids) != EXPECTED_CALIBRATION_COUNT:
        raise StageCCalibrationScoringError(
            "calibration row count changed"
        )
    if canonical_hash(sample_ids) != EXPECTED_CALIBRATION_SAMPLE_SET_SHA256:
        raise StageCCalibrationScoringError(
            "calibration sample-set identity changed"
        )
    matrix_hash = canonical_hash(rows)
    if matrix_hash != EXPECTED_CALIBRATION_FEATURE_MATRIX_SHA256:
        raise StageCCalibrationScoringError(
            "calibration feature-matrix identity changed"
        )

    x = np.asarray(
        [row["feature_vector"] for row in rows],
        dtype=np.float64,
    )
    if x.shape != (EXPECTED_CALIBRATION_COUNT, EXPECTED_FEATURE_COUNT):
        raise StageCCalibrationScoringError(
            "calibration feature matrix shape changed"
        )
    if not np.isfinite(x).all():
        raise StageCCalibrationScoringError(
            "calibration matrix contains non-finite values"
        )
    return sample_ids, x, matrix_hash


def _environment() -> dict[str, str]:
    versions = {
        "python": platform.python_version(),
        "numpy": importlib.metadata.version("numpy"),
        "scikit-learn": importlib.metadata.version("scikit-learn"),
    }
    if versions["numpy"] != EXPECTED_NUMPY_VERSION:
        raise StageCCalibrationScoringError(
            f"numpy version changed: {versions['numpy']} != {EXPECTED_NUMPY_VERSION}"
        )
    if versions["scikit-learn"] != EXPECTED_SKLEARN_VERSION:
        raise StageCCalibrationScoringError(
            "scikit-learn version changed: "
            f"{versions['scikit-learn']} != {EXPECTED_SKLEARN_VERSION}"
        )
    return versions


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_calibration_score_generation.py",
        "ml/evaluation/score_stage_c_calibration.py",
        "ml/evaluation/stage_c_calibration_scoring_authorization.py",
        "ml/training/stage_c_candidate_training.py",
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
            raise StageCCalibrationScoringError(
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
        raise StageCCalibrationScoringError(
            "Task-20 and bound scoring files must be committed before scoring"
        ) from exc
    if dirty != 0:
        raise StageCCalibrationScoringError(
            "Task-20/bound scoring files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task20_module_sha256": sha256_file(repo_root / paths[0]),
        "task20_cli_sha256": sha256_file(repo_root / paths[1]),
        "task19_module_sha256": sha256_file(repo_root / paths[2]),
        "task12_module_sha256": sha256_file(repo_root / paths[3]),
    }


def load_verified_selected_candidate(
    artifact_path: Path,
    artifact_record: Mapping[str, Any],
) -> Any:
    if artifact_record.get("candidate_id") != EXPECTED_SELECTED_CANDIDATE_ID:
        raise StageCCalibrationScoringError(
            "authorization does not bind selected candidate"
        )
    if not artifact_path.is_file():
        raise StageCCalibrationScoringError(
            f"selected candidate artifact missing: {artifact_path}"
        )
    if artifact_path.stat().st_size != artifact_record["artifact_size_bytes"]:
        raise StageCCalibrationScoringError(
            "selected candidate artifact size mismatch"
        )
    if sha256_file(artifact_path) != EXPECTED_SELECTED_ARTIFACT_SHA256:
        raise StageCCalibrationScoringError(
            "selected candidate artifact SHA mismatch"
        )
    try:
        with artifact_path.open("rb") as handle:
            model = pickle.load(handle)
    except Exception as exc:
        raise StageCCalibrationScoringError(
            f"trusted-local selected candidate load failed: {exc}"
        ) from exc
    if not hasattr(model, "predict_proba") or not hasattr(model, "classes_"):
        raise StageCCalibrationScoringError(
            "selected candidate lacks fitted probability interface"
        )
    return model


def phishing_probabilities(model: Any, x: np.ndarray) -> np.ndarray:
    classes = np.asarray(model.classes_)
    indices = np.flatnonzero(classes == 1)
    if len(indices) != 1:
        raise StageCCalibrationScoringError(
            "selected candidate class mapping invalid"
        )
    try:
        proba = np.asarray(model.predict_proba(x), dtype=np.float64)
    except Exception as exc:
        raise StageCCalibrationScoringError(
            f"selected candidate probability scoring failed: {exc}"
        ) from exc
    if proba.shape != (len(x), len(classes)):
        raise StageCCalibrationScoringError(
            "selected candidate probability shape invalid"
        )
    scores = proba[:, int(indices[0])]
    if not np.isfinite(scores).all():
        raise StageCCalibrationScoringError(
            "selected candidate probabilities are non-finite"
        )
    if np.any(scores < 0.0) or np.any(scores > 1.0):
        raise StageCCalibrationScoringError(
            "selected candidate probabilities outside [0,1]"
        )
    return scores


def render_score_dataset(
    sample_ids: list[str],
    scores: np.ndarray,
) -> bytes:
    if len(scores) != len(sample_ids):
        raise StageCCalibrationScoringError(
            "calibration score vector length changed"
        )
    lines: list[bytes] = []
    for index, sid in enumerate(sample_ids):
        score = float(scores[index])
        if not math.isfinite(score) or score < 0.0 or score > 1.0:
            raise StageCCalibrationScoringError(
                "invalid calibration score value"
            )
        row = {
            "sample_id": sid,
            "phishing_probability": score,
        }
        lines.append(canonical_bytes(row) + b"\n")
    return b"".join(lines)


def score_stage_c_calibration(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    authorization_path: Path,
    candidate_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    artifact_record = validate_authorization(auth)
    sample_ids, x, matrix_hash = load_calibration_features(feature_dataset_path)
    environment = _environment()
    git = _git_provenance(repo_root)

    artifact_path = (
        candidate_root / "artifacts" / f"{EXPECTED_SELECTED_CANDIDATE_ID}.pkl"
    )
    model = load_verified_selected_candidate(artifact_path, artifact_record)
    scores = phishing_probabilities(model, x)

    score_identity_rows = [
        {
            "sample_id": sid,
            "phishing_probability": float(scores[index]),
        }
        for index, sid in enumerate(sample_ids)
    ]
    score_vector_sha256 = canonical_hash(score_identity_rows)

    payload = render_score_dataset(sample_ids, scores)
    score_path = output_root / "calibration-selected-candidate-scores-v1.jsonl"
    score_state = atomic_frozen_bytes(score_path, payload)
    score_dataset_sha256 = hashlib.sha256(payload).hexdigest()

    manifest = {
        "schema_version": SCORING_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "selected_candidate_family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
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
        "selection_diagnostic_threshold_carryover_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "calibration_sample_count": EXPECTED_CALIBRATION_COUNT,
        "calibration_sample_set_sha256": EXPECTED_CALIBRATION_SAMPLE_SET_SHA256,
        "calibration_feature_matrix_sha256": matrix_hash,
        "score_row_count": EXPECTED_CALIBRATION_COUNT,
        "score_dataset": str(score_path),
        "score_dataset_sha256": score_dataset_sha256,
        "score_vector_sha256": score_vector_sha256,
        "score_schema": [
            "sample_id",
            "phishing_probability",
        ],
        "score_order": "SAMPLE_ID_ASCENDING",
        "environment": environment,
        "git_provenance": git,
        "prohibitions_preserved": {
            "score_non_selected_candidate": True,
            "calibration_label_read": True,
            "calibration_metric_computation": True,
            "model_refit": True,
            "calibration_fitting": True,
            "threshold_selection": True,
            "threshold_freeze": True,
            "reuse_selection_diagnostic_threshold": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "ISSUE_STAGE_C_CALIBRATION_LABEL_EVALUATION_AUTHORIZATION_"
            "FOR_FROZEN_SCORES"
        ),
    }
    manifest["scoring_manifest_sha256"] = canonical_hash(manifest)
    manifest_path = output_root / "calibration-score-manifest-v1.json"
    manifest_state = frozen_write_json(manifest_path, manifest)

    return {
        "status": "PASS",
        "scores": str(score_path),
        "score_state": score_state,
        "score_dataset_sha256": score_dataset_sha256,
        "score_vector_sha256": score_vector_sha256,
        "manifest": str(manifest_path),
        "manifest_state": manifest_state,
        "scoring_manifest_sha256": manifest["scoring_manifest_sha256"],
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "calibration_sample_count": EXPECTED_CALIBRATION_COUNT,
        "score_row_count": EXPECTED_CALIBRATION_COUNT,
        "model_scoring_authorized": True,
        "model_scoring_performed": True,
        "calibration_labels_accessed": False,
        "calibration_metrics_computed": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "next_gate": manifest["next_gate"],
    }
