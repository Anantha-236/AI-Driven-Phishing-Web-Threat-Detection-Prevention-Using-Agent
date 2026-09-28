"""Stage C Task 14 — generate frozen candidate scores on selection features.

This task is deliberately label-blind. It reads sample identity and feature
vectors only, loads the Task-12 trusted-local candidate artifacts after SHA-256
verification, calls predict_proba, and freezes probabilities.

It does not read selection labels, compute metrics, rank candidates, choose a
candidate, calibrate, select thresholds, deploy, or access a final holdout.
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

SCORING_SCHEMA = "stage-c-selection-score-generation-1"

EXPECTED_AUTHORIZATION_SHA256 = "a48f625c3b9c96fdebbd51729c197b1d9a87f2255f1a52db74715e4e1674a9c5"
EXPECTED_TASK13_GIT_HEAD = "e8e2dc67d2cc3cb10eb925d82eaee3e064d34cd3"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_SELECTION_COUNT = 20710
EXPECTED_SELECTION_SAMPLE_SET_SHA256 = "0cc84274558ee32889b114633e14782fe14c9dd17e933b8faa929efeab65c0cd"
EXPECTED_SELECTION_FEATURE_MATRIX_SHA256 = "31b58dd8900bddac87a7b9bcf8916d539f8b2c4326bbfe2b45919d521b4d03b0"
EXPECTED_CANDIDATE_COUNT = 4
EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"
EXPECTED_FEATURE_COUNT = 27
EXPECTED_SCORE_ROWS = EXPECTED_SELECTION_COUNT * EXPECTED_CANDIDATE_COUNT
EXPECTED_NUMPY_VERSION = "2.5.2"
EXPECTED_SKLEARN_VERSION = "1.9.0"

EXPECTED_CANDIDATES = (
    "dummy_prior",
    "hist_gradient_boosting",
    "logistic_regression",
    "random_forest_compact",
)

EXPECTED_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}


class StageCSelectionScoringError(ValueError):
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
        raise StageCSelectionScoringError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCSelectionScoringError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCSelectionScoringError(f"JSON root must be object: {path}")
    return value


def atomic_frozen_bytes(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCSelectionScoringError(
                f"refusing to replace non-identical frozen scoring output: {path}"
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
        "schema_version": "stage-c-selection-scoring-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_training_complete": True,
        "model_training_authorized": True,
        "model_scoring_authorized": True,
        "selection_feature_scoring_authorized": True,
        "selection_label_access_authorized": False,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "GENERATE_FROZEN_CANDIDATE_PROBABILITY_SCORES_ON_COMPLETE_SELECTION_FEATURES"
        ),
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "next_gate": (
            "SCORE_STAGE_C_FROZEN_CANDIDATES_ON_SELECTION_FEATURES_WITH_LABELS_LOCKED"
        ),
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCSelectionScoringError(
                f"Task-13 authorization guard mismatch: {key}"
            )
    if hash_without(auth, "authorization_sha256") != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCSelectionScoringError(
            "Task-13 canonical authorization hash mismatch"
        )

    scope = auth.get("selection_scope")
    candidate_scope = auth.get("candidate_scope")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(
        isinstance(x, Mapping)
        for x in (scope, candidate_scope, bindings, prohibitions)
    ):
        raise StageCSelectionScoringError(
            "Task-13 authorization sections missing"
        )

    checks = [
        (scope.get("selection_sample_count") == EXPECTED_SELECTION_COUNT, "selection count"),
        (
            scope.get("selection_sample_set_sha256")
            == EXPECTED_SELECTION_SAMPLE_SET_SHA256,
            "selection identity",
        ),
        (
            scope.get("selection_feature_matrix_sha256")
            == EXPECTED_SELECTION_FEATURE_MATRIX_SHA256,
            "selection feature matrix",
        ),
        (scope.get("feature_count") == EXPECTED_FEATURE_COUNT, "feature count"),
        (scope.get("scoring_order") == "SAMPLE_ID_ASCENDING", "scoring order"),
        (scope.get("authorized_partition") == "selection", "authorized partition"),
        (scope.get("model_observable_fields") == ["feature_vector"], "model fields"),
        (scope.get("label_field_authorized") is False, "label lock"),
        (
            scope.get("collection_incomplete_rows_authorized") is False,
            "incomplete-row lock",
        ),
        (scope.get("calibration_partition_authorized") is False, "calibration lock"),
        (scope.get("final_holdout_authorized") is False, "holdout lock"),
        (
            candidate_scope.get("candidate_count") == EXPECTED_CANDIDATE_COUNT,
            "candidate count",
        ),
        (
            candidate_scope.get("candidate_artifact_set_sha256")
            == EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
            "candidate artifact set",
        ),
        (
            bindings.get("feature_dataset_sha256")
            == EXPECTED_FEATURE_DATASET_SHA256,
            "feature dataset identity",
        ),
        (
            prohibitions.get("selection_label_read") is True,
            "selection-label prohibition",
        ),
        (
            prohibitions.get("selection_metric_computation") is True,
            "metric prohibition",
        ),
        (prohibitions.get("candidate_ranking") is True, "ranking prohibition"),
        (prohibitions.get("candidate_choice") is True, "choice prohibition"),
        (prohibitions.get("model_refit") is True, "refit prohibition"),
        (prohibitions.get("calibration_access") is True, "calibration prohibition"),
        (prohibitions.get("threshold_selection") is True, "threshold prohibition"),
        (prohibitions.get("final_holdout_access") is True, "holdout prohibition"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCSelectionScoringError(
                f"Task-13 authorization changed: {name}"
            )

    artifacts = candidate_scope.get("candidate_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != EXPECTED_CANDIDATE_COUNT:
        raise StageCSelectionScoringError(
            "Task-13 candidate artifact records missing"
        )

    verified_records: dict[str, dict[str, Any]] = {}
    for row in artifacts:
        if not isinstance(row, Mapping):
            raise StageCSelectionScoringError(
                "Task-13 candidate artifact record invalid"
            )
        cid = row.get("candidate_id")
        sha = row.get("artifact_sha256")
        size = row.get("artifact_size_bytes")
        if cid not in EXPECTED_CANDIDATES or cid in verified_records:
            raise StageCSelectionScoringError(
                "Task-13 candidate identity invalid"
            )
        if not isinstance(sha, str) or len(sha) != 64:
            raise StageCSelectionScoringError(
                f"Task-13 artifact SHA invalid: {cid}"
            )
        if type(size) is not int or size <= 0:
            raise StageCSelectionScoringError(
                f"Task-13 artifact size invalid: {cid}"
            )
        verified_records[cid] = {
            "candidate_id": cid,
            "family": row.get("family"),
            "eligible_for_later_selection": row.get(
                "eligible_for_later_selection"
            ),
            "artifact_sha256": sha,
            "artifact_size_bytes": size,
        }
    if tuple(sorted(verified_records)) != EXPECTED_CANDIDATES:
        raise StageCSelectionScoringError("Task-13 candidate set changed")

    artifact_set = canonical_hash([
        {
            "candidate_id": cid,
            "artifact_sha256": verified_records[cid]["artifact_sha256"],
        }
        for cid in EXPECTED_CANDIDATES
    ])
    if artifact_set != EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256:
        raise StageCSelectionScoringError(
            "Task-13 candidate artifact-set identity changed"
        )
    return verified_records


def load_selection_features(
    feature_dataset_path: Path,
) -> tuple[list[str], np.ndarray, str]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCSelectionScoringError(
            "Task-10 feature dataset SHA-256 mismatch"
        )

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCSelectionScoringError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_ROW_FIELDS:
                raise StageCSelectionScoringError(
                    "feature row closed-schema mismatch"
                )

            sid = row["sample_id"]
            part = row["partition"]
            vector = row["feature_vector"]
            incomplete = row["collection_incomplete"]
            dropped = row["dropped_events"]
            history = row["history_truncated"]

            if not isinstance(sid, str) or not sid or sid in seen:
                raise StageCSelectionScoringError(
                    "duplicate/invalid sample_id"
                )
            if part not in {"train", "selection", "calibration"}:
                raise StageCSelectionScoringError("partition invalid")
            if not isinstance(vector, list) or len(vector) != EXPECTED_FEATURE_COUNT:
                raise StageCSelectionScoringError(
                    "feature vector shape changed"
                )
            if any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
                raise StageCSelectionScoringError(
                    "feature vector contains non-finite value"
                )
            if type(incomplete) is not bool or type(history) is not bool:
                raise StageCSelectionScoringError(
                    "collection flags invalid"
                )
            if type(dropped) is not int or dropped < 0:
                raise StageCSelectionScoringError(
                    "dropped-event count invalid"
                )
            if incomplete is not (dropped > 0 or history):
                raise StageCSelectionScoringError(
                    "collection-loss metadata mismatch"
                )

            seen.add(sid)
            if part == "selection" and not incomplete:
                rows.append({
                    "sample_id": sid,
                    "feature_vector": list(vector),
                })

    if len(seen) != 73777:
        raise StageCSelectionScoringError(
            "full feature row count changed"
        )

    rows.sort(key=lambda x: x["sample_id"])
    sample_ids = [row["sample_id"] for row in rows]
    if len(sample_ids) != EXPECTED_SELECTION_COUNT:
        raise StageCSelectionScoringError("selection row count changed")
    if canonical_hash(sample_ids) != EXPECTED_SELECTION_SAMPLE_SET_SHA256:
        raise StageCSelectionScoringError(
            "selection sample-set identity changed"
        )
    matrix_hash = canonical_hash(rows)
    if matrix_hash != EXPECTED_SELECTION_FEATURE_MATRIX_SHA256:
        raise StageCSelectionScoringError(
            "selection feature-matrix identity changed"
        )

    x = np.asarray(
        [row["feature_vector"] for row in rows],
        dtype=np.float64,
    )
    if x.shape != (EXPECTED_SELECTION_COUNT, EXPECTED_FEATURE_COUNT):
        raise StageCSelectionScoringError(
            "selection feature matrix shape changed"
        )
    if not np.isfinite(x).all():
        raise StageCSelectionScoringError(
            "selection matrix contains non-finite values"
        )
    return sample_ids, x, matrix_hash


def _environment() -> dict[str, str]:
    versions = {
        "python": platform.python_version(),
        "numpy": importlib.metadata.version("numpy"),
        "scikit-learn": importlib.metadata.version("scikit-learn"),
    }
    if versions["numpy"] != EXPECTED_NUMPY_VERSION:
        raise StageCSelectionScoringError(
            f"numpy version changed: {versions['numpy']} != {EXPECTED_NUMPY_VERSION}"
        )
    if versions["scikit-learn"] != EXPECTED_SKLEARN_VERSION:
        raise StageCSelectionScoringError(
            "scikit-learn version changed: "
            f"{versions['scikit-learn']} != {EXPECTED_SKLEARN_VERSION}"
        )
    return versions


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_selection_score_generation.py",
        "ml/evaluation/score_stage_c_selection_candidates.py",
        "ml/evaluation/stage_c_selection_scoring_authorization.py",
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
            raise StageCSelectionScoringError("invalid Git HEAD identity")
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
        raise StageCSelectionScoringError(
            "Task-14 and bound scoring files must be committed before scoring"
        ) from exc
    if dirty != 0:
        raise StageCSelectionScoringError(
            "Task-14/bound scoring files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task14_module_sha256": sha256_file(repo_root / paths[0]),
        "task14_cli_sha256": sha256_file(repo_root / paths[1]),
        "task13_module_sha256": sha256_file(repo_root / paths[2]),
        "task12_module_sha256": sha256_file(repo_root / paths[3]),
    }


def load_verified_candidate(
    artifact_path: Path,
    record: Mapping[str, Any],
) -> Any:
    if not artifact_path.is_file():
        raise StageCSelectionScoringError(
            f"candidate artifact missing: {artifact_path}"
        )
    if artifact_path.stat().st_size != record["artifact_size_bytes"]:
        raise StageCSelectionScoringError(
            f"candidate artifact size mismatch: {record['candidate_id']}"
        )
    if sha256_file(artifact_path) != record["artifact_sha256"]:
        raise StageCSelectionScoringError(
            f"candidate artifact SHA mismatch: {record['candidate_id']}"
        )
    try:
        with artifact_path.open("rb") as handle:
            model = pickle.load(handle)
    except Exception as exc:
        raise StageCSelectionScoringError(
            f"trusted-local candidate load failed: {record['candidate_id']}: {exc}"
        ) from exc
    if not hasattr(model, "predict_proba") or not hasattr(model, "classes_"):
        raise StageCSelectionScoringError(
            f"candidate does not expose fitted probability interface: {record['candidate_id']}"
        )
    return model


def phishing_probabilities(model: Any, x: np.ndarray, candidate_id: str) -> np.ndarray:
    classes = np.asarray(model.classes_)
    indices = np.flatnonzero(classes == 1)
    if len(indices) != 1:
        raise StageCSelectionScoringError(
            f"candidate class mapping invalid: {candidate_id}"
        )
    try:
        proba = np.asarray(model.predict_proba(x), dtype=np.float64)
    except Exception as exc:
        raise StageCSelectionScoringError(
            f"candidate probability scoring failed: {candidate_id}: {exc}"
        ) from exc
    if proba.shape != (len(x), len(classes)):
        raise StageCSelectionScoringError(
            f"candidate probability shape invalid: {candidate_id}"
        )
    scores = proba[:, int(indices[0])]
    if not np.isfinite(scores).all():
        raise StageCSelectionScoringError(
            f"candidate probabilities are non-finite: {candidate_id}"
        )
    if np.any(scores < 0.0) or np.any(scores > 1.0):
        raise StageCSelectionScoringError(
            f"candidate probabilities outside [0,1]: {candidate_id}"
        )
    return scores


def render_score_dataset(
    sample_ids: list[str],
    score_vectors: Mapping[str, np.ndarray],
) -> bytes:
    if tuple(sorted(score_vectors)) != EXPECTED_CANDIDATES:
        raise StageCSelectionScoringError(
            "score vector candidate set changed"
        )
    lines: list[bytes] = []
    for sample_index, sid in enumerate(sample_ids):
        for cid in EXPECTED_CANDIDATES:
            scores = score_vectors[cid]
            if len(scores) != len(sample_ids):
                raise StageCSelectionScoringError(
                    f"score vector length changed: {cid}"
                )
            score = float(scores[sample_index])
            if not math.isfinite(score) or score < 0.0 or score > 1.0:
                raise StageCSelectionScoringError(
                    f"invalid score value: {cid}"
                )
            row = {
                "sample_id": sid,
                "candidate_id": cid,
                "phishing_probability": score,
            }
            lines.append(canonical_bytes(row) + b"\n")
    return b"".join(lines)


def score_stage_c_selection(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    authorization_path: Path,
    candidate_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    records = validate_authorization(auth)
    sample_ids, x, matrix_hash = load_selection_features(feature_dataset_path)
    environment = _environment()
    git = _git_provenance(repo_root)

    score_vectors: dict[str, np.ndarray] = {}
    per_candidate: list[dict[str, Any]] = []
    for cid in EXPECTED_CANDIDATES:
        artifact_path = candidate_root / "artifacts" / f"{cid}.pkl"
        model = load_verified_candidate(artifact_path, records[cid])
        scores = phishing_probabilities(model, x, cid)
        score_vectors[cid] = scores
        score_identity = canonical_hash([
            {
                "sample_id": sid,
                "phishing_probability": float(scores[index]),
            }
            for index, sid in enumerate(sample_ids)
        ])
        per_candidate.append({
            "candidate_id": cid,
            "family": records[cid]["family"],
            "eligible_for_later_selection": records[cid][
                "eligible_for_later_selection"
            ],
            "artifact_sha256": records[cid]["artifact_sha256"],
            "score_count": len(scores),
            "score_vector_sha256": score_identity,
        })

    payload = render_score_dataset(sample_ids, score_vectors)
    score_path = output_root / "selection-candidate-scores-v1.jsonl"
    score_state = atomic_frozen_bytes(score_path, payload)
    score_dataset_sha256 = hashlib.sha256(payload).hexdigest()

    manifest = {
        "schema_version": SCORING_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_training_complete": True,
        "model_scoring_authorized": True,
        "model_scoring_performed": True,
        "selection_feature_scoring_complete": True,
        "selection_label_access_authorized": False,
        "selection_labels_accessed": False,
        "selection_metrics_computed": False,
        "model_selection_authorized": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "selection_sample_count": EXPECTED_SELECTION_COUNT,
        "selection_sample_set_sha256": EXPECTED_SELECTION_SAMPLE_SET_SHA256,
        "selection_feature_matrix_sha256": matrix_hash,
        "candidate_count": EXPECTED_CANDIDATE_COUNT,
        "candidate_artifact_set_sha256": EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
        "score_row_count": EXPECTED_SCORE_ROWS,
        "score_dataset": str(score_path),
        "score_dataset_sha256": score_dataset_sha256,
        "score_schema": [
            "sample_id",
            "candidate_id",
            "phishing_probability",
        ],
        "score_order": "SAMPLE_ID_ASCENDING_THEN_CANDIDATE_ID_ASCENDING",
        "candidate_scores": per_candidate,
        "environment": environment,
        "git_provenance": git,
        "prohibitions_preserved": {
            "selection_label_read": True,
            "selection_metric_computation": True,
            "candidate_ranking": True,
            "candidate_choice": True,
            "model_refit": True,
            "calibration_access": True,
            "threshold_selection": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "ISSUE_STAGE_C_SELECTION_LABEL_EVALUATION_AUTHORIZATION_FOR_FROZEN_SCORES"
        ),
    }
    manifest["scoring_manifest_sha256"] = canonical_hash(manifest)
    manifest_path = output_root / "selection-score-manifest-v1.json"
    manifest_state = frozen_write_json(manifest_path, manifest)

    return {
        "status": "PASS",
        "scores": str(score_path),
        "score_state": score_state,
        "score_dataset_sha256": score_dataset_sha256,
        "manifest": str(manifest_path),
        "manifest_state": manifest_state,
        "scoring_manifest_sha256": manifest["scoring_manifest_sha256"],
        "selection_sample_count": EXPECTED_SELECTION_COUNT,
        "candidate_count": EXPECTED_CANDIDATE_COUNT,
        "score_row_count": EXPECTED_SCORE_ROWS,
        "model_scoring_authorized": True,
        "model_scoring_performed": True,
        "selection_labels_accessed": False,
        "selection_metrics_computed": False,
        "model_selection_authorized": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "final_holdout_touched": False,
        "next_gate": manifest["next_gate"],
    }
