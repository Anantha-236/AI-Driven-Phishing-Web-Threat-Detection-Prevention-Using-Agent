"""Stage C Task 12 — train and freeze candidate models on authorized TRAIN rows.

This task performs fitting only. It does not score any model, use selection or
calibration for fitting, choose a candidate, select a threshold, access a final
holdout, convert a model for deployment, or authorize deployment.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import pickle
import platform
import subprocess
from typing import Any, Callable, Mapping

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

TRAINING_SCHEMA = "stage-c-candidate-training-1"
RANDOM_SEED = 236

EXPECTED_AUTHORIZATION_SHA256 = "fa8a80ae3fc60f8c33518be10c77cc3df5ca793050fa2a44ecf181d16f311bc3"
EXPECTED_TASK11_GIT_HEAD = "dcc24fa1d759f907bbf7203a721f9bfd20f753b4"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_MODELING_COUNT = 73770
EXPECTED_MODELING_SHA256 = "451712b4b9f2584f228b4547fd70875f1e58c2888ff4e8352eb1f7544168a98b"
EXPECTED_TRAIN_COUNT = 45746
EXPECTED_TRAIN_SHA256 = "50138895b65a7a4b1c5b7defd331e4fed715f88b281eca04edfd0f2e613124c4"
EXPECTED_TRAIN_LABEL_COUNTS = {"legitimate": 22699, "phishing": 23047}
EXPECTED_INCOMPLETE_COUNT = 7
EXPECTED_FEATURE_COUNT = 27
EXPECTED_NUMPY_VERSION = "2.5.2"
EXPECTED_SKLEARN_VERSION = "1.9.0"

EXPECTED_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}


class StageCCandidateTrainingError(ValueError):
    pass


@dataclass(frozen=True)
class CandidateSpec:
    candidate_id: str
    family: str
    eligible_for_later_selection: bool
    parameters: Mapping[str, Any]
    factory: Callable[[], Any]


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
        raise StageCCandidateTrainingError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCandidateTrainingError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCCandidateTrainingError(f"JSON root must be object: {path}")
    return value


def _candidate_specs() -> tuple[CandidateSpec, ...]:
    return (
        CandidateSpec(
            candidate_id="dummy_prior",
            family="diagnostic_baseline",
            eligible_for_later_selection=False,
            parameters={"strategy": "prior"},
            factory=lambda: DummyClassifier(strategy="prior"),
        ),
        CandidateSpec(
            candidate_id="logistic_regression",
            family="linear",
            eligible_for_later_selection=True,
            parameters={
                "scaler": "StandardScaler",
                "C": 1.0,
                "class_weight": "balanced",
                "max_iter": 2000,
                "solver": "lbfgs",
                "random_state": RANDOM_SEED,
            },
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
        ),
        CandidateSpec(
            candidate_id="hist_gradient_boosting",
            family="boosting",
            eligible_for_later_selection=True,
            parameters={
                "learning_rate": 0.05,
                "max_iter": 120,
                "max_leaf_nodes": 15,
                "min_samples_leaf": 10,
                "l2_regularization": 1.0,
                "random_state": RANDOM_SEED,
            },
            factory=lambda: HistGradientBoostingClassifier(
                learning_rate=0.05,
                max_iter=120,
                max_leaf_nodes=15,
                min_samples_leaf=10,
                l2_regularization=1.0,
                random_state=RANDOM_SEED,
            ),
        ),
        CandidateSpec(
            candidate_id="random_forest_compact",
            family="bagged_trees",
            eligible_for_later_selection=True,
            parameters={
                "n_estimators": 128,
                "max_depth": 8,
                "min_samples_leaf": 2,
                "class_weight": "balanced_subsample",
                "max_features": "sqrt",
                "random_state": RANDOM_SEED,
                "n_jobs": 1,
            },
            factory=lambda: RandomForestClassifier(
                n_estimators=128,
                max_depth=8,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                max_features="sqrt",
                random_state=RANDOM_SEED,
                n_jobs=1,
            ),
        ),
    )


def candidate_protocol() -> dict[str, Any]:
    specs = _candidate_specs()
    payload = {
        "schema_version": TRAINING_SCHEMA,
        "random_seed": RANDOM_SEED,
        "fit_partition": "train",
        "selection_partition": "LOCKED_NOT_USED",
        "calibration_partition": "LOCKED_NOT_USED",
        "final_holdout": "LOCKED_NOT_USED",
        "model_scoring_performed": False,
        "training_order": "SAMPLE_ID_ASCENDING",
        "pickle_protocol": 5,
        "candidates": [
            {
                "candidate_id": s.candidate_id,
                "family": s.family,
                "eligible_for_later_selection": s.eligible_for_later_selection,
                "parameters": dict(s.parameters),
            }
            for s in specs
        ],
    }
    payload["candidate_protocol_sha256"] = canonical_hash(payload)
    return payload


def validate_authorization(auth: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-model-training-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": True,
        "model_training_authorized": True,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": "FIT_MODEL_PARAMETERS_ON_COMPLETE_COLLECTION_TRAIN_ROWS",
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "next_gate": "TRAIN_STAGE_C_CANDIDATE_MODELS_ON_AUTHORIZED_TRAIN_SUBSET",
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCCandidateTrainingError(f"Task-11 authorization guard mismatch: {key}")
    if hash_without(auth, "authorization_sha256") != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCCandidateTrainingError("Task-11 canonical authorization hash mismatch")

    scope = auth.get("training_scope")
    universe = auth.get("modeling_universe")
    excluded = auth.get("excluded_collection_incomplete")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(isinstance(x, Mapping) for x in (scope, universe, excluded, bindings, prohibitions)):
        raise StageCCandidateTrainingError("Task-11 authorization sections missing")

    checks = [
        (scope.get("authorized_partition") == "train", "authorized partition"),
        (scope.get("authorized_sample_count") == EXPECTED_TRAIN_COUNT, "train count"),
        (scope.get("authorized_sample_set_sha256") == EXPECTED_TRAIN_SHA256, "train identity"),
        (scope.get("authorized_label_counts") == EXPECTED_TRAIN_LABEL_COUNTS, "train labels"),
        (scope.get("feature_count") == EXPECTED_FEATURE_COUNT, "feature count"),
        (scope.get("model_observable_fields") == ["feature_vector"], "model fields"),
        (scope.get("supervision_metadata_fields") == ["label"], "supervision fields"),
        (scope.get("collection_incomplete_rows_authorized") is False, "incomplete exclusion"),
        (scope.get("selection_partition_use_for_fitting_authorized") is False, "selection fitting lock"),
        (scope.get("calibration_partition_use_for_fitting_authorized") is False, "calibration fitting lock"),
        (scope.get("final_holdout_authorized") is False, "final holdout lock"),
        (universe.get("policy") == "COLLECTION_COMPLETE_ONLY", "modeling policy"),
        (universe.get("sample_count") == EXPECTED_MODELING_COUNT, "modeling count"),
        (universe.get("sample_set_sha256") == EXPECTED_MODELING_SHA256, "modeling identity"),
        (excluded.get("sample_count") == EXPECTED_INCOMPLETE_COUNT, "incomplete count"),
        (excluded.get("model_fitting_authorized") is False, "incomplete fitting lock"),
        (bindings.get("feature_dataset_sha256") == EXPECTED_FEATURE_DATASET_SHA256, "dataset identity"),
        (bindings.get("git_head") == EXPECTED_TASK11_GIT_HEAD, "Task-11 Git identity"),
        (prohibitions.get("selection_labels_for_training") is True, "selection-label prohibition"),
        (prohibitions.get("calibration_labels_for_training") is True, "calibration-label prohibition"),
        (prohibitions.get("model_scoring_during_training") is True, "scoring prohibition"),
        (prohibitions.get("final_holdout_access") is True, "holdout prohibition"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCCandidateTrainingError(f"Task-11 authorization changed: {name}")


def load_authorized_train(
    feature_dataset_path: Path,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCCandidateTrainingError("Task-10 feature dataset SHA-256 mismatch")

    seen: set[str] = set()
    complete_ids: list[str] = []
    train_rows: list[dict[str, Any]] = []
    incomplete_count = 0

    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCandidateTrainingError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_ROW_FIELDS:
                raise StageCCandidateTrainingError("feature row closed-schema mismatch")

            sid = row["sample_id"]
            part = row["partition"]
            label = row["label"]
            vector = row["feature_vector"]
            incomplete = row["collection_incomplete"]
            dropped = row["dropped_events"]
            history = row["history_truncated"]

            if not isinstance(sid, str) or not sid or sid in seen:
                raise StageCCandidateTrainingError("duplicate/invalid sample_id")
            if part not in {"train", "selection", "calibration"} or label not in (0, 1):
                raise StageCCandidateTrainingError("partition/label invalid")
            if not isinstance(vector, list) or len(vector) != EXPECTED_FEATURE_COUNT:
                raise StageCCandidateTrainingError("feature vector shape changed")
            if any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
                raise StageCCandidateTrainingError("non-finite feature vector")
            if type(incomplete) is not bool or type(history) is not bool:
                raise StageCCandidateTrainingError("collection flags invalid")
            if type(dropped) is not int or dropped < 0:
                raise StageCCandidateTrainingError("dropped-event count invalid")
            if incomplete is not (dropped > 0 or history):
                raise StageCCandidateTrainingError("collection-loss metadata mismatch")

            seen.add(sid)
            if incomplete:
                incomplete_count += 1
                continue

            complete_ids.append(sid)
            if part == "train":
                train_rows.append({
                    "sample_id": sid,
                    "label": int(label),
                    "feature_vector": list(vector),
                })

    if len(seen) != 73777:
        raise StageCCandidateTrainingError("full feature row count changed")
    if incomplete_count != EXPECTED_INCOMPLETE_COUNT:
        raise StageCCandidateTrainingError("incomplete row count changed")
    if len(complete_ids) != EXPECTED_MODELING_COUNT:
        raise StageCCandidateTrainingError("complete modeling row count changed")
    if canonical_hash(sorted(complete_ids)) != EXPECTED_MODELING_SHA256:
        raise StageCCandidateTrainingError("complete modeling identity changed")

    train_rows.sort(key=lambda x: x["sample_id"])
    train_ids = [row["sample_id"] for row in train_rows]
    if len(train_rows) != EXPECTED_TRAIN_COUNT:
        raise StageCCandidateTrainingError("authorized train count changed")
    if canonical_hash(train_ids) != EXPECTED_TRAIN_SHA256:
        raise StageCCandidateTrainingError("authorized train identity changed")

    labels = Counter(row["label"] for row in train_rows)
    actual_labels = {"legitimate": labels[0], "phishing": labels[1]}
    if actual_labels != EXPECTED_TRAIN_LABEL_COUNTS:
        raise StageCCandidateTrainingError("authorized train label counts changed")

    training_identity_rows = [
        {
            "sample_id": row["sample_id"],
            "label": row["label"],
            "feature_vector": row["feature_vector"],
        }
        for row in train_rows
    ]
    training_matrix_sha256 = canonical_hash(training_identity_rows)

    x = np.asarray([row["feature_vector"] for row in train_rows], dtype=np.float64)
    y = np.asarray([row["label"] for row in train_rows], dtype=np.int64)
    if x.shape != (EXPECTED_TRAIN_COUNT, EXPECTED_FEATURE_COUNT):
        raise StageCCandidateTrainingError("training matrix shape changed")
    if y.shape != (EXPECTED_TRAIN_COUNT,) or set(y.tolist()) != {0, 1}:
        raise StageCCandidateTrainingError("training labels invalid")
    if not np.isfinite(x).all():
        raise StageCCandidateTrainingError("training matrix contains non-finite values")

    return x, y, {
        "authorized_train_sample_count": len(train_rows),
        "authorized_train_sample_set_sha256": EXPECTED_TRAIN_SHA256,
        "authorized_train_label_counts": actual_labels,
        "training_matrix_sha256": training_matrix_sha256,
        "training_order": "SAMPLE_ID_ASCENDING",
        "feature_count": EXPECTED_FEATURE_COUNT,
    }


def _environment() -> dict[str, str]:
    versions = {
        "python": platform.python_version(),
        "numpy": importlib.metadata.version("numpy"),
        "scikit-learn": importlib.metadata.version("scikit-learn"),
    }
    if versions["numpy"] != EXPECTED_NUMPY_VERSION:
        raise StageCCandidateTrainingError(
            f"numpy version changed: {versions['numpy']} != {EXPECTED_NUMPY_VERSION}"
        )
    if versions["scikit-learn"] != EXPECTED_SKLEARN_VERSION:
        raise StageCCandidateTrainingError(
            "scikit-learn version changed: "
            f"{versions['scikit-learn']} != {EXPECTED_SKLEARN_VERSION}"
        )
    return versions


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/training/stage_c_candidate_training.py",
        "ml/training/train_stage_c_candidates.py",
        "ml/data/stage_c_model_training_authorization.py",
        "requirements.txt",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            capture_output=True, text=True, encoding="utf-8", check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCCandidateTrainingError("invalid Git HEAD identity")
        for relative in paths:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"],
                cwd=repo_root, capture_output=True, check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *paths],
            cwd=repo_root,
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCCandidateTrainingError(
            "Task-12 and bound training files must be committed before fitting"
        ) from exc
    if dirty != 0:
        raise StageCCandidateTrainingError(
            "Task-12/bound training files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task12_module_sha256": sha256_file(repo_root / paths[0]),
        "task12_cli_sha256": sha256_file(repo_root / paths[1]),
        "task11_module_sha256": sha256_file(repo_root / paths[2]),
        "requirements_sha256": sha256_file(repo_root / paths[3]),
    }


def atomic_frozen_bytes(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCCandidateTrainingError(
                f"refusing to replace non-identical frozen model artifact: {path}"
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


def fit_candidates(
    x: np.ndarray,
    y: np.ndarray,
) -> list[dict[str, Any]]:
    if x.ndim != 2 or x.shape[1] != EXPECTED_FEATURE_COUNT:
        raise StageCCandidateTrainingError("fit matrix must have 27 features")
    if y.ndim != 1 or len(y) != len(x) or set(y.tolist()) != {0, 1}:
        raise StageCCandidateTrainingError("fit labels invalid")
    if not np.isfinite(x).all():
        raise StageCCandidateTrainingError("fit matrix contains non-finite values")

    trained: list[dict[str, Any]] = []
    for spec in _candidate_specs():
        model = spec.factory()
        model.fit(x, y)
        if not hasattr(model, "predict_proba"):
            raise StageCCandidateTrainingError(
                f"candidate lacks predict_proba for later authorized scoring: {spec.candidate_id}"
            )
        payload = pickle.dumps(model, protocol=5)
        trained.append({
            "candidate_id": spec.candidate_id,
            "family": spec.family,
            "eligible_for_later_selection": spec.eligible_for_later_selection,
            "parameters": dict(spec.parameters),
            "artifact_bytes": payload,
            "artifact_sha256": hashlib.sha256(payload).hexdigest(),
            "artifact_size_bytes": len(payload),
        })
    return trained


def train_stage_c_candidates(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    authorization_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    validate_authorization(auth)
    x, y, train_identity = load_authorized_train(feature_dataset_path)
    environment = _environment()
    git = _git_provenance(repo_root)
    protocol = candidate_protocol()

    trained = fit_candidates(x, y)

    artifact_dir = output_root / "artifacts"
    artifact_records: list[dict[str, Any]] = []
    states: dict[str, str] = {}
    for candidate in trained:
        path = artifact_dir / f"{candidate['candidate_id']}.pkl"
        state = atomic_frozen_bytes(path, candidate["artifact_bytes"])
        states[candidate["candidate_id"]] = state
        artifact_records.append({
            "candidate_id": candidate["candidate_id"],
            "family": candidate["family"],
            "eligible_for_later_selection": candidate["eligible_for_later_selection"],
            "parameters": candidate["parameters"],
            "artifact": str(path),
            "artifact_format": "PYTHON_PICKLE_PROTOCOL_5_TRUSTED_LOCAL_ONLY",
            "artifact_sha256": candidate["artifact_sha256"],
            "artifact_size_bytes": candidate["artifact_size_bytes"],
        })

    artifact_records.sort(key=lambda x: x["candidate_id"])
    artifact_set_sha256 = canonical_hash([
        {
            "candidate_id": row["candidate_id"],
            "artifact_sha256": row["artifact_sha256"],
        }
        for row in artifact_records
    ])

    manifest = {
        "schema_version": TRAINING_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": True,
        "candidate_training_complete": True,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "model_scoring_performed": False,
        "final_holdout_touched": False,
        "authorized_action": "FIT_MODEL_PARAMETERS_ON_COMPLETE_COLLECTION_TRAIN_ROWS",
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "training_data": train_identity,
        "candidate_protocol": protocol,
        "candidate_count": len(artifact_records),
        "candidate_artifacts": artifact_records,
        "candidate_artifact_set_sha256": artifact_set_sha256,
        "environment": environment,
        "git_provenance": git,
        "selection_partition": "LOCKED_NOT_USED",
        "calibration_partition": "LOCKED_NOT_USED",
        "final_holdout": "LOCKED_NOT_USED",
        "limitations": [
            "Task 12 performs parameter fitting only; it does not score or rank candidates.",
            "Selection and calibration rows are not used for fitting.",
            "The seven collection-incomplete rows remain excluded from the modeling universe.",
            "Pickle artifacts are trusted local research artifacts and must not be loaded from untrusted sources.",
            "PASS does not authorize model selection, calibration, thresholding, deployment, or final-holdout access.",
        ],
        "next_gate": "ISSUE_STAGE_C_SELECTION_SCORING_AUTHORIZATION_FOR_FROZEN_CANDIDATES",
    }
    manifest["training_manifest_sha256"] = canonical_hash(manifest)
    manifest_path = output_root / "candidate-training-manifest-v1.json"
    manifest_state = frozen_write_json(manifest_path, manifest)

    return {
        "status": "PASS",
        "manifest": str(manifest_path),
        "manifest_state": manifest_state,
        "training_manifest_sha256": manifest["training_manifest_sha256"],
        "authorized_train_sample_count": train_identity["authorized_train_sample_count"],
        "training_matrix_sha256": train_identity["training_matrix_sha256"],
        "candidate_count": len(artifact_records),
        "candidate_artifact_set_sha256": artifact_set_sha256,
        "artifact_states": states,
        "model_training_authorized": True,
        "candidate_training_complete": True,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "model_scoring_performed": False,
        "final_holdout_touched": False,
        "next_gate": manifest["next_gate"],
    }
