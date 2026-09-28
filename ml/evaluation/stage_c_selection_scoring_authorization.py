"""Stage C Task 13 — authorize feature-only scoring on the frozen selection subset.

This module does not load or execute candidate models. It verifies the frozen
Task-12 artifacts and authorizes later prediction generation only on the exact
collection-complete selection feature matrix. Selection labels remain locked.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-selection-scoring-authorization-1"

EXPECTED_TASK11_AUTHORIZATION_SHA256 = "fa8a80ae3fc60f8c33518be10c77cc3df5ca793050fa2a44ecf181d16f311bc3"
EXPECTED_TASK12_TRAINING_MANIFEST_SHA256 = "887903dfe3af05490c0f2cc89ad3bcc9afa20a1ac495a7e4ca9fdaca44369399"
EXPECTED_TASK12_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"
EXPECTED_TASK12_GIT_HEAD = "4a018f0474293aef0f5a4902a22d214a61db869b"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_TOTAL_ROWS = 73777
EXPECTED_MODELING_COUNT = 73770
EXPECTED_MODELING_SHA256 = "451712b4b9f2584f228b4547fd70875f1e58c2888ff4e8352eb1f7544168a98b"
EXPECTED_SELECTION_COUNT = 20710
EXPECTED_INCOMPLETE_COUNT = 7
EXPECTED_SELECTION_CLASS_COUNTS = {"legitimate": 19641, "phishing": 1069}
EXPECTED_FEATURE_COUNT = 27
EXPECTED_CANDIDATES = {
    "dummy_prior": {"family": "diagnostic_baseline", "eligible_for_later_selection": False},
    "logistic_regression": {"family": "linear", "eligible_for_later_selection": True},
    "hist_gradient_boosting": {"family": "boosting", "eligible_for_later_selection": True},
    "random_forest_compact": {"family": "bagged_trees", "eligible_for_later_selection": True},
}
EXPECTED_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}


class StageCSelectionScoringAuthorizationError(ValueError):
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
        raise StageCSelectionScoringAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCSelectionScoringAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCSelectionScoringAuthorizationError(
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
            raise StageCSelectionScoringAuthorizationError(
                f"refusing to replace non-identical frozen Task-13 output: {path}"
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


def validate_task11_authorization(auth: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-model-training-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": True,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK11_AUTHORIZATION_SHA256,
        "next_gate": "TRAIN_STAGE_C_CANDIDATE_MODELS_ON_AUTHORIZED_TRAIN_SUBSET",
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCSelectionScoringAuthorizationError(
                f"Task-11 authorization guard mismatch: {key}"
            )
    if hash_without(auth, "authorization_sha256") != EXPECTED_TASK11_AUTHORIZATION_SHA256:
        raise StageCSelectionScoringAuthorizationError(
            "Task-11 canonical authorization hash mismatch"
        )
    universe = auth.get("modeling_universe")
    if not isinstance(universe, Mapping):
        raise StageCSelectionScoringAuthorizationError("Task-11 modeling universe missing")
    if (
        universe.get("policy") != "COLLECTION_COMPLETE_ONLY"
        or universe.get("sample_count") != EXPECTED_MODELING_COUNT
        or universe.get("sample_set_sha256") != EXPECTED_MODELING_SHA256
    ):
        raise StageCSelectionScoringAuthorizationError(
            "Task-11 modeling universe changed"
        )
    partition_counts = universe.get("partition_counts")
    partition_ids = universe.get("partition_sample_set_sha256")
    if not isinstance(partition_counts, Mapping) or not isinstance(partition_ids, Mapping):
        raise StageCSelectionScoringAuthorizationError(
            "Task-11 partition identities missing"
        )
    selection_counts = partition_counts.get("selection")
    selection_sha = partition_ids.get("selection")
    if selection_counts != {
        "total": EXPECTED_SELECTION_COUNT,
        **EXPECTED_SELECTION_CLASS_COUNTS,
    }:
        raise StageCSelectionScoringAuthorizationError(
            "Task-11 selection counts changed"
        )
    if not isinstance(selection_sha, str) or len(selection_sha) != 64:
        raise StageCSelectionScoringAuthorizationError(
            "Task-11 selection sample-set identity invalid"
        )
    return {
        "selection_sample_count": EXPECTED_SELECTION_COUNT,
        "selection_sample_set_sha256": selection_sha,
    }


def validate_task12_manifest(
    manifest: Mapping[str, Any],
    *,
    candidate_root: Path,
) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-candidate-training-1",
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
        "authorization_sha256": EXPECTED_TASK11_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "candidate_count": 4,
        "candidate_artifact_set_sha256": EXPECTED_TASK12_ARTIFACT_SET_SHA256,
        "selection_partition": "LOCKED_NOT_USED",
        "calibration_partition": "LOCKED_NOT_USED",
        "final_holdout": "LOCKED_NOT_USED",
        "training_manifest_sha256": EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
        "next_gate": "ISSUE_STAGE_C_SELECTION_SCORING_AUTHORIZATION_FOR_FROZEN_CANDIDATES",
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise StageCSelectionScoringAuthorizationError(
                f"Task-12 training manifest guard mismatch: {key}"
            )
    if hash_without(manifest, "training_manifest_sha256") != EXPECTED_TASK12_TRAINING_MANIFEST_SHA256:
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 canonical training manifest hash mismatch"
        )

    git = manifest.get("git_provenance")
    training = manifest.get("training_data")
    protocol = manifest.get("candidate_protocol")
    artifacts = manifest.get("candidate_artifacts")
    if not isinstance(git, Mapping) or not isinstance(training, Mapping):
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 provenance/training identity missing"
        )
    if not isinstance(protocol, Mapping) or not isinstance(artifacts, list):
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 protocol/artifacts missing"
        )
    if git.get("git_head") != EXPECTED_TASK12_GIT_HEAD:
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 Git identity changed"
        )
    if training.get("authorized_train_sample_count") != 45746:
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 train count changed"
        )
    if training.get("authorized_train_sample_set_sha256") != (
        "50138895b65a7a4b1c5b7defd331e4fed715f88b281eca04edfd0f2e613124c4"
    ):
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 train identity changed"
        )
    if protocol.get("selection_partition") != "LOCKED_NOT_USED":
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 used selection before Task 13"
        )
    if protocol.get("model_scoring_performed") is not False:
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 unexpectedly performed scoring"
        )

    by_id: dict[str, Mapping[str, Any]] = {}
    for row in artifacts:
        if not isinstance(row, Mapping):
            raise StageCSelectionScoringAuthorizationError(
                "Task-12 artifact record invalid"
            )
        cid = row.get("candidate_id")
        if not isinstance(cid, str) or cid in by_id:
            raise StageCSelectionScoringAuthorizationError(
                "Task-12 candidate identity invalid"
            )
        by_id[cid] = row
    if set(by_id) != set(EXPECTED_CANDIDATES):
        raise StageCSelectionScoringAuthorizationError(
            "Task-12 candidate set changed"
        )

    verified: list[dict[str, Any]] = []
    for cid in sorted(EXPECTED_CANDIDATES):
        row = by_id[cid]
        expected_candidate = EXPECTED_CANDIDATES[cid]
        if row.get("family") != expected_candidate["family"]:
            raise StageCSelectionScoringAuthorizationError(
                f"candidate family changed: {cid}"
            )
        if row.get("eligible_for_later_selection") is not expected_candidate[
            "eligible_for_later_selection"
        ]:
            raise StageCSelectionScoringAuthorizationError(
                f"candidate eligibility changed: {cid}"
            )
        if row.get("artifact_format") != "PYTHON_PICKLE_PROTOCOL_5_TRUSTED_LOCAL_ONLY":
            raise StageCSelectionScoringAuthorizationError(
                f"candidate artifact format changed: {cid}"
            )
        artifact_sha = row.get("artifact_sha256")
        artifact_size = row.get("artifact_size_bytes")
        if not isinstance(artifact_sha, str) or len(artifact_sha) != 64:
            raise StageCSelectionScoringAuthorizationError(
                f"candidate artifact SHA invalid: {cid}"
            )
        if type(artifact_size) is not int or artifact_size <= 0:
            raise StageCSelectionScoringAuthorizationError(
                f"candidate artifact size invalid: {cid}"
            )
        artifact_path = candidate_root / "artifacts" / f"{cid}.pkl"
        if not artifact_path.is_file():
            raise StageCSelectionScoringAuthorizationError(
                f"candidate artifact missing: {artifact_path}"
            )
        if artifact_path.stat().st_size != artifact_size:
            raise StageCSelectionScoringAuthorizationError(
                f"candidate artifact size mismatch: {cid}"
            )
        if sha256_file(artifact_path) != artifact_sha:
            raise StageCSelectionScoringAuthorizationError(
                f"candidate artifact SHA mismatch: {cid}"
            )
        verified.append({
            "candidate_id": cid,
            "family": expected_candidate["family"],
            "eligible_for_later_selection": expected_candidate[
                "eligible_for_later_selection"
            ],
            "artifact_sha256": artifact_sha,
            "artifact_size_bytes": artifact_size,
        })

    artifact_set = canonical_hash([
        {
            "candidate_id": row["candidate_id"],
            "artifact_sha256": row["artifact_sha256"],
        }
        for row in verified
    ])
    if artifact_set != EXPECTED_TASK12_ARTIFACT_SET_SHA256:
        raise StageCSelectionScoringAuthorizationError(
            "verified candidate artifact set identity changed"
        )

    return {
        "candidate_count": len(verified),
        "candidate_artifact_set_sha256": artifact_set,
        "candidate_artifacts": verified,
        "candidate_protocol_sha256": protocol.get("candidate_protocol_sha256"),
        "training_matrix_sha256": training.get("training_matrix_sha256"),
    }


def derive_selection_feature_scope(
    feature_dataset_path: Path,
    *,
    expected_selection_sample_set_sha256: str,
) -> dict[str, Any]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCSelectionScoringAuthorizationError(
            "Task-10 feature dataset SHA-256 mismatch"
        )

    seen: set[str] = set()
    complete_ids: list[str] = []
    selection_rows: list[dict[str, Any]] = []
    incomplete_count = 0

    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCSelectionScoringAuthorizationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_ROW_FIELDS:
                raise StageCSelectionScoringAuthorizationError(
                    "feature row closed-schema mismatch"
                )
            sid = row["sample_id"]
            part = row["partition"]
            vector = row["feature_vector"]
            incomplete = row["collection_incomplete"]
            dropped = row["dropped_events"]
            history = row["history_truncated"]

            if not isinstance(sid, str) or not sid or sid in seen:
                raise StageCSelectionScoringAuthorizationError(
                    "duplicate/invalid sample_id"
                )
            if part not in {"train", "selection", "calibration"}:
                raise StageCSelectionScoringAuthorizationError(
                    "partition invalid"
                )
            if not isinstance(vector, list) or len(vector) != EXPECTED_FEATURE_COUNT:
                raise StageCSelectionScoringAuthorizationError(
                    "feature vector shape changed"
                )
            if any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
                raise StageCSelectionScoringAuthorizationError(
                    "feature vector contains non-finite value"
                )
            if type(incomplete) is not bool or type(history) is not bool:
                raise StageCSelectionScoringAuthorizationError(
                    "collection flags invalid"
                )
            if type(dropped) is not int or dropped < 0:
                raise StageCSelectionScoringAuthorizationError(
                    "dropped-event count invalid"
                )
            if incomplete is not (dropped > 0 or history):
                raise StageCSelectionScoringAuthorizationError(
                    "collection-loss metadata mismatch"
                )

            seen.add(sid)
            if incomplete:
                incomplete_count += 1
                continue
            complete_ids.append(sid)
            if part == "selection":
                selection_rows.append({
                    "sample_id": sid,
                    "feature_vector": list(vector),
                })

    if len(seen) != EXPECTED_TOTAL_ROWS:
        raise StageCSelectionScoringAuthorizationError(
            "full feature row count changed"
        )
    if incomplete_count != EXPECTED_INCOMPLETE_COUNT:
        raise StageCSelectionScoringAuthorizationError(
            "collection-incomplete count changed"
        )
    if len(complete_ids) != EXPECTED_MODELING_COUNT:
        raise StageCSelectionScoringAuthorizationError(
            "modeling-universe count changed"
        )
    if canonical_hash(sorted(complete_ids)) != EXPECTED_MODELING_SHA256:
        raise StageCSelectionScoringAuthorizationError(
            "modeling-universe identity changed"
        )

    selection_rows.sort(key=lambda x: x["sample_id"])
    selection_ids = [row["sample_id"] for row in selection_rows]
    if len(selection_ids) != EXPECTED_SELECTION_COUNT:
        raise StageCSelectionScoringAuthorizationError(
            "selection count changed"
        )
    actual_selection_sha = canonical_hash(selection_ids)
    if actual_selection_sha != expected_selection_sample_set_sha256:
        raise StageCSelectionScoringAuthorizationError(
            "selection sample-set identity changed"
        )

    feature_matrix_sha = canonical_hash(selection_rows)
    return {
        "selection_sample_count": len(selection_rows),
        "selection_sample_set_sha256": actual_selection_sha,
        "selection_feature_matrix_sha256": feature_matrix_sha,
        "feature_count": EXPECTED_FEATURE_COUNT,
        "scoring_order": "SAMPLE_ID_ASCENDING",
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_selection_scoring_authorization.py",
        "ml/evaluation/authorize_stage_c_selection_scoring.py",
        "ml/training/stage_c_candidate_training.py",
        "ml/data/stage_c_model_training_authorization.py",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            capture_output=True, text=True, encoding="utf-8", check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCSelectionScoringAuthorizationError(
                "invalid Git HEAD identity"
            )
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
        raise StageCSelectionScoringAuthorizationError(
            "Task-13 and bound files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCSelectionScoringAuthorizationError(
            "Task-13/bound files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task13_module_sha256": sha256_file(repo_root / paths[0]),
        "task13_cli_sha256": sha256_file(repo_root / paths[1]),
        "task12_module_sha256": sha256_file(repo_root / paths[2]),
        "task11_module_sha256": sha256_file(repo_root / paths[3]),
    }


def issue_selection_scoring_authorization(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    task11_authorization_path: Path,
    training_manifest_path: Path,
    candidate_root: Path,
) -> dict[str, Any]:
    task11 = load_json(task11_authorization_path)
    manifest = load_json(training_manifest_path)

    selection_binding = validate_task11_authorization(task11)
    candidate_binding = validate_task12_manifest(
        manifest, candidate_root=candidate_root
    )
    selection_scope = derive_selection_feature_scope(
        feature_dataset_path,
        expected_selection_sample_set_sha256=selection_binding[
            "selection_sample_set_sha256"
        ],
    )
    git = _git_provenance(repo_root)

    authorization = {
        "schema_version": AUTH_SCHEMA,
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
        "selection_scope": {
            **selection_scope,
            "authorized_partition": "selection",
            "model_observable_fields": ["feature_vector"],
            "label_field_authorized": False,
            "collection_incomplete_rows_authorized": False,
            "calibration_partition_authorized": False,
            "final_holdout_authorized": False,
        },
        "candidate_scope": candidate_binding,
        "identity_bindings": {
            "task11_authorization_sha256": EXPECTED_TASK11_AUTHORIZATION_SHA256,
            "task12_training_manifest_sha256": EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
            "task12_candidate_artifact_set_sha256": EXPECTED_TASK12_ARTIFACT_SET_SHA256,
            "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
            **git,
        },
        "prohibitions": {
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
        "next_gate": "SCORE_STAGE_C_FROZEN_CANDIDATES_ON_SELECTION_FEATURES_WITH_LABELS_LOCKED",
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
