"""Stage C Task 19 — authorize calibration scoring for the selected candidate.

This gate binds the frozen Task-18 candidate selection, the physical selected
Task-12 artifact, and the exact collection-complete calibration feature subset.

It authorizes a later task to generate selected-candidate probability scores on
calibration feature vectors with calibration labels locked.

Task 19 itself does not load/execute the model, read calibration labels for
evaluation, fit a calibrator, choose/freeze a threshold, deploy, or touch the
final holdout.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-calibration-scoring-authorization-1"

EXPECTED_TASK18_SELECTION_RECORD_SHA256 = "dffd5498523326c3272d32f50662a68f0671a6a51424bf8ebc2f75382eec0a10"
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_CANDIDATE_FAMILY = "linear"
EXPECTED_SELECTED_ARTIFACT_SHA256 = "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"

EXPECTED_TASK17_AUTHORIZATION_SHA256 = "416c29e333325b0f0f201eecde801fdc1ee05b966a8d84c78bd24a07a626ea34"
EXPECTED_TASK12_TRAINING_MANIFEST_SHA256 = "887903dfe3af05490c0f2cc89ad3bcc9afa20a1ac495a7e4ca9fdaca44369399"
EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"

EXPECTED_TOTAL_ROWS = 73777
EXPECTED_FEATURE_COUNT = 27
EXPECTED_COMPLETE_CALIBRATION_COUNT = 7314
EXPECTED_INCOMPLETE_CALIBRATION_COUNT = 1

EXPECTED_FEATURE_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}


class StageCCalibrationScoringAuthorizationError(ValueError):
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
        raise StageCCalibrationScoringAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCalibrationScoringAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCCalibrationScoringAuthorizationError(
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
            raise StageCCalibrationScoringAuthorizationError(
                f"refusing to replace non-identical frozen Task-19 output: {path}"
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


def validate_task18_selection(record: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-candidate-selection-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selection_metrics_computed": True,
        "model_selection_authorized": True,
        "model_selection_performed": True,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "selected_candidate_family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
        "selection_diagnostic_threshold_frozen": False,
        "calibration_access_authorized": False,
        "calibration_scoring_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "selection_record_sha256": EXPECTED_TASK18_SELECTION_RECORD_SHA256,
        "next_gate": (
            "ISSUE_STAGE_C_CALIBRATION_SCORING_AUTHORIZATION_FOR_SELECTED_CANDIDATE"
        ),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise StageCCalibrationScoringAuthorizationError(
                f"Task-18 selection guard mismatch: {key}"
            )
    if (
        hash_without(record, "selection_record_sha256")
        != EXPECTED_TASK18_SELECTION_RECORD_SHA256
    ):
        raise StageCCalibrationScoringAuthorizationError(
            "Task-18 canonical selection-record hash mismatch"
        )

    artifact = record.get("selected_candidate_artifact")
    result = record.get("selection_result")
    bindings = record.get("identity_bindings")
    prohibitions = record.get("prohibitions")
    if not all(
        isinstance(x, Mapping)
        for x in (artifact, result, bindings, prohibitions)
    ):
        raise StageCCalibrationScoringAuthorizationError(
            "Task-18 selection sections missing"
        )

    checks = [
        (
            artifact.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID,
            "selected artifact candidate",
        ),
        (
            artifact.get("family") == EXPECTED_SELECTED_CANDIDATE_FAMILY,
            "selected artifact family",
        ),
        (
            artifact.get("artifact_sha256") == EXPECTED_SELECTED_ARTIFACT_SHA256,
            "selected artifact SHA",
        ),
        (
            artifact.get("physical_artifact_verified") is True,
            "physical artifact verification",
        ),
        (
            result.get("selection_diagnostic_threshold_frozen") is False,
            "selection diagnostic threshold freeze",
        ),
        (
            result.get(
                "selection_diagnostic_threshold_authorized_for_calibration"
            ) is False,
            "selection diagnostic threshold calibration carryover",
        ),
        (
            bindings.get("task17_authorization_sha256")
            == EXPECTED_TASK17_AUTHORIZATION_SHA256,
            "Task-17 binding",
        ),
        (
            bindings.get("task12_training_manifest_sha256")
            == EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
            "Task-12 binding",
        ),
        (
            bindings.get("candidate_artifact_set_sha256")
            == EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
            "artifact-set binding",
        ),
        (
            prohibitions.get("reuse_selection_diagnostic_threshold_as_calibration_threshold")
            is True,
            "selection-threshold carryover prohibition",
        ),
        (
            prohibitions.get("calibration_access") is True,
            "Task-18 calibration-access prohibition",
        ),
        (
            prohibitions.get("calibration_scoring") is True,
            "Task-18 calibration-scoring prohibition",
        ),
        (
            prohibitions.get("threshold_freeze") is True,
            "Task-18 threshold-freeze prohibition",
        ),
        (
            prohibitions.get("final_holdout_access") is True,
            "Task-18 holdout prohibition",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCCalibrationScoringAuthorizationError(
                f"Task-18 selection changed: {name}"
            )
    return dict(artifact)


def validate_training_manifest_and_selected_artifact(
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
        "candidate_count": 4,
        "candidate_artifact_set_sha256": EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
        "training_manifest_sha256": EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise StageCCalibrationScoringAuthorizationError(
                f"Task-12 training manifest guard mismatch: {key}"
            )
    if (
        hash_without(manifest, "training_manifest_sha256")
        != EXPECTED_TASK12_TRAINING_MANIFEST_SHA256
    ):
        raise StageCCalibrationScoringAuthorizationError(
            "Task-12 canonical training-manifest hash mismatch"
        )

    artifacts = manifest.get("candidate_artifacts")
    if not isinstance(artifacts, list):
        raise StageCCalibrationScoringAuthorizationError(
            "Task-12 candidate artifacts missing"
        )
    matches = [
        row for row in artifacts
        if isinstance(row, Mapping)
        and row.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID
    ]
    if len(matches) != 1:
        raise StageCCalibrationScoringAuthorizationError(
            "selected Task-12 candidate artifact record missing"
        )
    row = matches[0]
    if row.get("family") != EXPECTED_SELECTED_CANDIDATE_FAMILY:
        raise StageCCalibrationScoringAuthorizationError(
            "selected Task-12 family changed"
        )
    if row.get("eligible_for_later_selection") is not True:
        raise StageCCalibrationScoringAuthorizationError(
            "selected Task-12 candidate is no longer eligible"
        )
    if row.get("artifact_sha256") != EXPECTED_SELECTED_ARTIFACT_SHA256:
        raise StageCCalibrationScoringAuthorizationError(
            "selected Task-12 artifact SHA changed"
        )
    artifact_size = row.get("artifact_size_bytes")
    if type(artifact_size) is not int or artifact_size <= 0:
        raise StageCCalibrationScoringAuthorizationError(
            "selected Task-12 artifact size invalid"
        )

    artifact_path = (
        candidate_root / "artifacts" / f"{EXPECTED_SELECTED_CANDIDATE_ID}.pkl"
    )
    if not artifact_path.is_file():
        raise StageCCalibrationScoringAuthorizationError(
            f"selected candidate artifact missing: {artifact_path}"
        )
    if artifact_path.stat().st_size != artifact_size:
        raise StageCCalibrationScoringAuthorizationError(
            "selected candidate artifact size mismatch"
        )
    if sha256_file(artifact_path) != EXPECTED_SELECTED_ARTIFACT_SHA256:
        raise StageCCalibrationScoringAuthorizationError(
            "selected candidate artifact SHA mismatch"
        )
    return {
        "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
        "artifact_path": str(artifact_path),
        "artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "artifact_size_bytes": artifact_size,
        "artifact_format": row.get("artifact_format"),
        "physical_artifact_verified": True,
    }


def derive_calibration_scope(feature_dataset_path: Path) -> dict[str, Any]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCCalibrationScoringAuthorizationError(
            "Task-10 feature dataset SHA-256 mismatch"
        )

    seen: set[str] = set()
    calibration_rows: list[dict[str, Any]] = []
    incomplete_calibration = 0
    total_rows = 0

    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCCalibrationScoringAuthorizationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_FEATURE_ROW_FIELDS:
                raise StageCCalibrationScoringAuthorizationError(
                    "feature row closed-schema mismatch"
                )

            sid = row["sample_id"]
            partition = row["partition"]
            vector = row["feature_vector"]
            incomplete = row["collection_incomplete"]
            dropped = row["dropped_events"]
            history_truncated = row["history_truncated"]

            if not isinstance(sid, str) or not sid or sid in seen:
                raise StageCCalibrationScoringAuthorizationError(
                    "duplicate/invalid feature sample_id"
                )
            if partition not in {"train", "selection", "calibration"}:
                raise StageCCalibrationScoringAuthorizationError(
                    "feature partition invalid"
                )
            if not isinstance(vector, list) or len(vector) != EXPECTED_FEATURE_COUNT:
                raise StageCCalibrationScoringAuthorizationError(
                    "feature vector shape changed"
                )
            if any(
                type(value) not in (int, float) or not math.isfinite(value)
                for value in vector
            ):
                raise StageCCalibrationScoringAuthorizationError(
                    "feature vector contains non-finite value"
                )
            if type(incomplete) is not bool or type(history_truncated) is not bool:
                raise StageCCalibrationScoringAuthorizationError(
                    "collection flag invalid"
                )
            if type(dropped) is not int or dropped < 0:
                raise StageCCalibrationScoringAuthorizationError(
                    "collection dropped-event counter invalid"
                )

            seen.add(sid)
            total_rows += 1

            if partition != "calibration":
                continue
            if incomplete:
                incomplete_calibration += 1
                continue

            # Intentionally exclude label from the authorized calibration
            # scoring input. It remains locked for a later gate.
            calibration_rows.append({
                "sample_id": sid,
                "feature_vector": vector,
            })

    if total_rows != EXPECTED_TOTAL_ROWS:
        raise StageCCalibrationScoringAuthorizationError(
            "feature dataset row count changed"
        )
    if len(calibration_rows) != EXPECTED_COMPLETE_CALIBRATION_COUNT:
        raise StageCCalibrationScoringAuthorizationError(
            "complete calibration sample count changed"
        )
    if incomplete_calibration != EXPECTED_INCOMPLETE_CALIBRATION_COUNT:
        raise StageCCalibrationScoringAuthorizationError(
            "incomplete calibration sample count changed"
        )

    calibration_rows.sort(key=lambda row: row["sample_id"])
    sample_ids = [row["sample_id"] for row in calibration_rows]

    return {
        "authorized_partition": "calibration",
        "authorized_sample_count": len(calibration_rows),
        "authorized_sample_set_sha256": canonical_hash(sample_ids),
        "authorized_feature_matrix_sha256": canonical_hash(calibration_rows),
        "feature_count": EXPECTED_FEATURE_COUNT,
        "row_order": "SAMPLE_ID_ASCENDING",
        "model_observable_fields": ["feature_vector"],
        "join_only_fields": ["sample_id"],
        "calibration_label_access_authorized": False,
        "collection_incomplete_rows_authorized": False,
        "excluded_collection_incomplete_count": incomplete_calibration,
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_calibration_scoring_authorization.py",
        "ml/evaluation/authorize_stage_c_calibration_scoring.py",
        "ml/evaluation/stage_c_candidate_selection.py",
        "ml/training/stage_c_candidate_training.py",
        "ml/data/stage_c_development_feature_extraction.py",
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
            raise StageCCalibrationScoringAuthorizationError(
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
        raise StageCCalibrationScoringAuthorizationError(
            "Task-19 and bound calibration files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCCalibrationScoringAuthorizationError(
            "Task-19/bound calibration files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task19_module_sha256": sha256_file(repo_root / paths[0]),
        "task19_cli_sha256": sha256_file(repo_root / paths[1]),
        "task18_module_sha256": sha256_file(repo_root / paths[2]),
        "task12_module_sha256": sha256_file(repo_root / paths[3]),
        "task10_module_sha256": sha256_file(repo_root / paths[4]),
    }


def issue_calibration_scoring_authorization(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    selection_record_path: Path,
    training_manifest_path: Path,
    candidate_root: Path,
) -> dict[str, Any]:
    selection = load_json(selection_record_path)
    training = load_json(training_manifest_path)

    selected_from_task18 = validate_task18_selection(selection)
    selected_artifact = validate_training_manifest_and_selected_artifact(
        training,
        candidate_root=candidate_root,
    )
    if (
        selected_from_task18.get("artifact_sha256")
        != selected_artifact["artifact_sha256"]
    ):
        raise StageCCalibrationScoringAuthorizationError(
            "Task-18/Task-12 selected artifact identity mismatch"
        )

    scope = derive_calibration_scope(feature_dataset_path)
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
        "calibration_scoring_scope": scope,
        "selected_candidate_artifact": selected_artifact,
        "identity_bindings": {
            "task18_selection_record_sha256": (
                EXPECTED_TASK18_SELECTION_RECORD_SHA256
            ),
            "task17_authorization_sha256": EXPECTED_TASK17_AUTHORIZATION_SHA256,
            "task12_training_manifest_sha256": (
                EXPECTED_TASK12_TRAINING_MANIFEST_SHA256
            ),
            "candidate_artifact_set_sha256": (
                EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256
            ),
            "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
            **git,
        },
        "prohibitions": {
            "model_refit": True,
            "score_non_selected_candidate": True,
            "calibration_label_read": True,
            "calibration_metric_computation": True,
            "calibration_fitting": True,
            "threshold_selection": True,
            "threshold_freeze": True,
            "reuse_selection_diagnostic_threshold": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "SCORE_STAGE_C_SELECTED_CANDIDATE_ON_CALIBRATION_FEATURES_"
            "WITH_LABELS_LOCKED"
        ),
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
