"""Stage C Task 11 — fail-closed model-training authorization.

This module does not train, select, calibrate, threshold, score, or deploy a
model. It authorizes parameter fitting only on collection-complete TRAIN rows.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-model-training-authorization-1"

EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"
EXPECTED_AUDIT_FILE_SHA256 = "e1d7dbb50a18bd7d4f85e7179e01ee3895b43537e61364b9398171aca2fd6652"
EXPECTED_READINESS_FILE_SHA256 = "45053d2040367fcfbd9eb00c791c81694c5c5f43579bfbc07ae07cf0a1ae1e9b"
EXPECTED_AUDIT_SHA256 = "a895874eedf02fcfd8e097e2ef386b2c6ff839f4c024681d0ea8f34c7aee2c84"
EXPECTED_READINESS_SHA256 = "46e919b2a1e09ee3f1805fcb58b319726b313a07ca200846762371ea794fc21d"
EXPECTED_FEATURE_ROW_SET_SHA256 = "d18aa86db81f056d522057b7bdc0ac7d43e7ee40239c1bd283d52edd11d117e2"
EXPECTED_CHECKPOINT_SET_SHA256 = "c40bfd283e4ca32518995ba69c6278b677bb644332a66014bd1be96fdaf9fa04"
EXPECTED_TASK10_STATE_SHA256 = "72bf45aec6c7cafbdaab7918e5ea516466cf39b08ccb91b4c0f848f0a377f58f"
EXPECTED_TASK9_AUTHORIZATION_SHA256 = "b83f7038a98704465b4097b7f0b54d3ae62f9d72caa5ec31eb82b4d031bda27b"
EXPECTED_SPLIT_MANIFEST_SHA256 = "b36708d960bc21f3c325bc5ac9e5a25bb0627b244c378ac643914df38d1365b9"
EXPECTED_FEATURE_CONTRACT_SHA256 = "2ee75478749e347f84e97b6fb8911a5b961019be6e282b28792a3e70b0c95a6b"
EXPECTED_EXTRACTOR_SOURCE_SHA256 = "6378a55363653da12a101f1cdae33a8b53313d20aee8db95e1deb21fe1e57d74"
EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256 = "9217d4100c711e038229e2c1de2679f0452969067c098c819e1e8b851dabfb16"

EXPECTED_TOTAL_ROWS = 73777
EXPECTED_MODELING_COUNT = 73770
EXPECTED_MODELING_SHA256 = "451712b4b9f2584f228b4547fd70875f1e58c2888ff4e8352eb1f7544168a98b"
EXPECTED_INCOMPLETE_COUNT = 7
EXPECTED_INCOMPLETE_SHA256 = "90fd6c6df7a8c82cee7de8413239fbb36a21a19bca7df35e5d7f18ccedb26682"
EXPECTED_FEATURE_COUNT = 27
PARTITIONS = ("train", "selection", "calibration")

EXPECTED_PARTITION_COUNTS = {
    "train": {"total": 45750, "legitimate": 22702, "phishing": 23048},
    "selection": {"total": 20712, "legitimate": 19643, "phishing": 1069},
    "calibration": {"total": 7315, "legitimate": 5585, "phishing": 1730},
}
EXPECTED_MODELING_PARTITION_COUNTS = {
    "train": {"total": 45746, "legitimate": 22699, "phishing": 23047},
    "selection": {"total": 20710, "legitimate": 19641, "phishing": 1069},
    "calibration": {"total": 7314, "legitimate": 5584, "phishing": 1730},
}
EXPECTED_INCOMPLETE_PARTITION_COUNTS = {
    "train": {"total": 4, "legitimate": 3, "phishing": 1},
    "selection": {"total": 2, "legitimate": 2, "phishing": 0},
    "calibration": {"total": 1, "legitimate": 1, "phishing": 0},
}


class StageCTrainingAuthorizationError(ValueError):
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
        raise StageCTrainingAuthorizationError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCTrainingAuthorizationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCTrainingAuthorizationError(f"JSON root must be an object: {path}")
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCTrainingAuthorizationError(
                f"refusing to replace non-identical frozen Task-11 output: {path}"
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


def _require_exact(source: Mapping[str, Any], expected: Mapping[str, Any], name: str) -> None:
    for key, value in expected.items():
        if source.get(key) != value:
            raise StageCTrainingAuthorizationError(f"{name} guard mismatch: {key}")


def _counts(counters: Mapping[str, Counter[int]]) -> dict[str, dict[str, int]]:
    return {
        p: {
            "total": counters[p][0] + counters[p][1],
            "legitimate": counters[p][0],
            "phishing": counters[p][1],
        }
        for p in PARTITIONS
    }


def _validate_task9(auth: Mapping[str, Any]) -> None:
    _require_exact(auth, {
        "schema_version": "stage-c-feature-extraction-authorization-2",
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": True,
        "model_training_authorized": False,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK9_AUTHORIZATION_SHA256,
    }, "Task-9 authorization")
    if hash_without(auth, "authorization_sha256") != EXPECTED_TASK9_AUTHORIZATION_SHA256:
        raise StageCTrainingAuthorizationError("Task-9 canonical hash does not reproduce")
    scope = auth.get("scope")
    feature = auth.get("feature_contract")
    if not isinstance(scope, Mapping) or not isinstance(feature, Mapping):
        raise StageCTrainingAuthorizationError("Task-9 scope/feature contract missing")
    if scope.get("authorized_sample_count") != EXPECTED_TOTAL_ROWS:
        raise StageCTrainingAuthorizationError("Task-9 authorized count changed")
    if scope.get("authorized_sample_set_sha256") != EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256:
        raise StageCTrainingAuthorizationError("Task-9 authorized identity changed")
    if feature.get("feature_count") != EXPECTED_FEATURE_COUNT:
        raise StageCTrainingAuthorizationError("Task-9 feature count changed")
    if feature.get("feature_contract_sha256") != EXPECTED_FEATURE_CONTRACT_SHA256:
        raise StageCTrainingAuthorizationError("Task-9 feature contract changed")
    if feature.get("extractor_source_sha256") != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCTrainingAuthorizationError("Task-9 extractor identity changed")


def _validate_split(split: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    _require_exact(split, {
        "schema_version": "stage-c-development-split-manifest-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": False,
        "model_training_authorized": False,
        "final_holdout_touched": False,
        "manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
    }, "Task-8 split")
    if hash_without(split, "manifest_sha256") != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise StageCTrainingAuthorizationError("Task-8 split hash does not reproduce")
    if split.get("partition_counts") != EXPECTED_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-8 partition counts changed")

    partitions = split.get("partitions")
    if not isinstance(partitions, Mapping) or set(partitions) != set(PARTITIONS):
        raise StageCTrainingAuthorizationError("Task-8 partitions missing")
    membership: dict[str, dict[str, Any]] = {}
    for part in PARTITIONS:
        rows = partitions.get(part)
        if not isinstance(rows, list):
            raise StageCTrainingAuthorizationError(f"Task-8 {part} rows missing")
        for row in rows:
            if not isinstance(row, Mapping):
                raise StageCTrainingAuthorizationError("Task-8 row invalid")
            sid, label = row.get("sample_id"), row.get("label")
            if not isinstance(sid, str) or not sid or label not in (0, 1):
                raise StageCTrainingAuthorizationError("Task-8 identity/label invalid")
            if sid in membership:
                raise StageCTrainingAuthorizationError("Task-8 partition overlap")
            membership[sid] = {"partition": part, "label": int(label)}
    if len(membership) != EXPECTED_TOTAL_ROWS:
        raise StageCTrainingAuthorizationError("Task-8 membership count changed")
    return membership


def _validate_experiment(contract: Mapping[str, Any]) -> str:
    _require_exact(contract, {
        "schema_version": "stage-c-experiment-contract-1",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
    }, "Stage-C experiment contract")
    objective = contract.get("objective")
    holdout = contract.get("holdout_contract")
    development = contract.get("development_contract")
    if not all(isinstance(x, Mapping) for x in (objective, holdout, development)):
        raise StageCTrainingAuthorizationError("experiment contract sections missing")
    guards = [
        (objective.get("primary_metric") == "false_positive_rate", "primary metric"),
        (objective.get("primary_fpr_cap") == 0.01, "FPR cap"),
        (objective.get("confidence_level") == 0.95, "confidence level"),
        (objective.get("require_observed_fpr_at_or_below_cap") is True, "observed FPR guard"),
        (objective.get("require_wilson_upper_at_or_below_cap") is True, "Wilson guard"),
        (holdout.get("selection_use_prohibited") is True, "holdout selection guard"),
        (holdout.get("calibration_use_prohibited") is True, "holdout calibration guard"),
        (holdout.get("threshold_selection_use_prohibited") is True, "holdout threshold guard"),
        (development.get("test_locked_until_candidate_and_threshold_frozen") is True, "test lock"),
        (development.get("allowed_partitions") == ["train", "selection", "calibration"], "development partitions"),
    ]
    for ok, name in guards:
        if not ok:
            raise StageCTrainingAuthorizationError(f"experiment contract changed: {name}")
    return canonical_hash(contract)


def _validate_task10(
    audit: Mapping[str, Any],
    readiness: Mapping[str, Any],
    audit_path: Path,
    readiness_path: Path,
) -> None:
    if sha256_file(audit_path) != EXPECTED_AUDIT_FILE_SHA256:
        raise StageCTrainingAuthorizationError("Task-10 audit file SHA-256 mismatch")
    if sha256_file(readiness_path) != EXPECTED_READINESS_FILE_SHA256:
        raise StageCTrainingAuthorizationError("Task-10 readiness file SHA-256 mismatch")

    _require_exact(audit, {
        "schema_version": "stage-c-development-feature-audit-2",
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": True,
        "model_training_authorized": False,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK9_AUTHORIZATION_SHA256,
        "state_sha256": EXPECTED_TASK10_STATE_SHA256,
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
        "feature_count": EXPECTED_FEATURE_COUNT,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "feature_row_set_sha256": EXPECTED_FEATURE_ROW_SET_SHA256,
        "checkpoint_set_sha256": EXPECTED_CHECKPOINT_SET_SHA256,
        "total_rows": EXPECTED_TOTAL_ROWS,
        "collection_incomplete_count": EXPECTED_INCOMPLETE_COUNT,
        "collection_incomplete_sample_set_sha256": EXPECTED_INCOMPLETE_SHA256,
        "modeling_candidate_policy": "COLLECTION_COMPLETE_ONLY",
        "modeling_candidate_sample_count": EXPECTED_MODELING_COUNT,
        "modeling_candidate_sample_set_sha256": EXPECTED_MODELING_SHA256,
        "audit_sha256": EXPECTED_AUDIT_SHA256,
    }, "Task-10 audit")
    if hash_without(audit, "audit_sha256") != EXPECTED_AUDIT_SHA256:
        raise StageCTrainingAuthorizationError("Task-10 audit canonical hash mismatch")
    if audit.get("partition_counts") != EXPECTED_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-10 full counts changed")
    if audit.get("modeling_candidate_partition_counts") != EXPECTED_MODELING_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-10 modeling counts changed")
    if audit.get("collection_incomplete_partition_counts") != EXPECTED_INCOMPLETE_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-10 incomplete counts changed")
    checks = audit.get("audits")
    if not isinstance(checks, Mapping) or not checks or not all(x is True for x in checks.values()):
        raise StageCTrainingAuthorizationError("Task-10 audits are not all PASS")

    _require_exact(readiness, {
        "schema_version": "stage-c-development-feature-readiness-2",
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_complete": True,
        "feature_extraction_authorized": True,
        "model_training_authorized": False,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "feature_audit_sha256": EXPECTED_AUDIT_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "feature_row_set_sha256": EXPECTED_FEATURE_ROW_SET_SHA256,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "authorized_sample_count": EXPECTED_TOTAL_ROWS,
        "collection_incomplete_count": EXPECTED_INCOMPLETE_COUNT,
        "collection_incomplete_sample_set_sha256": EXPECTED_INCOMPLETE_SHA256,
        "modeling_candidate_policy": "COLLECTION_COMPLETE_ONLY",
        "modeling_candidate_sample_count": EXPECTED_MODELING_COUNT,
        "modeling_candidate_sample_set_sha256": EXPECTED_MODELING_SHA256,
        "all_required_post_extraction_audits_passed": True,
        "next_gate": "ISSUE_STAGE_C_MODEL_TRAINING_AUTHORIZATION_FOR_COMPLETE_COLLECTION_SUBSET",
        "readiness_sha256": EXPECTED_READINESS_SHA256,
    }, "Task-10 readiness")
    if hash_without(readiness, "readiness_sha256") != EXPECTED_READINESS_SHA256:
        raise StageCTrainingAuthorizationError("Task-10 readiness canonical hash mismatch")
    if readiness.get("partition_counts") != EXPECTED_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-10 readiness full counts changed")
    if readiness.get("modeling_candidate_partition_counts") != EXPECTED_MODELING_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-10 readiness modeling counts changed")
    if readiness.get("collection_incomplete_partition_counts") != EXPECTED_INCOMPLETE_PARTITION_COUNTS:
        raise StageCTrainingAuthorizationError("Task-10 readiness incomplete counts changed")


def derive_scope(
    rows: list[Mapping[str, Any]],
    split_membership: Mapping[str, Mapping[str, Any]],
    *,
    enforce_frozen: bool = True,
) -> dict[str, Any]:
    seen: set[str] = set()
    complete_ids: list[str] = []
    incomplete_ids: list[str] = []
    complete_by_part: dict[str, list[str]] = {p: [] for p in PARTITIONS}
    full_counts = {p: Counter() for p in PARTITIONS}
    complete_counts = {p: Counter() for p in PARTITIONS}
    incomplete_counts = {p: Counter() for p in PARTITIONS}

    expected_fields = {
        "sample_id", "partition", "label", "feature_vector",
        "collection_incomplete", "dropped_events", "delivery_errors",
        "history_truncated",
    }
    for row in rows:
        if set(row) != expected_fields:
            raise StageCTrainingAuthorizationError("feature row closed-schema mismatch")
        sid, part, label = row["sample_id"], row["partition"], row["label"]
        vector = row["feature_vector"]
        incomplete = row["collection_incomplete"]
        dropped = row["dropped_events"]
        delivery = row["delivery_errors"]
        history = row["history_truncated"]

        if not isinstance(sid, str) or not sid or sid in seen:
            raise StageCTrainingAuthorizationError("duplicate/invalid sample_id")
        if part not in PARTITIONS or label not in (0, 1):
            raise StageCTrainingAuthorizationError("partition/label invalid")
        if not isinstance(vector, list) or len(vector) != EXPECTED_FEATURE_COUNT:
            raise StageCTrainingAuthorizationError("feature vector shape changed")
        if any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
            raise StageCTrainingAuthorizationError("feature vector contains non-finite value")
        if type(incomplete) is not bool or type(history) is not bool:
            raise StageCTrainingAuthorizationError("collection flag invalid")
        if type(dropped) is not int or dropped < 0 or type(delivery) is not int or delivery < 0:
            raise StageCTrainingAuthorizationError("collection counter invalid")
        if incomplete is not (dropped > 0 or history):
            raise StageCTrainingAuthorizationError("collection-loss metadata mismatch")

        expected = split_membership.get(sid)
        if not isinstance(expected, Mapping):
            raise StageCTrainingAuthorizationError("sample absent from Task-8 split")
        if expected.get("partition") != part or expected.get("label") != label:
            raise StageCTrainingAuthorizationError("feature/split membership mismatch")

        seen.add(sid)
        full_counts[part][label] += 1
        if incomplete:
            incomplete_ids.append(sid)
            incomplete_counts[part][label] += 1
        else:
            complete_ids.append(sid)
            complete_by_part[part].append(sid)
            complete_counts[part][label] += 1

    if seen != set(split_membership):
        raise StageCTrainingAuthorizationError("feature/split sample coverage mismatch")

    result = {
        "full_partition_counts": _counts(full_counts),
        "modeling_candidate_sample_count": len(complete_ids),
        "modeling_candidate_sample_set_sha256": canonical_hash(sorted(complete_ids)),
        "modeling_candidate_partition_counts": _counts(complete_counts),
        "modeling_candidate_partition_sample_set_sha256": {
            p: canonical_hash(sorted(complete_by_part[p])) for p in PARTITIONS
        },
        "collection_incomplete_count": len(incomplete_ids),
        "collection_incomplete_sample_set_sha256": canonical_hash(sorted(incomplete_ids)),
        "collection_incomplete_partition_counts": _counts(incomplete_counts),
    }
    result["authorized_train_sample_count"] = result[
        "modeling_candidate_partition_counts"
    ]["train"]["total"]
    result["authorized_train_sample_set_sha256"] = result[
        "modeling_candidate_partition_sample_set_sha256"
    ]["train"]
    result["authorized_train_label_counts"] = {
        "legitimate": result["modeling_candidate_partition_counts"]["train"]["legitimate"],
        "phishing": result["modeling_candidate_partition_counts"]["train"]["phishing"],
    }

    if enforce_frozen:
        if result["full_partition_counts"] != EXPECTED_PARTITION_COUNTS:
            raise StageCTrainingAuthorizationError("full partition counts changed")
        if result["modeling_candidate_partition_counts"] != EXPECTED_MODELING_PARTITION_COUNTS:
            raise StageCTrainingAuthorizationError("modeling partition counts changed")
        if result["collection_incomplete_partition_counts"] != EXPECTED_INCOMPLETE_PARTITION_COUNTS:
            raise StageCTrainingAuthorizationError("incomplete partition counts changed")
        if result["modeling_candidate_sample_count"] != EXPECTED_MODELING_COUNT:
            raise StageCTrainingAuthorizationError("modeling sample count changed")
        if result["modeling_candidate_sample_set_sha256"] != EXPECTED_MODELING_SHA256:
            raise StageCTrainingAuthorizationError("modeling sample identity changed")
        if result["collection_incomplete_count"] != EXPECTED_INCOMPLETE_COUNT:
            raise StageCTrainingAuthorizationError("incomplete sample count changed")
        if result["collection_incomplete_sample_set_sha256"] != EXPECTED_INCOMPLETE_SHA256:
            raise StageCTrainingAuthorizationError("incomplete sample identity changed")
    return result


def scan_feature_dataset(
    feature_dataset_path: Path,
    split_membership: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCTrainingAuthorizationError("Task-10 feature dataset SHA-256 mismatch")
    rows: list[Mapping[str, Any]] = []
    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCTrainingAuthorizationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping):
                raise StageCTrainingAuthorizationError("feature JSONL row is not an object")
            rows.append(row)
    if len(rows) != EXPECTED_TOTAL_ROWS:
        raise StageCTrainingAuthorizationError("Task-10 feature row count changed")
    return derive_scope(rows, split_membership, enforce_frozen=True)


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_model_training_authorization.py",
        "ml/data/authorize_stage_c_model_training.py",
        "ml/data/stage_c_development_feature_extraction.py",
        "ml/data/stage_c_feature_extraction_authorization_v2.py",
        "ml/data/manifests/stage-c-experiment-contract-v1.json",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            capture_output=True, text=True, encoding="utf-8", check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCTrainingAuthorizationError("invalid Git HEAD")
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
        raise StageCTrainingAuthorizationError(
            "Task-11 and bound protocol files must be committed"
        ) from exc
    if dirty != 0:
        raise StageCTrainingAuthorizationError(
            "Task-11/bound protocol files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task11_module_sha256": sha256_file(repo_root / paths[0]),
        "task11_cli_sha256": sha256_file(repo_root / paths[1]),
        "task10_module_sha256": sha256_file(repo_root / paths[2]),
        "task9_v2_module_sha256": sha256_file(repo_root / paths[3]),
        "experiment_contract_file_sha256": sha256_file(repo_root / paths[4]),
    }


def issue_model_training_authorization(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    feature_audit_path: Path,
    feature_readiness_path: Path,
    split_manifest_path: Path,
    task9_authorization_path: Path,
    experiment_contract_path: Path,
) -> dict[str, Any]:
    audit = load_json(feature_audit_path)
    readiness = load_json(feature_readiness_path)
    split = load_json(split_manifest_path)
    task9 = load_json(task9_authorization_path)
    experiment = load_json(experiment_contract_path)

    _validate_task9(task9)
    membership = _validate_split(split)
    experiment_hash = _validate_experiment(experiment)
    _validate_task10(audit, readiness, feature_audit_path, feature_readiness_path)
    scope = scan_feature_dataset(feature_dataset_path, membership)
    git = _git_provenance(repo_root)

    authorization = {
        "schema_version": AUTH_SCHEMA,
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
        "training_scope": {
            "authorized_partition": "train",
            "authorized_sample_count": scope["authorized_train_sample_count"],
            "authorized_sample_set_sha256": scope["authorized_train_sample_set_sha256"],
            "authorized_label_counts": scope["authorized_train_label_counts"],
            "feature_count": EXPECTED_FEATURE_COUNT,
            "model_observable_fields": ["feature_vector"],
            "supervision_metadata_fields": ["label"],
            "join_only_fields": ["sample_id"],
            "collection_incomplete_rows_authorized": False,
            "selection_partition_use_for_fitting_authorized": False,
            "calibration_partition_use_for_fitting_authorized": False,
            "threshold_selection_authorized": False,
            "final_holdout_authorized": False,
        },
        "modeling_universe": {
            "policy": "COLLECTION_COMPLETE_ONLY",
            "sample_count": scope["modeling_candidate_sample_count"],
            "sample_set_sha256": scope["modeling_candidate_sample_set_sha256"],
            "partition_counts": scope["modeling_candidate_partition_counts"],
            "partition_sample_set_sha256": scope[
                "modeling_candidate_partition_sample_set_sha256"
            ],
        },
        "excluded_collection_incomplete": {
            "sample_count": scope["collection_incomplete_count"],
            "sample_set_sha256": scope["collection_incomplete_sample_set_sha256"],
            "partition_counts": scope["collection_incomplete_partition_counts"],
            "model_fitting_authorized": False,
        },
        "experiment_constraints": {
            "primary_metric": "false_positive_rate",
            "primary_fpr_cap": 0.01,
            "confidence_level": 0.95,
            "require_observed_fpr_at_or_below_cap": True,
            "require_wilson_upper_at_or_below_cap": True,
            "secondary_metric": "recall",
            "selection_partition_reserved": True,
            "calibration_partition_reserved": True,
            "final_holdout_locked": True,
            "stage_b_final_test_reuse_prohibited": True,
        },
        "identity_bindings": {
            "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
            "feature_row_set_sha256": EXPECTED_FEATURE_ROW_SET_SHA256,
            "feature_audit_sha256": EXPECTED_AUDIT_SHA256,
            "feature_audit_file_sha256": EXPECTED_AUDIT_FILE_SHA256,
            "feature_readiness_sha256": EXPECTED_READINESS_SHA256,
            "feature_readiness_file_sha256": EXPECTED_READINESS_FILE_SHA256,
            "checkpoint_set_sha256": EXPECTED_CHECKPOINT_SET_SHA256,
            "task10_state_sha256": EXPECTED_TASK10_STATE_SHA256,
            "task9_feature_authorization_sha256": EXPECTED_TASK9_AUTHORIZATION_SHA256,
            "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
            "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
            "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
            "experiment_contract_sha256": experiment_hash,
            **git,
        },
        "prohibitions": {
            "selection_labels_for_training": True,
            "calibration_labels_for_training": True,
            "threshold_selection_during_training": True,
            "model_scoring_during_training": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": "TRAIN_STAGE_C_CANDIDATE_MODELS_ON_AUTHORIZED_TRAIN_SUBSET",
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
