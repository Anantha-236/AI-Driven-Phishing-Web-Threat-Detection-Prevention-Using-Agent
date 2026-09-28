"""Stage C Task 25 — authorize final-holdout acquisition after freeze.

This gate consumes the frozen Task-24 candidate+threshold operating point and
the original Stage-C acquisition/experiment contracts. It authorizes only the
pinned CompPhish v3 final-holdout acquisition and integrity/identity workflow.

Task 25 does not fetch metadata, download bytes, inspect model-relevant content,
extract evaluation features, score the model, compute metrics, perform error
analysis, deploy anything, or otherwise touch the final holdout.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-final-holdout-acquisition-authorization-1"

EXPECTED_TASK24_FREEZE_RECORD_SHA256 = "081a36b04e1f319081e84ab23172bd633d799877b58db27a33d80f8087b617ee"
EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256 = "25286bcee337d4731eda836f23cf3032c4b9ae0922a3742fa7a15251da5aa0eb"

EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_ARTIFACT_SHA256 = "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"
EXPECTED_THRESHOLD = 0.8637646437995518

EXPECTED_HOLDOUT_CANDIDATE_ID = "compphish-v3-2026"
EXPECTED_HOLDOUT_SOURCE_ID = "mendeley-fmbs4kp9wz-v3"
EXPECTED_HOLDOUT_DOI = "10.17632/fmbs4kp9wz.3"
EXPECTED_HOLDOUT_LICENSE = "CC BY 4.0"
EXPECTED_HOLDOUT_LANDING_PAGE = "https://data.mendeley.com/datasets/fmbs4kp9wz/3"
EXPECTED_HOLDOUT_COUNTS = {"legitimate": 8154, "phishing": 7204}
EXPECTED_HOLDOUT_COLLECTION_START = "2024-09-01"

EXPECTED_DEVELOPMENT_SOURCE_ID = "mendeley-n96ncsr5g4-v1"
EXPECTED_DEVELOPMENT_COLLECTION_END = "2021-10-31"

EXPECTED_ALLOWED_PRE_MODEL_USES = [
    "LICENSE_VERIFICATION",
    "FILE_INTEGRITY_VERIFICATION",
    "SCHEMA_VERIFICATION",
    "IDENTITY_INDEX_BUILD",
    "CONTAMINATION_AUDIT",
]
EXPECTED_PROHIBITED_PRE_FREEZE_USES = [
    "FEATURE_SELECTION",
    "MODEL_SELECTION",
    "CALIBRATION",
    "THRESHOLD_SELECTION",
    "MODEL_SCORING",
    "ERROR_ANALYSIS",
]


class StageCFinalHoldoutAcquisitionAuthorizationError(ValueError):
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
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
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
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"refusing to replace non-identical frozen Task-25 output: {path}"
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


def validate_task24_freeze(record: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-threshold-freeze-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "selected_candidate_artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "threshold_selection_authorized": True,
        "threshold_selection_performed": True,
        "threshold_selected": True,
        "threshold_frozen": True,
        "calibration_fitting_authorized": False,
        "final_holdout_touched": False,
        "threshold_freeze_record_sha256": EXPECTED_TASK24_FREEZE_RECORD_SHA256,
        "next_gate": (
            "ISSUE_STAGE_C_FINAL_HOLDOUT_SCORING_AUTHORIZATION_FOR_FROZEN_"
            "CANDIDATE_AND_THRESHOLD"
        ),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"Task-24 freeze guard mismatch: {key}"
            )
    if (
        hash_without(record, "threshold_freeze_record_sha256")
        != EXPECTED_TASK24_FREEZE_RECORD_SHA256
    ):
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "Task-24 canonical freeze-record hash mismatch"
        )

    point = record.get("frozen_operating_point")
    prohibitions = record.get("prohibitions")
    if not isinstance(point, Mapping) or not isinstance(prohibitions, Mapping):
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "Task-24 freeze sections missing"
        )

    checks = [
        (point.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID, "candidate id"),
        (point.get("artifact_sha256") == EXPECTED_SELECTED_ARTIFACT_SHA256, "artifact sha"),
        (point.get("threshold") == EXPECTED_THRESHOLD, "threshold"),
        (point.get("threshold_rule") == "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD", "threshold rule"),
        (
            point.get("candidate_threshold_pair_sha256")
            == EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
            "candidate-threshold pair",
        ),
        (prohibitions.get("model_refit") is True, "model-refit prohibition"),
        (prohibitions.get("artifact_substitution") is True, "artifact-substitution prohibition"),
        (prohibitions.get("calibration_fitting") is True, "calibration-fitting prohibition"),
        (prohibitions.get("threshold_reselection") is True, "threshold-reselection prohibition"),
        (prohibitions.get("threshold_change") is True, "threshold-change prohibition"),
        (prohibitions.get("deployment") is True, "deployment prohibition"),
        (prohibitions.get("final_holdout_access") is True, "pre-authorization holdout lock"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"Task-24 freeze changed: {name}"
            )
    return dict(point)


def validate_acquisition_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-dataset-acquisition-plan-1",
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "downloads_authorized": False,
        "source_independent": True,
        "next_gate": "VERIFY_REMOTE_FILES_AND_FREEZE_DOWNLOAD_MANIFESTS",
    }
    for key, value in expected.items():
        if plan.get(key) != value:
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"Task-3 acquisition-plan guard mismatch: {key}"
            )

    dev = plan.get("development")
    final = plan.get("final_holdout")
    temporal = plan.get("strict_temporal_order")
    if not all(isinstance(x, Mapping) for x in (dev, final, temporal)):
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "Task-3 acquisition-plan sections missing"
        )

    checks = [
        (dev.get("source_id") == EXPECTED_DEVELOPMENT_SOURCE_ID, "development source"),
        (final.get("candidate_id") == EXPECTED_HOLDOUT_CANDIDATE_ID, "holdout candidate"),
        (final.get("source_id") == EXPECTED_HOLDOUT_SOURCE_ID, "holdout source"),
        (final.get("doi") == EXPECTED_HOLDOUT_DOI, "holdout DOI"),
        (final.get("license") == EXPECTED_HOLDOUT_LICENSE, "holdout license"),
        (final.get("expected_class_counts") == EXPECTED_HOLDOUT_COUNTS, "holdout class counts"),
        (final.get("landing_page") == EXPECTED_HOLDOUT_LANDING_PAGE, "holdout landing page"),
        (final.get("acquisition_state") == "QUALIFIED_LOCKED_NOT_DOWNLOADED", "holdout acquisition state"),
        (
            final.get("allowed_uses_before_final_freeze")
            == EXPECTED_ALLOWED_PRE_MODEL_USES,
            "holdout allowed-use policy",
        ),
        (
            final.get("prohibited_uses_before_final_freeze")
            == EXPECTED_PROHIBITED_PRE_FREEZE_USES,
            "holdout prohibited-use policy",
        ),
        (temporal.get("development_end") == EXPECTED_DEVELOPMENT_COLLECTION_END, "development end"),
        (temporal.get("final_start") == EXPECTED_HOLDOUT_COLLECTION_START, "holdout start"),
        (temporal.get("satisfied") is True, "temporal-order requirement"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"Task-3 acquisition plan changed: {name}"
            )
    if dev.get("source_id") == final.get("source_id"):
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "development and final holdout are not source-independent"
        )
    return dict(final)


def validate_experiment_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-experiment-contract-1",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"experiment-contract guard mismatch: {key}"
            )

    holdout = contract.get("holdout_contract")
    development = contract.get("development_contract")
    if not isinstance(holdout, Mapping) or not isinstance(development, Mapping):
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "experiment contract sections missing"
        )

    checks = [
        (holdout.get("new_final_holdout_required") is True, "new holdout requirement"),
        (holdout.get("stage_b_final_test_samples_prohibited") is True, "Stage-B reuse prohibition"),
        (holdout.get("selection_use_prohibited") is True, "holdout selection prohibition"),
        (holdout.get("calibration_use_prohibited") is True, "holdout calibration prohibition"),
        (holdout.get("threshold_selection_use_prohibited") is True, "holdout threshold prohibition"),
        (holdout.get("minimum_legitimate_samples_for_zero_fp_wilson_resolution") == 381, "minimum legitimate count"),
        (holdout.get("strict_forward_preferred") is True, "strict-forward preference"),
        (holdout.get("independent_source_preferred") is True, "independent-source preference"),
        (
            development.get("test_locked_until_candidate_and_threshold_frozen")
            is True,
            "final-test lock contract",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
                f"experiment contract changed: {name}"
            )
    return {
        "experiment_contract_sha256": canonical_hash(contract),
        "minimum_legitimate_samples_for_zero_fp_wilson_resolution": 381,
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_final_holdout_acquisition_authorization.py",
        "ml/data/authorize_stage_c_final_holdout_acquisition.py",
        "ml/evaluation/stage_c_threshold_freeze.py",
        "ml/data/stage_c_dataset_qualification.py",
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
            raise StageCFinalHoldoutAcquisitionAuthorizationError(
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
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "Task-25 and bound protocol files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCFinalHoldoutAcquisitionAuthorizationError(
            "Task-25/bound protocol files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task25_module_sha256": sha256_file(repo_root / paths[0]),
        "task25_cli_sha256": sha256_file(repo_root / paths[1]),
        "task24_module_sha256": sha256_file(repo_root / paths[2]),
        "dataset_qualification_module_sha256": sha256_file(repo_root / paths[3]),
        "experiment_contract_file_sha256": sha256_file(repo_root / paths[4]),
    }


def issue_final_holdout_acquisition_authorization(
    *,
    repo_root: Path,
    threshold_freeze_record_path: Path,
    acquisition_plan_path: Path,
    experiment_contract_path: Path,
) -> dict[str, Any]:
    freeze_record = load_json(threshold_freeze_record_path)
    acquisition_plan = load_json(acquisition_plan_path)
    experiment_contract = load_json(experiment_contract_path)

    operating_point = validate_task24_freeze(freeze_record)
    final = validate_acquisition_plan(acquisition_plan)
    experiment = validate_experiment_contract(experiment_contract)
    git = _git_provenance(repo_root)

    holdout_identity = {
        "candidate_id": EXPECTED_HOLDOUT_CANDIDATE_ID,
        "source_id": EXPECTED_HOLDOUT_SOURCE_ID,
        "doi": EXPECTED_HOLDOUT_DOI,
        "license": EXPECTED_HOLDOUT_LICENSE,
        "expected_class_counts": EXPECTED_HOLDOUT_COUNTS,
        "collection_start": EXPECTED_HOLDOUT_COLLECTION_START,
    }

    authorization = {
        "schema_version": AUTH_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "threshold_frozen": True,
        "final_holdout_touched": False,
        "final_holdout_acquisition_authorized": True,
        "remote_inventory_authorized": True,
        "download_manifest_freeze_authorized": True,
        "final_holdout_download_authorized": True,
        "local_integrity_seal_authorized": True,
        "schema_verification_authorized": True,
        "identity_index_build_authorized": True,
        "contamination_audit_authorized": True,
        "final_holdout_feature_extraction_authorized": False,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_label_evaluation_authorized": False,
        "final_holdout_metrics_authorized": False,
        "final_holdout_error_analysis_authorized": False,
        "authorized_action": (
            "ACQUIRE_AND_SEAL_PINNED_COMPPHISH_V3_FINAL_HOLDOUT_WITHOUT_MODEL_ACCESS"
        ),
        "frozen_operating_point": {
            "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
            "artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
            "threshold": EXPECTED_THRESHOLD,
            "threshold_rule": operating_point["threshold_rule"],
            "candidate_threshold_pair_sha256": EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
        },
        "final_holdout_scope": {
            **holdout_identity,
            "landing_page": EXPECTED_HOLDOUT_LANDING_PAGE,
            "identity_sha256": canonical_hash(holdout_identity),
            "acquisition_state_before_task25": final["acquisition_state"],
            "source_independent_from_development": True,
            "strict_forward_from_primary_development": True,
        },
        "authorized_pre_scoring_operations": [
            "FETCH_PINNED_REMOTE_METADATA",
            "FREEZE_REMOTE_FILE_INVENTORY",
            "FREEZE_DOWNLOAD_MANIFEST",
            "DOWNLOAD_BYTES_FROM_FROZEN_MANIFEST",
            "VERIFY_ARCHIVE_SHA256_AND_SIZE",
            "VERIFY_ARCHIVE_CONTAINER_INTEGRITY",
            "VERIFY_SCHEMA_WITHOUT_MODEL_SCORING",
            "BUILD_PRIVACY_REDUCED_IDENTITY_INDEX",
            "AUDIT_CONTAMINATION_AGAINST_DEVELOPMENT_AND_CONSUMED_STAGE_B_TEST",
        ],
        "identity_bindings": {
            "task24_threshold_freeze_record_sha256": EXPECTED_TASK24_FREEZE_RECORD_SHA256,
            "candidate_threshold_pair_sha256": EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
            "acquisition_plan_sha256": canonical_hash(acquisition_plan),
            **experiment,
            **git,
        },
        "prohibitions": {
            "feature_selection": True,
            "model_selection": True,
            "model_refit": True,
            "calibration": True,
            "threshold_selection": True,
            "threshold_change": True,
            "model_scoring": True,
            "metric_computation": True,
            "error_analysis": True,
            "deployment": True,
            "use_stage_b_consumed_final_test": True,
        },
        "next_gate": (
            "FREEZE_STAGE_C_FINAL_HOLDOUT_REMOTE_INVENTORY_AND_DOWNLOAD_MANIFEST"
        ),
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
