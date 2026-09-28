"""Stage C Task 24 — freeze the authorized candidate+threshold pair.

Consumes the Task-23 threshold-selection authorization and the frozen Task-18
candidate-selection record. It validates both identities, then freezes one
immutable candidate/artifact/threshold operating point.

Task 24 does not load or execute the model, recompute calibration metrics,
rescore data, refit anything, deploy anything, or access the final holdout.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

FREEZE_SCHEMA = "stage-c-threshold-freeze-1"

EXPECTED_TASK23_AUTHORIZATION_SHA256 = "81882cba37003f9e5907e93daae9ba02040ba027af718dd9bf57d1e23c302031"
EXPECTED_TASK23_THRESHOLD_EVIDENCE_SHA256 = "1e7387f09bae65e99f9a12d1d263ee92ff77e1afc7bd8bb92ae38d86fb8ac5d5"
EXPECTED_TASK22_EVALUATION_REPORT_SHA256 = "ea3de4d936246a5d7ead22851e0485cede762a63e417e5e583ab43617b167499"
EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256 = "b9e09ba9911adcba1072194ec7c7242b3fa9b34ecca19fa72efb21468ad78d6b"

EXPECTED_TASK18_SELECTION_RECORD_SHA256 = "dffd5498523326c3272d32f50662a68f0671a6a51424bf8ebc2f75382eec0a10"
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_CANDIDATE_FAMILY = "linear"
EXPECTED_SELECTED_ARTIFACT_SHA256 = "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"

EXPECTED_THRESHOLD = 0.8637646437995518
EXPECTED_THRESHOLD_POINT = {
    "diagnostic_only": True,
    "fn": 1420,
    "fp": 36,
    "observed_fpr": 0.0064469914040114614,
    "precision": 0.8959537572254336,
    "primary_constraint_satisfied": True,
    "recall": 0.1791907514450867,
    "threshold": EXPECTED_THRESHOLD,
    "threshold_frozen": False,
    "threshold_is_above_max_score_sentinel": False,
    "threshold_selected": False,
    "tn": 5548,
    "tp": 310,
    "wilson_upper_95": 0.00891200424846714,
}

EXPECTED_PRIMARY_FPR_CAP = 0.01


class StageCThresholdFreezeError(ValueError):
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
        raise StageCThresholdFreezeError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCThresholdFreezeError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCThresholdFreezeError(f"JSON root must be object: {path}")
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCThresholdFreezeError(
                f"refusing to replace non-identical frozen Task-24 output: {path}"
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


def _require_number(actual: Any, expected: float, field: str) -> None:
    if type(actual) not in (int, float) or not math.isfinite(actual):
        raise StageCThresholdFreezeError(f"invalid numeric field: {field}")
    if float(actual) != expected:
        raise StageCThresholdFreezeError(f"frozen numeric field changed: {field}")


def validate_task23_authorization(auth: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-threshold-selection-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "calibration_metrics_computed": True,
        "threshold_analysis_performed": True,
        "threshold_selection_authorized": True,
        "threshold_selection_performed": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "calibration_fitting_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "SELECT_AND_FREEZE_TASK22_DIAGNOSTIC_MAX_RECALL_COMPLIANT_THRESHOLD"
        ),
        "authorization_sha256": EXPECTED_TASK23_AUTHORIZATION_SHA256,
        "next_gate": "FREEZE_STAGE_C_AUTHORIZED_THRESHOLD",
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCThresholdFreezeError(
                f"Task-23 authorization guard mismatch: {key}"
            )

    if hash_without(auth, "authorization_sha256") != EXPECTED_TASK23_AUTHORIZATION_SHA256:
        raise StageCThresholdFreezeError(
            "Task-23 canonical authorization hash mismatch"
        )

    rule = auth.get("selection_rule")
    scope = auth.get("threshold_selection_scope")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(isinstance(x, Mapping) for x in (rule, scope, bindings, prohibitions)):
        raise StageCThresholdFreezeError(
            "Task-23 authorization sections missing"
        )

    checks = [
        (rule.get("source") == "TASK22_DIAGNOSTIC_MAX_RECALL_POINT_UNDER_PRIMARY_CONSTRAINT", "source"),
        (rule.get("threshold_rule") == "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD", "threshold rule"),
        (rule.get("require_non_sentinel_point") is True, "non-sentinel requirement"),
        (rule.get("require_primary_constraint_satisfied") is True, "constraint requirement"),
        (rule.get("observed_fpr_lte") == EXPECTED_PRIMARY_FPR_CAP, "observed FPR cap"),
        (rule.get("wilson_upper_95_lte") == EXPECTED_PRIMARY_FPR_CAP, "Wilson cap"),
        (rule.get("secondary_objective") == "MAXIMIZE_RECALL", "secondary objective"),
        (rule.get("selection_choice_count") == 1, "choice count"),
        (rule.get("implicit_alternative_thresholds_authorized") is False, "alternative-threshold lock"),
        (rule.get("recompute_threshold_sweep_authorized") is False, "sweep-recompute lock"),
        (scope.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID, "candidate"),
        (scope.get("authorized_threshold") == EXPECTED_THRESHOLD, "authorized threshold"),
        (scope.get("authorized_threshold_evidence_sha256") == EXPECTED_TASK23_THRESHOLD_EVIDENCE_SHA256, "threshold evidence"),
        (bindings.get("task22_evaluation_report_sha256") == EXPECTED_TASK22_EVALUATION_REPORT_SHA256, "Task-22 report binding"),
        (bindings.get("task22_threshold_analysis_sha256") == EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256, "Task-22 analysis binding"),
        (prohibitions.get("model_refit") is True, "model-refit prohibition"),
        (prohibitions.get("calibration_fitting") is True, "calibration-fitting prohibition"),
        (prohibitions.get("threshold_sweep_recomputation") is True, "threshold-sweep prohibition"),
        (prohibitions.get("select_different_threshold") is True, "different-threshold prohibition"),
        (prohibitions.get("select_sentinel_threshold") is True, "sentinel-threshold prohibition"),
        (prohibitions.get("deployment") is True, "deployment prohibition"),
        (prohibitions.get("final_holdout_access") is True, "holdout prohibition"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCThresholdFreezeError(
                f"Task-23 authorization changed: {name}"
            )

    point = scope.get("authorized_threshold_point")
    if not isinstance(point, Mapping):
        raise StageCThresholdFreezeError("Task-23 authorized threshold point missing")

    for field in ("threshold", "observed_fpr", "wilson_upper_95", "recall", "precision"):
        _require_number(point.get(field), EXPECTED_THRESHOLD_POINT[field], field)
    for field in ("tp", "fp", "tn", "fn"):
        if point.get(field) != EXPECTED_THRESHOLD_POINT[field]:
            raise StageCThresholdFreezeError(
                f"Task-23 threshold count changed: {field}"
            )
    for field in (
        "diagnostic_only",
        "primary_constraint_satisfied",
        "threshold_frozen",
        "threshold_is_above_max_score_sentinel",
        "threshold_selected",
    ):
        if point.get(field) is not EXPECTED_THRESHOLD_POINT[field]:
            raise StageCThresholdFreezeError(
                f"Task-23 threshold flag changed: {field}"
            )

    frozen_evidence = {
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
        "diagnostic_point": dict(point),
        "task22_threshold_analysis_sha256": EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256,
    }
    if canonical_hash(frozen_evidence) != EXPECTED_TASK23_THRESHOLD_EVIDENCE_SHA256:
        raise StageCThresholdFreezeError(
            "Task-23 threshold-evidence canonical hash mismatch"
        )

    return dict(point)


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
            raise StageCThresholdFreezeError(
                f"Task-18 selection guard mismatch: {key}"
            )
    if (
        hash_without(record, "selection_record_sha256")
        != EXPECTED_TASK18_SELECTION_RECORD_SHA256
    ):
        raise StageCThresholdFreezeError(
            "Task-18 canonical selection-record hash mismatch"
        )

    artifact = record.get("selected_candidate_artifact")
    result = record.get("selection_result")
    if not isinstance(artifact, Mapping) or not isinstance(result, Mapping):
        raise StageCThresholdFreezeError(
            "Task-18 selected artifact/result missing"
        )
    checks = [
        (artifact.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID, "artifact candidate"),
        (artifact.get("family") == EXPECTED_SELECTED_CANDIDATE_FAMILY, "artifact family"),
        (artifact.get("artifact_sha256") == EXPECTED_SELECTED_ARTIFACT_SHA256, "artifact SHA"),
        (artifact.get("physical_artifact_verified") is True, "artifact physical verification"),
        (result.get("primary_constraint_feasible") is True, "candidate feasibility"),
        (result.get("selection_diagnostic_threshold_frozen") is False, "selection diagnostic threshold state"),
        (result.get("selection_diagnostic_threshold_authorized_for_calibration") is False, "selection diagnostic threshold carryover"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCThresholdFreezeError(
                f"Task-18 selected candidate changed: {name}"
            )
    return dict(artifact)


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_threshold_freeze.py",
        "ml/evaluation/freeze_stage_c_threshold.py",
        "ml/evaluation/stage_c_threshold_selection_authorization.py",
        "ml/evaluation/stage_c_candidate_selection.py",
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
            raise StageCThresholdFreezeError("invalid Git HEAD identity")
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
        raise StageCThresholdFreezeError(
            "Task-24 and bound freeze files must be committed before threshold freeze"
        ) from exc
    if dirty != 0:
        raise StageCThresholdFreezeError(
            "Task-24/bound freeze files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task24_module_sha256": sha256_file(repo_root / paths[0]),
        "task24_cli_sha256": sha256_file(repo_root / paths[1]),
        "task23_module_sha256": sha256_file(repo_root / paths[2]),
        "task18_module_sha256": sha256_file(repo_root / paths[3]),
    }


def freeze_stage_c_threshold(
    *,
    repo_root: Path,
    authorization_path: Path,
    selection_record_path: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    selection = load_json(selection_record_path)

    threshold_point = validate_task23_authorization(auth)
    artifact = validate_task18_selection(selection)
    git = _git_provenance(repo_root)

    frozen_pair = {
        "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "candidate_family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
        "artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
        "threshold": EXPECTED_THRESHOLD,
    }

    record = {
        "schema_version": FREEZE_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "selected_candidate_family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
        "selected_candidate_artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "threshold_selection_authorized": True,
        "threshold_selection_performed": True,
        "threshold_selected": True,
        "threshold_frozen": True,
        "calibration_fitting_authorized": False,
        "final_holdout_touched": False,
        "frozen_operating_point": {
            "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
            "threshold": EXPECTED_THRESHOLD,
            "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
            "candidate_family": EXPECTED_SELECTED_CANDIDATE_FAMILY,
            "artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
            "candidate_threshold_pair_sha256": canonical_hash(frozen_pair),
            "calibration_evidence": {
                "tp": threshold_point["tp"],
                "fp": threshold_point["fp"],
                "tn": threshold_point["tn"],
                "fn": threshold_point["fn"],
                "observed_fpr": threshold_point["observed_fpr"],
                "wilson_upper_95": threshold_point["wilson_upper_95"],
                "recall": threshold_point["recall"],
                "precision": threshold_point["precision"],
                "primary_constraint_satisfied": True,
            },
        },
        "selected_candidate_artifact": {
            "candidate_id": artifact["candidate_id"],
            "family": artifact["family"],
            "artifact_sha256": artifact["artifact_sha256"],
            "artifact_size_bytes": artifact.get("artifact_size_bytes"),
            "artifact_format": artifact.get("artifact_format"),
            "physical_artifact_verified_at_task18": True,
        },
        "identity_bindings": {
            "task18_selection_record_sha256": EXPECTED_TASK18_SELECTION_RECORD_SHA256,
            "task23_authorization_sha256": EXPECTED_TASK23_AUTHORIZATION_SHA256,
            "task23_threshold_evidence_sha256": EXPECTED_TASK23_THRESHOLD_EVIDENCE_SHA256,
            "task22_evaluation_report_sha256": EXPECTED_TASK22_EVALUATION_REPORT_SHA256,
            "task22_threshold_analysis_sha256": EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256,
            **git,
        },
        "prohibitions": {
            "model_refit": True,
            "artifact_substitution": True,
            "calibration_fitting": True,
            "threshold_reselection": True,
            "threshold_change": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "ISSUE_STAGE_C_FINAL_HOLDOUT_SCORING_AUTHORIZATION_FOR_FROZEN_"
            "CANDIDATE_AND_THRESHOLD"
        ),
    }
    record["threshold_freeze_record_sha256"] = canonical_hash(record)
    return record
