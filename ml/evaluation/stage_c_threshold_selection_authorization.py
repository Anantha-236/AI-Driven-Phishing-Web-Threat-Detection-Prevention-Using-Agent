"""Stage C Task 23 — authorize threshold selection from frozen calibration analysis.

This gate binds the frozen Task-22 calibration evaluation report and its
threshold-analysis identity. It authorizes a later task to select exactly the
diagnostic maximum-recall threshold satisfying the registered 1% observed-FPR
and 95% Wilson-upper constraints.

Task 23 does not itself select or freeze a threshold. It does not refit the
model, fit a calibrator, deploy anything, or access the final holdout.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-threshold-selection-authorization-1"

EXPECTED_TASK22_EVALUATION_REPORT_SHA256 = "ea3de4d936246a5d7ead22851e0485cede762a63e417e5e583ab43617b167499"
EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256 = "b9e09ba9911adcba1072194ec7c7242b3fa9b34ecca19fa72efb21468ad78d6b"
EXPECTED_TASK21_AUTHORIZATION_SHA256 = "7fc833b8fb9e4a8d90d744102e38fcc7fbcbd2bf7e572b51c0fb36b9198bb518"

EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_CALIBRATION_COUNT = 7314
EXPECTED_PRIMARY_FPR_CAP = 0.01
EXPECTED_CONFIDENCE_LEVEL = 0.95

EXPECTED_DIAGNOSTIC_POINT = {
    "threshold": 0.8637646437995518,
    "threshold_is_above_max_score_sentinel": False,
    "tp": 310,
    "fp": 36,
    "tn": 5548,
    "fn": 1420,
    "observed_fpr": 0.0064469914040114614,
    "wilson_upper_95": 0.00891200424846714,
    "recall": 0.1791907514450867,
    "precision": 0.8959537572254336,
    "primary_constraint_satisfied": True,
    "threshold_selected": False,
    "threshold_frozen": False,
    "diagnostic_only": True,
}


class StageCThresholdSelectionAuthorizationError(ValueError):
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
        raise StageCThresholdSelectionAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCThresholdSelectionAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCThresholdSelectionAuthorizationError(
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
            raise StageCThresholdSelectionAuthorizationError(
                f"refusing to replace non-identical frozen Task-23 output: {path}"
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


def _same_number(actual: Any, expected: float, field: str) -> None:
    if type(actual) not in (int, float) or not math.isfinite(actual):
        raise StageCThresholdSelectionAuthorizationError(
            f"Task-22 diagnostic value invalid: {field}"
        )
    if float(actual) != expected:
        raise StageCThresholdSelectionAuthorizationError(
            f"Task-22 diagnostic value changed: {field}"
        )


def validate_task22_report(report: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-calibration-evaluation-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "calibration_metric_computation_authorized": True,
        "calibration_metrics_computed": True,
        "threshold_analysis_authorized": True,
        "threshold_analysis_performed": True,
        "threshold_selection_authorized": False,
        "threshold_selected": False,
        "threshold_frozen": False,
        "calibration_fitting_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK21_AUTHORIZATION_SHA256,
        "threshold_analysis_sha256": EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256,
        "evaluation_report_sha256": EXPECTED_TASK22_EVALUATION_REPORT_SHA256,
        "next_gate": (
            "ISSUE_STAGE_C_THRESHOLD_SELECTION_AUTHORIZATION_FROM_FROZEN_"
            "CALIBRATION_ANALYSIS"
        ),
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise StageCThresholdSelectionAuthorizationError(
                f"Task-22 report guard mismatch: {key}"
            )

    if (
        hash_without(report, "evaluation_report_sha256")
        != EXPECTED_TASK22_EVALUATION_REPORT_SHA256
    ):
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 canonical evaluation-report hash mismatch"
        )

    evaluation = report.get("calibration_evaluation")
    objective = report.get("primary_objective")
    if not isinstance(evaluation, Mapping) or not isinstance(objective, Mapping):
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 evaluation/objective missing"
        )

    if evaluation.get("selected_candidate_id") != EXPECTED_SELECTED_CANDIDATE_ID:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 selected candidate changed"
        )
    if evaluation.get("calibration_sample_count") != EXPECTED_CALIBRATION_COUNT:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 calibration count changed"
        )
    if evaluation.get("threshold_selected") is not False:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 unexpectedly selected threshold"
        )
    if evaluation.get("threshold_frozen") is not False:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 unexpectedly froze threshold"
        )

    threshold_analysis = evaluation.get("threshold_analysis")
    if not isinstance(threshold_analysis, Mapping):
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 threshold analysis missing"
        )

    checks = [
        (
            threshold_analysis.get("threshold_rule")
            == "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
            "threshold rule",
        ),
        (
            threshold_analysis.get("primary_fpr_cap") == EXPECTED_PRIMARY_FPR_CAP,
            "threshold FPR cap",
        ),
        (
            threshold_analysis.get("confidence_level") == EXPECTED_CONFIDENCE_LEVEL,
            "threshold confidence",
        ),
        (
            threshold_analysis.get("constraint_feasible") is True,
            "threshold feasibility",
        ),
        (
            threshold_analysis.get("threshold_selection_authorized") is False,
            "Task-22 threshold-selection state",
        ),
        (
            threshold_analysis.get("threshold_selected") is False,
            "Task-22 selected state",
        ),
        (
            threshold_analysis.get("threshold_frozen") is False,
            "Task-22 frozen state",
        ),
        (
            objective.get("metric") == "false_positive_rate",
            "primary metric",
        ),
        (
            objective.get("fpr_cap") == EXPECTED_PRIMARY_FPR_CAP,
            "objective FPR cap",
        ),
        (
            objective.get("confidence_level") == EXPECTED_CONFIDENCE_LEVEL,
            "objective confidence",
        ),
        (
            objective.get("require_observed_fpr_at_or_below_cap") is True,
            "observed-FPR requirement",
        ),
        (
            objective.get("require_wilson_upper_at_or_below_cap") is True,
            "Wilson requirement",
        ),
        (
            objective.get("secondary_metric") == "recall",
            "secondary metric",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCThresholdSelectionAuthorizationError(
                f"Task-22 report changed: {name}"
            )

    diagnostic = threshold_analysis.get(
        "diagnostic_max_recall_point_under_primary_constraint"
    )
    if not isinstance(diagnostic, Mapping):
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 diagnostic threshold point missing"
        )

    for field in ("threshold", "observed_fpr", "wilson_upper_95", "recall", "precision"):
        _same_number(diagnostic.get(field), EXPECTED_DIAGNOSTIC_POINT[field], field)

    for field in ("tp", "fp", "tn", "fn"):
        if diagnostic.get(field) != EXPECTED_DIAGNOSTIC_POINT[field]:
            raise StageCThresholdSelectionAuthorizationError(
                f"Task-22 diagnostic count changed: {field}"
            )

    boolean_fields = (
        "threshold_is_above_max_score_sentinel",
        "primary_constraint_satisfied",
        "threshold_selected",
        "threshold_frozen",
        "diagnostic_only",
    )
    for field in boolean_fields:
        if diagnostic.get(field) is not EXPECTED_DIAGNOSTIC_POINT[field]:
            raise StageCThresholdSelectionAuthorizationError(
                f"Task-22 diagnostic flag changed: {field}"
            )

    if diagnostic["observed_fpr"] > EXPECTED_PRIMARY_FPR_CAP:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 diagnostic observed FPR exceeds cap"
        )
    if diagnostic["wilson_upper_95"] > EXPECTED_PRIMARY_FPR_CAP:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 diagnostic Wilson upper exceeds cap"
        )
    if diagnostic["threshold_is_above_max_score_sentinel"]:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 diagnostic point is sentinel, refusing threshold selection"
        )

    analysis_identity = {
        "selected_candidate_id": evaluation["selected_candidate_id"],
        "calibration_sample_count": evaluation["calibration_sample_count"],
        "calibration_legitimate_count": evaluation["calibration_legitimate_count"],
        "calibration_phishing_count": evaluation["calibration_phishing_count"],
        "score_min": evaluation["score_min"],
        "score_max": evaluation["score_max"],
        "score_mean": evaluation["score_mean"],
        "metrics": evaluation["metrics"],
        "threshold_analysis": evaluation["threshold_analysis"],
        "threshold_selected": evaluation["threshold_selected"],
        "threshold_frozen": evaluation["threshold_frozen"],
    }
    if canonical_hash(analysis_identity) != EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-22 threshold-analysis canonical hash mismatch"
        )

    return dict(diagnostic)


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_threshold_selection_authorization.py",
        "ml/evaluation/authorize_stage_c_threshold_selection.py",
        "ml/evaluation/stage_c_calibration_evaluation.py",
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
            raise StageCThresholdSelectionAuthorizationError(
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
        raise StageCThresholdSelectionAuthorizationError(
            "Task-23 and bound threshold files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCThresholdSelectionAuthorizationError(
            "Task-23/bound threshold files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task23_module_sha256": sha256_file(repo_root / paths[0]),
        "task23_cli_sha256": sha256_file(repo_root / paths[1]),
        "task22_module_sha256": sha256_file(repo_root / paths[2]),
    }


def issue_threshold_selection_authorization(
    *,
    repo_root: Path,
    evaluation_report_path: Path,
) -> dict[str, Any]:
    report = load_json(evaluation_report_path)
    diagnostic = validate_task22_report(report)
    git = _git_provenance(repo_root)

    frozen_evidence = {
        "selected_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
        "diagnostic_point": diagnostic,
        "task22_threshold_analysis_sha256": (
            EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256
        ),
    }

    authorization = {
        "schema_version": AUTH_SCHEMA,
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
        "selection_rule": {
            "source": (
                "TASK22_DIAGNOSTIC_MAX_RECALL_POINT_UNDER_PRIMARY_CONSTRAINT"
            ),
            "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
            "require_non_sentinel_point": True,
            "require_primary_constraint_satisfied": True,
            "observed_fpr_lte": EXPECTED_PRIMARY_FPR_CAP,
            "wilson_upper_95_lte": EXPECTED_PRIMARY_FPR_CAP,
            "secondary_objective": "MAXIMIZE_RECALL",
            "selection_choice_count": 1,
            "implicit_alternative_thresholds_authorized": False,
            "recompute_threshold_sweep_authorized": False,
        },
        "threshold_selection_scope": {
            "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
            "authorized_threshold": diagnostic["threshold"],
            "authorized_threshold_point": diagnostic,
            "authorized_threshold_evidence_sha256": canonical_hash(frozen_evidence),
        },
        "identity_bindings": {
            "task21_authorization_sha256": EXPECTED_TASK21_AUTHORIZATION_SHA256,
            "task22_evaluation_report_sha256": (
                EXPECTED_TASK22_EVALUATION_REPORT_SHA256
            ),
            "task22_threshold_analysis_sha256": (
                EXPECTED_TASK22_THRESHOLD_ANALYSIS_SHA256
            ),
            **git,
        },
        "prohibitions": {
            "model_refit": True,
            "calibration_fitting": True,
            "threshold_sweep_recomputation": True,
            "select_different_threshold": True,
            "select_sentinel_threshold": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": "FREEZE_STAGE_C_AUTHORIZED_THRESHOLD",
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
