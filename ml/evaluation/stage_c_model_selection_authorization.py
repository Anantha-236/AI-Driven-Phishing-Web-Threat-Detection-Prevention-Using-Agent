"""Stage C Task 17 — authorize model selection from frozen Task-16 evidence.

This gate binds the Task-16 evaluation report, Task-12 candidate eligibility,
and the Stage-C experiment objective into one deterministic selection policy.

Task 17 does NOT select a candidate. It authorizes a later task to select among
eligible candidates by maximizing diagnostic recall subject to the frozen
low-FPR constraints. Ties fail closed; no implicit tie-breaker is allowed.

Calibration, threshold freezing, deployment, and final holdout remain locked.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-model-selection-authorization-1"

EXPECTED_TASK16_EVALUATION_REPORT_SHA256 = "e66cb4780fcd2d1141e3a47008ba6d1f414d8b49a706441484522a6eee5672b1"
EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256 = "24997e9b069f46318207b973cab29551acd3dba45405e260976e17af4f3542a4"
EXPECTED_TASK16_GIT_HEAD = "b7bf76d45da7ca7794c0c25b6766dbb2fafa49c6"
EXPECTED_TASK15_AUTHORIZATION_SHA256 = "d70f1ec228a91beba90a424528eaa3e0cda5a0a59213e5b0ee8a4adce42fb491"

EXPECTED_TASK12_TRAINING_MANIFEST_SHA256 = "887903dfe3af05490c0f2cc89ad3bcc9afa20a1ac495a7e4ca9fdaca44369399"
EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"

EXPECTED_SELECTION_COUNT = 20710
EXPECTED_PRIMARY_FPR_CAP = 0.01
EXPECTED_CONFIDENCE_LEVEL = 0.95

EXPECTED_CANDIDATES = (
    "dummy_prior",
    "hist_gradient_boosting",
    "logistic_regression",
    "random_forest_compact",
)
EXPECTED_ELIGIBILITY = {
    "dummy_prior": False,
    "hist_gradient_boosting": True,
    "logistic_regression": True,
    "random_forest_compact": True,
}


class StageCModelSelectionAuthorizationError(ValueError):
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
        raise StageCModelSelectionAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCModelSelectionAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCModelSelectionAuthorizationError(
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
            raise StageCModelSelectionAuthorizationError(
                f"refusing to replace non-identical frozen Task-17 output: {path}"
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


def validate_task16_report(report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    expected = {
        "schema_version": "stage-c-selection-evaluation-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selection_metric_computation_authorized": True,
        "selection_metrics_computed": True,
        "model_selection_authorized": False,
        "candidate_ranking_performed": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK15_AUTHORIZATION_SHA256,
        "candidate_order": list(EXPECTED_CANDIDATES),
        "candidate_order_semantics": (
            "FIXED_CANDIDATE_ID_ORDER_NOT_PERFORMANCE_RANKING"
        ),
        "candidate_evaluation_set_sha256": (
            EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256
        ),
        "evaluation_report_sha256": EXPECTED_TASK16_EVALUATION_REPORT_SHA256,
        "next_gate": (
            "ISSUE_STAGE_C_MODEL_SELECTION_AUTHORIZATION_FROM_FROZEN_SELECTION_EVALUATION"
        ),
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 report guard mismatch: {key}"
            )
    if (
        hash_without(report, "evaluation_report_sha256")
        != EXPECTED_TASK16_EVALUATION_REPORT_SHA256
    ):
        raise StageCModelSelectionAuthorizationError(
            "Task-16 canonical evaluation-report hash mismatch"
        )

    objective = report.get("primary_objective")
    evaluation_input = report.get("evaluation_input")
    git = report.get("git_provenance")
    evaluations = report.get("candidate_evaluations")
    if not isinstance(objective, Mapping):
        raise StageCModelSelectionAuthorizationError(
            "Task-16 primary objective missing"
        )
    if not isinstance(evaluation_input, Mapping):
        raise StageCModelSelectionAuthorizationError(
            "Task-16 evaluation input missing"
        )
    if not isinstance(git, Mapping):
        raise StageCModelSelectionAuthorizationError(
            "Task-16 Git provenance missing"
        )
    if not isinstance(evaluations, list) or len(evaluations) != 4:
        raise StageCModelSelectionAuthorizationError(
            "Task-16 candidate evaluations missing"
        )

    objective_checks = [
        (objective.get("metric") == "false_positive_rate", "primary metric"),
        (objective.get("fpr_cap") == EXPECTED_PRIMARY_FPR_CAP, "FPR cap"),
        (
            objective.get("confidence_level") == EXPECTED_CONFIDENCE_LEVEL,
            "confidence level",
        ),
        (
            objective.get("require_observed_fpr_at_or_below_cap") is True,
            "observed-FPR requirement",
        ),
        (
            objective.get("require_wilson_upper_at_or_below_cap") is True,
            "Wilson requirement",
        ),
        (objective.get("secondary_metric") == "recall", "secondary metric"),
        (
            evaluation_input.get("selection_sample_count")
            == EXPECTED_SELECTION_COUNT,
            "selection sample count",
        ),
        (
            git.get("git_head") == EXPECTED_TASK16_GIT_HEAD,
            "Task-16 Git identity",
        ),
    ]
    for ok, name in objective_checks:
        if not ok:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 report changed: {name}"
            )

    if canonical_hash(evaluations) != EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256:
        raise StageCModelSelectionAuthorizationError(
            "Task-16 candidate-evaluation set identity changed"
        )

    by_id: dict[str, dict[str, Any]] = {}
    for row in evaluations:
        if not isinstance(row, Mapping):
            raise StageCModelSelectionAuthorizationError(
                "Task-16 candidate evaluation invalid"
            )
        cid = row.get("candidate_id")
        if cid not in EXPECTED_CANDIDATES or cid in by_id:
            raise StageCModelSelectionAuthorizationError(
                "Task-16 candidate identity invalid"
            )
        if row.get("candidate_rank") is not None:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 unexpectedly ranked candidate: {cid}"
            )
        if row.get("candidate_selected") is not False:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 unexpectedly selected candidate: {cid}"
            )
        if row.get("threshold_frozen") is not False:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 unexpectedly froze threshold: {cid}"
            )
        if row.get("selection_sample_count") != EXPECTED_SELECTION_COUNT:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 candidate sample count changed: {cid}"
            )
        metrics = row.get("metrics")
        diag = row.get("low_fpr_diagnostics")
        if not isinstance(metrics, Mapping) or not isinstance(diag, Mapping):
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 candidate evidence missing: {cid}"
            )
        for metric in ("average_precision", "roc_auc", "brier_score", "log_loss"):
            value = metrics.get(metric)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 metric invalid: {cid}/{metric}"
                )
        if diag.get("threshold_frozen") is not False:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 diagnostic threshold frozen: {cid}"
            )
        point = diag.get("diagnostic_max_recall_point_under_primary_constraint")
        if diag.get("constraint_feasible") is True:
            if not isinstance(point, Mapping):
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 feasible candidate lacks diagnostic point: {cid}"
                )
            if point.get("primary_constraint_satisfied") is not True:
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 diagnostic constraint mismatch: {cid}"
                )
            if point.get("threshold_frozen") is not False:
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 diagnostic threshold unexpectedly frozen: {cid}"
                )
            if point.get("diagnostic_only") is not True:
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 diagnostic point not marked diagnostic-only: {cid}"
                )
            for field in ("observed_fpr", "wilson_upper_95", "recall", "precision"):
                value = point.get(field)
                if type(value) not in (int, float) or not math.isfinite(value):
                    raise StageCModelSelectionAuthorizationError(
                        f"Task-16 diagnostic value invalid: {cid}/{field}"
                    )
            if point["observed_fpr"] > EXPECTED_PRIMARY_FPR_CAP:
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 observed FPR exceeds cap: {cid}"
                )
            if point["wilson_upper_95"] > EXPECTED_PRIMARY_FPR_CAP:
                raise StageCModelSelectionAuthorizationError(
                    f"Task-16 Wilson upper exceeds cap: {cid}"
                )
        elif point is not None:
            raise StageCModelSelectionAuthorizationError(
                f"Task-16 infeasible candidate has diagnostic point: {cid}"
            )
        by_id[cid] = dict(row)

    if tuple(by_id) != EXPECTED_CANDIDATES:
        raise StageCModelSelectionAuthorizationError(
            "Task-16 candidate order changed"
        )
    return by_id


def validate_task12_manifest(
    manifest: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
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
            raise StageCModelSelectionAuthorizationError(
                f"Task-12 training manifest guard mismatch: {key}"
            )
    if (
        hash_without(manifest, "training_manifest_sha256")
        != EXPECTED_TASK12_TRAINING_MANIFEST_SHA256
    ):
        raise StageCModelSelectionAuthorizationError(
            "Task-12 canonical training-manifest hash mismatch"
        )

    artifacts = manifest.get("candidate_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 4:
        raise StageCModelSelectionAuthorizationError(
            "Task-12 candidate artifacts missing"
        )
    by_id: dict[str, dict[str, Any]] = {}
    for row in artifacts:
        if not isinstance(row, Mapping):
            raise StageCModelSelectionAuthorizationError(
                "Task-12 candidate artifact record invalid"
            )
        cid = row.get("candidate_id")
        if cid not in EXPECTED_CANDIDATES or cid in by_id:
            raise StageCModelSelectionAuthorizationError(
                "Task-12 candidate artifact identity invalid"
            )
        if (
            row.get("eligible_for_later_selection")
            is not EXPECTED_ELIGIBILITY[cid]
        ):
            raise StageCModelSelectionAuthorizationError(
                f"Task-12 selection eligibility changed: {cid}"
            )
        artifact_sha = row.get("artifact_sha256")
        if not isinstance(artifact_sha, str) or len(artifact_sha) != 64:
            raise StageCModelSelectionAuthorizationError(
                f"Task-12 candidate artifact SHA invalid: {cid}"
            )
        by_id[cid] = {
            "candidate_id": cid,
            "family": row.get("family"),
            "eligible_for_later_selection": EXPECTED_ELIGIBILITY[cid],
            "artifact_sha256": artifact_sha,
        }
    if set(by_id) != set(EXPECTED_CANDIDATES):
        raise StageCModelSelectionAuthorizationError(
            "Task-12 candidate artifact set changed"
        )
    return by_id


def validate_experiment_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != "stage-c-experiment-contract-1":
        raise StageCModelSelectionAuthorizationError(
            "experiment contract schema changed"
        )
    if (
        contract.get("stage") != "C"
        or contract.get("protocol_id") != "low-fpr-generalization-v1"
    ):
        raise StageCModelSelectionAuthorizationError(
            "experiment contract identity changed"
        )
    if (
        contract.get("research_only") is not True
        or contract.get("deployment_authorized") is not False
    ):
        raise StageCModelSelectionAuthorizationError(
            "experiment contract safety state changed"
        )
    objective = contract.get("objective")
    holdout = contract.get("holdout_contract")
    development = contract.get("development_contract")
    if not all(isinstance(x, Mapping) for x in (objective, holdout, development)):
        raise StageCModelSelectionAuthorizationError(
            "experiment contract sections missing"
        )
    checks = [
        (objective.get("primary_metric") == "false_positive_rate", "primary metric"),
        (objective.get("primary_fpr_cap") == EXPECTED_PRIMARY_FPR_CAP, "FPR cap"),
        (
            objective.get("confidence_level") == EXPECTED_CONFIDENCE_LEVEL,
            "confidence level",
        ),
        (
            objective.get("require_observed_fpr_at_or_below_cap") is True,
            "observed-FPR requirement",
        ),
        (
            objective.get("require_wilson_upper_at_or_below_cap") is True,
            "Wilson requirement",
        ),
        (objective.get("secondary_metric") == "recall", "secondary metric"),
        (
            objective.get("secondary_objective")
            == "maximize recall subject to primary low-FPR constraints",
            "secondary objective",
        ),
        (
            holdout.get("selection_use_prohibited") is True,
            "holdout selection prohibition",
        ),
        (
            holdout.get("calibration_use_prohibited") is True,
            "holdout calibration prohibition",
        ),
        (
            holdout.get("threshold_selection_use_prohibited") is True,
            "holdout threshold prohibition",
        ),
        (
            development.get("test_locked_until_candidate_and_threshold_frozen")
            is True,
            "test lock",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCModelSelectionAuthorizationError(
                f"experiment contract changed: {name}"
            )
    return {
        "experiment_contract_sha256": canonical_hash(contract),
        "primary_metric": "false_positive_rate",
        "primary_fpr_cap": EXPECTED_PRIMARY_FPR_CAP,
        "confidence_level": EXPECTED_CONFIDENCE_LEVEL,
        "secondary_metric": "recall",
        "secondary_objective": (
            "maximize recall subject to primary low-FPR constraints"
        ),
    }


def build_selection_evidence(
    evaluations: Mapping[str, Mapping[str, Any]],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for cid in EXPECTED_CANDIDATES:
        evaluation = evaluations[cid]
        artifact = artifacts[cid]
        diag = evaluation["low_fpr_diagnostics"]
        point = diag["diagnostic_max_recall_point_under_primary_constraint"]
        feasible = bool(diag["constraint_feasible"])
        record = {
            "candidate_id": cid,
            "family": artifact["family"],
            "artifact_sha256": artifact["artifact_sha256"],
            "eligible_for_model_selection": artifact[
                "eligible_for_later_selection"
            ],
            "primary_constraint_feasible": feasible,
            "diagnostic_point_present": point is not None,
            "diagnostic_threshold_is_not_frozen": True,
            "diagnostic_sweep_sha256": diag["sweep_sha256"],
            "average_precision": evaluation["metrics"]["average_precision"],
            "roc_auc": evaluation["metrics"]["roc_auc"],
            "brier_score": evaluation["metrics"]["brier_score"],
            "log_loss": evaluation["metrics"]["log_loss"],
        }
        if point is not None:
            record.update({
                "diagnostic_threshold": point["threshold"],
                "diagnostic_observed_fpr": point["observed_fpr"],
                "diagnostic_wilson_upper_95": point["wilson_upper_95"],
                "diagnostic_recall": point["recall"],
                "diagnostic_precision": point["precision"],
                "diagnostic_fp": point["fp"],
                "diagnostic_tp": point["tp"],
            })
        else:
            record.update({
                "diagnostic_threshold": None,
                "diagnostic_observed_fpr": None,
                "diagnostic_wilson_upper_95": None,
                "diagnostic_recall": None,
                "diagnostic_precision": None,
                "diagnostic_fp": None,
                "diagnostic_tp": None,
            })
        evidence.append(record)
    return evidence


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_model_selection_authorization.py",
        "ml/evaluation/authorize_stage_c_model_selection.py",
        "ml/evaluation/stage_c_selection_evaluation.py",
        "ml/training/stage_c_candidate_training.py",
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
            raise StageCModelSelectionAuthorizationError(
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
        raise StageCModelSelectionAuthorizationError(
            "Task-17 and bound selection files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCModelSelectionAuthorizationError(
            "Task-17/bound selection files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task17_module_sha256": sha256_file(repo_root / paths[0]),
        "task17_cli_sha256": sha256_file(repo_root / paths[1]),
        "task16_module_sha256": sha256_file(repo_root / paths[2]),
        "task12_module_sha256": sha256_file(repo_root / paths[3]),
        "experiment_contract_file_sha256": sha256_file(repo_root / paths[4]),
    }


def issue_model_selection_authorization(
    *,
    repo_root: Path,
    evaluation_report_path: Path,
    training_manifest_path: Path,
    experiment_contract_path: Path,
) -> dict[str, Any]:
    report = load_json(evaluation_report_path)
    training = load_json(training_manifest_path)
    contract = load_json(experiment_contract_path)

    evaluations = validate_task16_report(report)
    artifacts = validate_task12_manifest(training)
    objective = validate_experiment_contract(contract)
    evidence = build_selection_evidence(evaluations, artifacts)
    git = _git_provenance(repo_root)

    eligible_and_feasible = [
        row["candidate_id"]
        for row in evidence
        if row["eligible_for_model_selection"]
        and row["primary_constraint_feasible"]
    ]
    if not eligible_and_feasible:
        raise StageCModelSelectionAuthorizationError(
            "no eligible candidate satisfies the primary low-FPR constraint"
        )

    authorization = {
        "schema_version": AUTH_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selection_metrics_computed": True,
        "model_selection_authorized": True,
        "model_selection_performed": False,
        "candidate_selected": False,
        "calibration_access_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "SELECT_ONE_ELIGIBLE_STAGE_C_CANDIDATE_FROM_FROZEN_SELECTION_EVIDENCE"
        ),
        "selection_rule": {
            "candidate_eligibility_source": "TASK12_FROZEN_ELIGIBILITY_FLAG",
            "primary_constraint": {
                "require_constraint_feasible": True,
                "observed_fpr_lte": EXPECTED_PRIMARY_FPR_CAP,
                "wilson_upper_95_lte": EXPECTED_PRIMARY_FPR_CAP,
            },
            "secondary_objective": "MAXIMIZE_DIAGNOSTIC_RECALL",
            "diagnostic_threshold_use": (
                "SELECTION_EVIDENCE_ONLY_NOT_AUTHORIZED_AS_FROZEN_THRESHOLD"
            ),
            "tie_policy": "FAIL_CLOSED_NO_IMPLICIT_TIEBREAKER",
            "candidate_ranking_required": False,
            "non_objective_metrics_are_descriptive_only": [
                "average_precision",
                "roc_auc",
                "brier_score",
                "log_loss",
                "precision",
            ],
        },
        "selection_scope": {
            "candidate_count": len(evidence),
            "candidate_order": list(EXPECTED_CANDIDATES),
            "eligible_candidate_count": sum(
                1 for row in evidence
                if row["eligible_for_model_selection"]
            ),
            "eligible_and_primary_feasible_count": len(eligible_and_feasible),
            "eligible_and_primary_feasible_candidates": eligible_and_feasible,
            "selection_evidence": evidence,
            "selection_evidence_sha256": canonical_hash(evidence),
        },
        "objective": objective,
        "identity_bindings": {
            "task16_evaluation_report_sha256": (
                EXPECTED_TASK16_EVALUATION_REPORT_SHA256
            ),
            "task16_candidate_evaluation_set_sha256": (
                EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256
            ),
            "task12_training_manifest_sha256": (
                EXPECTED_TASK12_TRAINING_MANIFEST_SHA256
            ),
            "candidate_artifact_set_sha256": (
                EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256
            ),
            **git,
        },
        "prohibitions": {
            "model_refit": True,
            "use_ineligible_candidate": True,
            "use_candidate_failing_primary_constraint": True,
            "implicit_tiebreak": True,
            "freeze_selection_diagnostic_threshold": True,
            "calibration_access": True,
            "calibration_fitting": True,
            "threshold_freeze": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": "SELECT_STAGE_C_CANDIDATE_FROM_FROZEN_SELECTION_EVIDENCE",
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
