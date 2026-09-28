"""Stage C Task 18 — execute the authorized model-selection rule once.

Task 18 consumes the frozen Task-17 authorization, deterministically selects one
eligible candidate by maximum diagnostic recall subject to the primary low-FPR
constraint, verifies the selected Task-12 artifact on disk, and freezes the
selection record.

The Task-16 diagnostic threshold remains evidence only. It is not frozen and is
not authorized for calibration or deployment.

Task 18 does not fit, score, calibrate, threshold, deploy, or access holdout data.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

SELECTION_SCHEMA = "stage-c-candidate-selection-1"

EXPECTED_TASK17_AUTHORIZATION_SHA256 = "416c29e333325b0f0f201eecde801fdc1ee05b966a8d84c78bd24a07a626ea34"
EXPECTED_TASK17_SELECTION_EVIDENCE_SHA256 = "95b13e1b9322fb914282e02608b139220964be132cd259b69b30ba755c48ec1b"
EXPECTED_TASK16_EVALUATION_REPORT_SHA256 = "e66cb4780fcd2d1141e3a47008ba6d1f414d8b49a706441484522a6eee5672b1"
EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256 = "24997e9b069f46318207b973cab29551acd3dba45405e260976e17af4f3542a4"
EXPECTED_TASK12_TRAINING_MANIFEST_SHA256 = "887903dfe3af05490c0f2cc89ad3bcc9afa20a1ac495a7e4ca9fdaca44369399"
EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"

EXPECTED_PRIMARY_FPR_CAP = 0.01
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


class StageCCandidateSelectionError(ValueError):
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
        raise StageCCandidateSelectionError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCandidateSelectionError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCCandidateSelectionError(
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
            raise StageCCandidateSelectionError(
                f"refusing to replace non-identical frozen Task-18 output: {path}"
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


def validate_task17_authorization(
    auth: Mapping[str, Any],
) -> list[dict[str, Any]]:
    expected = {
        "schema_version": "stage-c-model-selection-authorization-1",
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
        "authorization_sha256": EXPECTED_TASK17_AUTHORIZATION_SHA256,
        "next_gate": "SELECT_STAGE_C_CANDIDATE_FROM_FROZEN_SELECTION_EVIDENCE",
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCCandidateSelectionError(
                f"Task-17 authorization guard mismatch: {key}"
            )
    if (
        hash_without(auth, "authorization_sha256")
        != EXPECTED_TASK17_AUTHORIZATION_SHA256
    ):
        raise StageCCandidateSelectionError(
            "Task-17 canonical authorization hash mismatch"
        )

    rule = auth.get("selection_rule")
    scope = auth.get("selection_scope")
    bindings = auth.get("identity_bindings")
    prohibitions = auth.get("prohibitions")
    if not all(
        isinstance(x, Mapping)
        for x in (rule, scope, bindings, prohibitions)
    ):
        raise StageCCandidateSelectionError(
            "Task-17 authorization sections missing"
        )

    primary = rule.get("primary_constraint")
    if not isinstance(primary, Mapping):
        raise StageCCandidateSelectionError(
            "Task-17 primary selection constraint missing"
        )
    checks = [
        (
            rule.get("candidate_eligibility_source")
            == "TASK12_FROZEN_ELIGIBILITY_FLAG",
            "candidate eligibility source",
        ),
        (
            primary.get("require_constraint_feasible") is True,
            "feasibility requirement",
        ),
        (
            primary.get("observed_fpr_lte") == EXPECTED_PRIMARY_FPR_CAP,
            "observed FPR cap",
        ),
        (
            primary.get("wilson_upper_95_lte") == EXPECTED_PRIMARY_FPR_CAP,
            "Wilson cap",
        ),
        (
            rule.get("secondary_objective") == "MAXIMIZE_DIAGNOSTIC_RECALL",
            "secondary objective",
        ),
        (
            rule.get("diagnostic_threshold_use")
            == "SELECTION_EVIDENCE_ONLY_NOT_AUTHORIZED_AS_FROZEN_THRESHOLD",
            "diagnostic threshold semantics",
        ),
        (
            rule.get("tie_policy")
            == "FAIL_CLOSED_NO_IMPLICIT_TIEBREAKER",
            "tie policy",
        ),
        (
            rule.get("candidate_ranking_required") is False,
            "ranking requirement",
        ),
        (scope.get("candidate_count") == 4, "candidate count"),
        (scope.get("candidate_order") == list(EXPECTED_CANDIDATES), "candidate order"),
        (scope.get("eligible_candidate_count") == 3, "eligible count"),
        (
            scope.get("eligible_and_primary_feasible_count") == 3,
            "eligible feasible count",
        ),
        (
            scope.get("selection_evidence_sha256")
            == EXPECTED_TASK17_SELECTION_EVIDENCE_SHA256,
            "selection evidence identity",
        ),
        (
            bindings.get("task16_evaluation_report_sha256")
            == EXPECTED_TASK16_EVALUATION_REPORT_SHA256,
            "Task-16 report binding",
        ),
        (
            bindings.get("task16_candidate_evaluation_set_sha256")
            == EXPECTED_TASK16_CANDIDATE_EVALUATION_SET_SHA256,
            "Task-16 evaluation-set binding",
        ),
        (
            bindings.get("task12_training_manifest_sha256")
            == EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
            "Task-12 manifest binding",
        ),
        (
            bindings.get("candidate_artifact_set_sha256")
            == EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
            "artifact-set binding",
        ),
        (prohibitions.get("model_refit") is True, "refit prohibition"),
        (
            prohibitions.get("use_ineligible_candidate") is True,
            "ineligible-candidate prohibition",
        ),
        (
            prohibitions.get("use_candidate_failing_primary_constraint") is True,
            "primary-constraint prohibition",
        ),
        (
            prohibitions.get("implicit_tiebreak") is True,
            "implicit-tiebreak prohibition",
        ),
        (
            prohibitions.get("freeze_selection_diagnostic_threshold") is True,
            "diagnostic-threshold freeze prohibition",
        ),
        (
            prohibitions.get("calibration_access") is True,
            "calibration prohibition",
        ),
        (
            prohibitions.get("threshold_freeze") is True,
            "threshold-freeze prohibition",
        ),
        (
            prohibitions.get("final_holdout_access") is True,
            "holdout prohibition",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCCandidateSelectionError(
                f"Task-17 authorization changed: {name}"
            )

    evidence = scope.get("selection_evidence")
    if not isinstance(evidence, list) or len(evidence) != 4:
        raise StageCCandidateSelectionError(
            "Task-17 selection evidence missing"
        )
    if canonical_hash(evidence) != EXPECTED_TASK17_SELECTION_EVIDENCE_SHA256:
        raise StageCCandidateSelectionError(
            "Task-17 selection-evidence canonical hash mismatch"
        )

    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for row in evidence:
        if not isinstance(row, Mapping):
            raise StageCCandidateSelectionError(
                "Task-17 evidence record invalid"
            )
        cid = row.get("candidate_id")
        if cid not in EXPECTED_CANDIDATES or cid in seen:
            raise StageCCandidateSelectionError(
                "Task-17 evidence candidate identity invalid"
            )
        if (
            row.get("eligible_for_model_selection")
            is not EXPECTED_ELIGIBILITY[cid]
        ):
            raise StageCCandidateSelectionError(
                f"Task-17 evidence eligibility changed: {cid}"
            )
        feasible = row.get("primary_constraint_feasible")
        if type(feasible) is not bool:
            raise StageCCandidateSelectionError(
                f"Task-17 feasibility invalid: {cid}"
            )
        if row.get("diagnostic_threshold_is_not_frozen") is not True:
            raise StageCCandidateSelectionError(
                f"Task-17 threshold semantics changed: {cid}"
            )
        recall = row.get("diagnostic_recall")
        fpr = row.get("diagnostic_observed_fpr")
        wilson = row.get("diagnostic_wilson_upper_95")
        if feasible:
            for field, value in (
                ("diagnostic_recall", recall),
                ("diagnostic_observed_fpr", fpr),
                ("diagnostic_wilson_upper_95", wilson),
            ):
                if type(value) not in (int, float) or not math.isfinite(value):
                    raise StageCCandidateSelectionError(
                        f"Task-17 evidence value invalid: {cid}/{field}"
                    )
            if fpr > EXPECTED_PRIMARY_FPR_CAP:
                raise StageCCandidateSelectionError(
                    f"Task-17 evidence FPR exceeds cap: {cid}"
                )
            if wilson > EXPECTED_PRIMARY_FPR_CAP:
                raise StageCCandidateSelectionError(
                    f"Task-17 evidence Wilson upper exceeds cap: {cid}"
                )
        seen.add(cid)
        validated.append(dict(row))

    if tuple(row["candidate_id"] for row in validated) != EXPECTED_CANDIDATES:
        raise StageCCandidateSelectionError(
            "Task-17 evidence candidate order changed"
        )
    return validated


def select_candidate(evidence: list[Mapping[str, Any]]) -> dict[str, Any]:
    pool = [
        row for row in evidence
        if row["eligible_for_model_selection"]
        and row["primary_constraint_feasible"]
    ]
    if not pool:
        raise StageCCandidateSelectionError(
            "no eligible candidate satisfies primary low-FPR constraint"
        )

    max_recall = max(float(row["diagnostic_recall"]) for row in pool)
    winners = [
        row for row in pool
        if float(row["diagnostic_recall"]) == max_recall
    ]
    if len(winners) != 1:
        raise StageCCandidateSelectionError(
            "selection tie at maximum diagnostic recall; fail closed"
        )

    selected = dict(winners[0])
    return {
        "selected_candidate_id": selected["candidate_id"],
        "selected_family": selected["family"],
        "selected_artifact_sha256": selected["artifact_sha256"],
        "selection_objective_value": max_recall,
        "selection_objective_name": "diagnostic_recall",
        "primary_constraint_feasible": True,
        "selection_evidence": {
            "diagnostic_observed_fpr": selected["diagnostic_observed_fpr"],
            "diagnostic_wilson_upper_95": selected[
                "diagnostic_wilson_upper_95"
            ],
            "diagnostic_recall": selected["diagnostic_recall"],
            "diagnostic_fp": selected["diagnostic_fp"],
            "diagnostic_tp": selected["diagnostic_tp"],
            "diagnostic_sweep_sha256": selected[
                "diagnostic_sweep_sha256"
            ],
        },
        "selection_diagnostic_threshold_frozen": False,
        "selection_diagnostic_threshold_authorized_for_calibration": False,
    }


def validate_task12_manifest_and_artifact(
    manifest: Mapping[str, Any],
    *,
    candidate_root: Path,
    selected_candidate_id: str,
    expected_artifact_sha256: str,
) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-candidate-training-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_training_complete": True,
        "candidate_count": 4,
        "candidate_artifact_set_sha256": EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
        "training_manifest_sha256": EXPECTED_TASK12_TRAINING_MANIFEST_SHA256,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise StageCCandidateSelectionError(
                f"Task-12 manifest guard mismatch: {key}"
            )
    if (
        hash_without(manifest, "training_manifest_sha256")
        != EXPECTED_TASK12_TRAINING_MANIFEST_SHA256
    ):
        raise StageCCandidateSelectionError(
            "Task-12 canonical training-manifest hash mismatch"
        )

    artifacts = manifest.get("candidate_artifacts")
    if not isinstance(artifacts, list):
        raise StageCCandidateSelectionError(
            "Task-12 candidate artifacts missing"
        )
    matches = [
        row for row in artifacts
        if isinstance(row, Mapping)
        and row.get("candidate_id") == selected_candidate_id
    ]
    if len(matches) != 1:
        raise StageCCandidateSelectionError(
            "selected Task-12 candidate artifact record missing"
        )
    row = matches[0]
    if row.get("eligible_for_later_selection") is not True:
        raise StageCCandidateSelectionError(
            "selected Task-12 candidate is not selection-eligible"
        )
    artifact_sha = row.get("artifact_sha256")
    artifact_size = row.get("artifact_size_bytes")
    if artifact_sha != expected_artifact_sha256:
        raise StageCCandidateSelectionError(
            "selected artifact SHA differs between Task-12 and Task-17"
        )
    if type(artifact_size) is not int or artifact_size <= 0:
        raise StageCCandidateSelectionError(
            "selected artifact size invalid"
        )

    artifact_path = candidate_root / "artifacts" / f"{selected_candidate_id}.pkl"
    if not artifact_path.is_file():
        raise StageCCandidateSelectionError(
            f"selected candidate artifact missing: {artifact_path}"
        )
    if artifact_path.stat().st_size != artifact_size:
        raise StageCCandidateSelectionError(
            "selected candidate artifact size mismatch"
        )
    if sha256_file(artifact_path) != artifact_sha:
        raise StageCCandidateSelectionError(
            "selected candidate artifact SHA mismatch"
        )

    return {
        "candidate_id": selected_candidate_id,
        "family": row.get("family"),
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_sha,
        "artifact_size_bytes": artifact_size,
        "artifact_format": row.get("artifact_format"),
        "physical_artifact_verified": True,
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_candidate_selection.py",
        "ml/evaluation/select_stage_c_candidate.py",
        "ml/evaluation/stage_c_model_selection_authorization.py",
        "ml/evaluation/stage_c_selection_evaluation.py",
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
            raise StageCCandidateSelectionError("invalid Git HEAD identity")
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
        raise StageCCandidateSelectionError(
            "Task-18 and bound selection files must be committed before selection"
        ) from exc
    if dirty != 0:
        raise StageCCandidateSelectionError(
            "Task-18/bound selection files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task18_module_sha256": sha256_file(repo_root / paths[0]),
        "task18_cli_sha256": sha256_file(repo_root / paths[1]),
        "task17_module_sha256": sha256_file(repo_root / paths[2]),
        "task16_module_sha256": sha256_file(repo_root / paths[3]),
        "task12_module_sha256": sha256_file(repo_root / paths[4]),
    }


def execute_candidate_selection(
    *,
    repo_root: Path,
    authorization_path: Path,
    training_manifest_path: Path,
    candidate_root: Path,
) -> dict[str, Any]:
    auth = load_json(authorization_path)
    manifest = load_json(training_manifest_path)

    evidence = validate_task17_authorization(auth)
    decision = select_candidate(evidence)
    artifact = validate_task12_manifest_and_artifact(
        manifest,
        candidate_root=candidate_root,
        selected_candidate_id=decision["selected_candidate_id"],
        expected_artifact_sha256=decision["selected_artifact_sha256"],
    )
    if artifact["family"] != decision["selected_family"]:
        raise StageCCandidateSelectionError(
            "selected candidate family differs between Task-12 and Task-17"
        )
    git = _git_provenance(repo_root)

    record = {
        "schema_version": SELECTION_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "selection_metrics_computed": True,
        "model_selection_authorized": True,
        "model_selection_performed": True,
        "candidate_selected": True,
        "selected_candidate_id": decision["selected_candidate_id"],
        "selected_candidate_family": decision["selected_family"],
        "selected_candidate_artifact": artifact,
        "selection_policy": {
            "primary_constraint": (
                "OBSERVED_FPR_LTE_0.01_AND_WILSON_UPPER_95_LTE_0.01"
            ),
            "secondary_objective": "MAXIMIZE_DIAGNOSTIC_RECALL",
            "tie_policy": "FAIL_CLOSED_NO_IMPLICIT_TIEBREAKER",
        },
        "selection_result": {
            "selection_objective_name": decision[
                "selection_objective_name"
            ],
            "selection_objective_value": decision[
                "selection_objective_value"
            ],
            "primary_constraint_feasible": True,
            "selection_evidence": decision["selection_evidence"],
            "selection_diagnostic_threshold_frozen": False,
            "selection_diagnostic_threshold_authorized_for_calibration": False,
        },
        "selection_diagnostic_threshold_frozen": False,
        "calibration_access_authorized": False,
        "calibration_scoring_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_frozen": False,
        "final_holdout_touched": False,
        "identity_bindings": {
            "task17_authorization_sha256": EXPECTED_TASK17_AUTHORIZATION_SHA256,
            "task17_selection_evidence_sha256": (
                EXPECTED_TASK17_SELECTION_EVIDENCE_SHA256
            ),
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
            "reuse_selection_diagnostic_threshold_as_calibration_threshold": True,
            "calibration_access": True,
            "calibration_scoring": True,
            "calibration_fitting": True,
            "threshold_freeze": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "ISSUE_STAGE_C_CALIBRATION_SCORING_AUTHORIZATION_FOR_SELECTED_CANDIDATE"
        ),
    }
    record["selection_record_sha256"] = canonical_hash(record)
    return record
