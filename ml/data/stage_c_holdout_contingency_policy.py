"""Stage C Task 26 — freeze final-holdout contingency policy.

This task freezes a deterministic, performance-blind fallback policy for the
Stage-C final holdout. The primary remains CompPhish v3. Backups may be
activated only because of access, availability, licensing, integrity, schema,
or contamination failures — never because model performance is disappointing.

Task 26 does not access, download, score, evaluate, rank by model performance,
or otherwise touch any final-holdout candidate.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

POLICY_SCHEMA = "stage-c-final-holdout-contingency-policy-1"

EXPECTED_TASK25_AUTHORIZATION_SHA256 = (
    "35832fbb13ed28b93120953b8edf8dae997cb107df1116cedaeeffaf2733e59d"
)
EXPECTED_TASK24_PAIR_SHA256 = (
    "25286bcee337d4731eda836f23cf3032c4b9ae0922a3742fa7a15251da5aa0eb"
)

PRIMARY = {
    "candidate_id": "compphish-v3-2026",
    "source_id": "mendeley-fmbs4kp9wz-v3",
    "doi": "10.17632/fmbs4kp9wz.3",
    "license": "CC BY 4.0",
    "expected_class_counts": {"legitimate": 8154, "phishing": 7204},
    "collection_start": "2024-09-01",
    "collection_end": "2025-08-31",
    "raw_html_expected": True,
    "priority": 1,
    "status": "PRIMARY_AUTHORIZED_PENDING_ACQUISITION",
}

FALLBACKS = [
    {
        "candidate_id": "compphish-v4-2026",
        "source_id": "mendeley-fmbs4kp9wz-v4",
        "doi": "10.17632/fmbs4kp9wz.4",
        "license": "CC BY 4.0",
        "reported_class_counts": {"legitimate": 8154, "phishing": 7204},
        "collection_start": "2024-09-01",
        "collection_end": "2025-08-31",
        "raw_html_reported": True,
        "priority": 2,
        "status": "SAME_FAMILY_FALLBACK_REQUIRES_FRESH_QUALIFICATION_AND_SEAL",
    },
    {
        "candidate_id": "phishark-2026",
        "source_id": "phishark-2026-research-release",
        "reported_class_counts": {"legitimate": 27993, "phishing": 25598},
        "collection_start": "2026-04-01",
        "collection_end": "2026-07-31",
        "raw_html_availability": "PER_OBSERVATION_WHEN_AVAILABLE",
        "access": "RESTRICTED_ACADEMIC_DUA",
        "priority": 3,
        "status": "INDEPENDENT_CANDIDATE_REQUIRES_ACCESS_AND_FULL_QUALIFICATION",
    },
    {
        "candidate_id": "phish360",
        "source_id": "phish360-public-release",
        "reported_total_samples": 10748,
        "collection_start": "2020-01-01",
        "collection_end": "2023-12-31",
        "raw_html_reported": True,
        "access": "PUBLIC_DOWNLOAD_ADVERTISED",
        "priority": 4,
        "status": (
            "INDEPENDENT_CANDIDATE_REQUIRES_FULL_QUALIFICATION_"
            "AND_STRICT_FORWARD_SUBSET_OR_EXCEPTION_REVIEW"
        ),
    },
    {
        "candidate_id": "tr-op",
        "source_id": "knowphish-tr-op-release",
        "reported_class_counts": {"legitimate": 5000, "phishing": 5000},
        "priority": 5,
        "status": (
            "INDEPENDENT_CANDIDATE_REQUIRES_CAPTURE_FORMAT_LICENSE_"
            "TEMPORAL_AND_CONTAMINATION_QUALIFICATION"
        ),
    },
]

ALLOWED_ACTIVATION_REASONS = [
    "PRIMARY_REMOTE_METADATA_UNAVAILABLE",
    "PRIMARY_DOWNLOAD_UNAVAILABLE",
    "PRIMARY_PROVIDER_ACCESS_DENIED",
    "PRIMARY_PROVIDER_REJECTED_REQUEST",
    "PRIMARY_LICENSE_NO_LONGER_ACCEPTABLE",
    "PRIMARY_INTEGRITY_VERIFICATION_FAILED",
    "PRIMARY_SCHEMA_INCOMPATIBLE",
    "PRIMARY_CONTAMINATION_DETECTED",
]

REQUIRED_BACKUP_GATES = [
    "LICENSE_ACCEPTABLE",
    "PINNED_VERSION_OR_IMMUTABLE_RELEASE",
    "RAW_HTML_OR_REPLAY_COMPATIBLE_CAPTURE_AVAILABLE",
    "LEGITIMATE_COUNT_AT_LEAST_381",
    "PHISHING_COUNT_AT_LEAST_1",
    "INDEPENDENT_FROM_STAGE_C_DEVELOPMENT_SOURCE",
    "NO_OVERLAP_WITH_STAGE_C_DEVELOPMENT",
    "NO_OVERLAP_WITH_CONSUMED_STAGE_B_FINAL_TEST",
    "TEMPORAL_REQUIREMENT_SATISFIED_OR_EXPLICITLY_REVIEWED",
    "REMOTE_FILE_INVENTORY_FROZEN",
    "DOWNLOAD_MANIFEST_FROZEN",
    "LOCAL_ARCHIVE_SHA256_AND_SIZE_SEALED",
    "SCHEMA_VERIFIED",
    "CONTAMINATION_AUDIT_PASSED",
]

PROHIBITED_SELECTION_SIGNALS = [
    "MODEL_ACCURACY",
    "MODEL_PRECISION",
    "MODEL_RECALL",
    "MODEL_F1",
    "MODEL_FALSE_POSITIVE_RATE",
    "MODEL_ROC_AUC",
    "MODEL_AVERAGE_PRECISION",
    "MODEL_BRIER_SCORE",
    "MODEL_LOG_LOSS",
    "MODEL_SCORE_DISTRIBUTION",
    "WHICH_HOLDOUT_MAKES_MODEL_LOOK_BEST",
]


class StageCHoldoutContingencyPolicyError(ValueError):
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
        raise StageCHoldoutContingencyPolicyError(
            f"required JSON file not found: {path}"
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StageCHoldoutContingencyPolicyError(
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
            raise StageCHoldoutContingencyPolicyError(
                f"refusing to replace non-identical frozen Task-26 output: {path}"
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


def validate_task25_authorization(auth: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-final-holdout-acquisition-authorization-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_selected": True,
        "threshold_frozen": True,
        "final_holdout_touched": False,
        "final_holdout_acquisition_authorized": True,
        "final_holdout_download_authorized": True,
        "final_holdout_feature_extraction_authorized": False,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_metrics_authorized": False,
        "authorization_sha256": EXPECTED_TASK25_AUTHORIZATION_SHA256,
        "next_gate": (
            "FREEZE_STAGE_C_FINAL_HOLDOUT_REMOTE_INVENTORY_AND_DOWNLOAD_MANIFEST"
        ),
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCHoldoutContingencyPolicyError(
                f"Task-25 authorization guard mismatch: {key}"
            )
    if (
        hash_without(auth, "authorization_sha256")
        != EXPECTED_TASK25_AUTHORIZATION_SHA256
    ):
        raise StageCHoldoutContingencyPolicyError(
            "Task-25 canonical authorization hash mismatch"
        )

    point = auth.get("frozen_operating_point")
    scope = auth.get("final_holdout_scope")
    prohibitions = auth.get("prohibitions")
    if not all(isinstance(x, Mapping) for x in (point, scope, prohibitions)):
        raise StageCHoldoutContingencyPolicyError(
            "Task-25 authorization sections missing"
        )
    checks = [
        (
            point.get("candidate_threshold_pair_sha256")
            == EXPECTED_TASK24_PAIR_SHA256,
            "candidate-threshold pair",
        ),
        (scope.get("candidate_id") == PRIMARY["candidate_id"], "primary candidate"),
        (scope.get("source_id") == PRIMARY["source_id"], "primary source"),
        (scope.get("doi") == PRIMARY["doi"], "primary DOI"),
        (scope.get("license") == PRIMARY["license"], "primary license"),
        (
            scope.get("expected_class_counts") == PRIMARY["expected_class_counts"],
            "primary counts",
        ),
        (prohibitions.get("model_scoring") is True, "model-scoring lock"),
        (prohibitions.get("metric_computation") is True, "metric lock"),
        (prohibitions.get("error_analysis") is True, "error-analysis lock"),
        (prohibitions.get("threshold_change") is True, "threshold-change lock"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCHoldoutContingencyPolicyError(
                f"Task-25 authorization changed: {name}"
            )


def validate_policy_constants() -> None:
    priorities = [PRIMARY["priority"]] + [x["priority"] for x in FALLBACKS]
    if priorities != sorted(priorities) or len(set(priorities)) != len(priorities):
        raise StageCHoldoutContingencyPolicyError(
            "holdout priorities must be unique and increasing"
        )
    ids = [PRIMARY["candidate_id"]] + [x["candidate_id"] for x in FALLBACKS]
    if len(ids) != len(set(ids)):
        raise StageCHoldoutContingencyPolicyError(
            "duplicate holdout candidate id"
        )
    if PRIMARY["expected_class_counts"]["legitimate"] < 381:
        raise StageCHoldoutContingencyPolicyError(
            "primary holdout legitimate count below protocol minimum"
        )
    if PRIMARY["expected_class_counts"]["phishing"] < 1:
        raise StageCHoldoutContingencyPolicyError(
            "primary holdout phishing count invalid"
        )
    if not ALLOWED_ACTIVATION_REASONS:
        raise StageCHoldoutContingencyPolicyError(
            "fallback activation reasons missing"
        )
    if not REQUIRED_BACKUP_GATES:
        raise StageCHoldoutContingencyPolicyError(
            "backup qualification gates missing"
        )
    if not PROHIBITED_SELECTION_SIGNALS:
        raise StageCHoldoutContingencyPolicyError(
            "performance-selection prohibitions missing"
        )


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_holdout_contingency_policy.py",
        "ml/data/freeze_stage_c_holdout_contingency_policy.py",
        "ml/data/stage_c_final_holdout_acquisition_authorization.py",
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
            raise StageCHoldoutContingencyPolicyError(
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
        raise StageCHoldoutContingencyPolicyError(
            "Task-26 and bound files must be committed before policy freeze"
        ) from exc
    if dirty != 0:
        raise StageCHoldoutContingencyPolicyError(
            "Task-26/bound files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task26_module_sha256": sha256_file(repo_root / paths[0]),
        "task26_cli_sha256": sha256_file(repo_root / paths[1]),
        "task25_module_sha256": sha256_file(repo_root / paths[2]),
    }


def freeze_holdout_contingency_policy(
    *,
    repo_root: Path,
    task25_authorization_path: Path,
) -> dict[str, Any]:
    auth = load_json(task25_authorization_path)
    validate_task25_authorization(auth)
    validate_policy_constants()
    git = _git_provenance(repo_root)

    selection_policy = {
        "primary": PRIMARY,
        "fallbacks_in_priority_order": FALLBACKS,
        "allowed_activation_reasons": ALLOWED_ACTIVATION_REASONS,
        "required_backup_qualification_gates": REQUIRED_BACKUP_GATES,
        "prohibited_selection_signals": PROHIBITED_SELECTION_SIGNALS,
        "selection_algorithm": (
            "USE_PRIMARY_IF_ACQUIRABLE_AND_QUALIFIED_ELSE_FIRST_FALLBACK_"
            "IN_PRIORITY_ORDER_THAT_PASSES_ALL_REQUIRED_GATES"
        ),
        "performance_blind_selection_required": True,
        "evaluate_multiple_holdouts_then_choose_best": False,
        "switch_after_evaluation_due_to_bad_model_results": False,
        "backup_model_scoring_before_activation": False,
        "backup_label_metric_access_before_activation": False,
    }

    policy = {
        "schema_version": POLICY_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_threshold_pair_frozen": True,
        "candidate_threshold_pair_sha256": EXPECTED_TASK24_PAIR_SHA256,
        "primary_final_holdout_candidate_id": PRIMARY["candidate_id"],
        "primary_final_holdout_still_active": True,
        "fallback_policy_frozen": True,
        "fallback_activated": False,
        "active_fallback_candidate_id": None,
        "final_holdout_touched": False,
        "model_scoring_authorized": False,
        "metric_computation_authorized": False,
        "error_analysis_authorized": False,
        "selection_policy": selection_policy,
        "policy_evidence_sha256": canonical_hash(selection_policy),
        "identity_bindings": {
            "task25_authorization_sha256": EXPECTED_TASK25_AUTHORIZATION_SHA256,
            "candidate_threshold_pair_sha256": EXPECTED_TASK24_PAIR_SHA256,
            **git,
        },
        "prohibitions": {
            "performance_based_holdout_selection": True,
            "score_backup_before_activation": True,
            "metric_access_before_activation": True,
            "switch_holdout_after_bad_result": True,
            "threshold_change": True,
            "model_refit": True,
            "deployment": True,
        },
        "next_gate": (
            "ATTEMPT_PRIMARY_FINAL_HOLDOUT_ACQUISITION_OR_ACTIVATE_"
            "PRECOMMITTED_FALLBACK"
        ),
    }
    policy["contingency_policy_sha256"] = canonical_hash(policy)
    return policy
