"""Stage C Task 27 — freeze primary holdout public-availability evidence.

This task binds the Task-26 contingency policy and freezes the externally
verified public landing-page evidence for CompPhish v3. It does not claim a
cryptographic remote manifest because the authenticated API/file-UUID path has
not been established.

The decision is therefore limited to:
  PRIMARY_PUBLICLY_AVAILABLE_FOR_MANUAL_ACQUISITION

No final-holdout bytes are downloaded or inspected by this task. No features,
scores, labels, metrics, error analysis, threshold changes, or deployment are
authorized.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

EVIDENCE_SCHEMA = "stage-c-primary-holdout-availability-evidence-1"

EXPECTED_TASK26_POLICY_SHA256 = (
    "dd7a3e9c9abc5040fa857564a8413903a94a2597f3d5c8589655f55abae522d8"
)
EXPECTED_TASK26_POLICY_EVIDENCE_SHA256 = (
    "dca1526ff1a583210dcc3a4901a2332761762a2d7b40ba7f05956a7cc727f747"
)
EXPECTED_TASK25_AUTHORIZATION_SHA256 = (
    "35832fbb13ed28b93120953b8edf8dae997cb107df1116cedaeeffaf2733e59d"
)

PRIMARY_CANDIDATE_ID = "compphish-v3-2026"
PRIMARY_SOURCE_ID = "mendeley-fmbs4kp9wz-v3"
PRIMARY_DOI = "10.17632/fmbs4kp9wz.3"
PRIMARY_LANDING_PAGE = "https://data.mendeley.com/datasets/fmbs4kp9wz/3"
PRIMARY_VERSION = 3
PRIMARY_PUBLISHED_DATE = "2026-07-08"
PRIMARY_LICENSE = "CC BY 4.0"
PRIMARY_CLASS_COUNTS = {"legitimate": 8154, "phishing": 7204}
PRIMARY_TOTAL = 15358
PRIMARY_COLLECTION_PERIOD = {
    "start": "2024-09-01",
    "end": "2025-08-31",
}

PUBLIC_FILE_INVENTORY_DISPLAY = [
    {
        "name": "All_Features_threshold90.xlsx",
        "display_size": "4.51 MB",
        "role": "PROCESSED_FEATURES_NOT_USED_FOR_STAGE_C_FINAL_SCORING",
    },
    {
        "name": "All_HTML.zip",
        "display_size": "692 MB",
        "role": "PRIMARY_RAW_HTML_ARCHIVE_REQUIRED",
    },
    {
        "name": "Data_Dictionary.xlsx",
        "display_size": "17.6 KB",
        "role": "DOCUMENTATION",
    },
    {
        "name": "dataset Creator.zip",
        "display_size": "9.48 KB",
        "role": "PROVENANCE_SOURCE_CODE",
    },
    {
        "name": "feature extractor.zip",
        "display_size": "33 KB",
        "role": "PROVENANCE_SOURCE_CODE_NOT_USED_FOR_STAGE_C_FEATURES",
    },
    {
        "name": "Mapping_File.xlsx",
        "display_size": "621 KB",
        "role": "LABEL_AND_HTML_MAPPING_REQUIRED",
    },
    {
        "name": "Readme.docx",
        "display_size": "17.9 KB",
        "role": "DOCUMENTATION",
    },
    {
        "name": "requirements.txt.txt",
        "display_size": "166 B",
        "role": "DOCUMENTATION",
    },
]

PUBLIC_EVIDENCE = {
    "observed_date": "2026-09-28",
    "landing_page": PRIMARY_LANDING_PAGE,
    "page_reachable": True,
    "download_all_control_visible": True,
    "version": PRIMARY_VERSION,
    "published_date": PRIMARY_PUBLISHED_DATE,
    "doi": PRIMARY_DOI,
    "license": PRIMARY_LICENSE,
    "sample_count": PRIMARY_TOTAL,
    "class_counts": PRIMARY_CLASS_COUNTS,
    "collection_period": PRIMARY_COLLECTION_PERIOD,
    "raw_html_described": True,
    "raw_html_archive_name": "All_HTML.zip",
    "mapping_file_name": "Mapping_File.xlsx",
    "file_inventory_display": PUBLIC_FILE_INVENTORY_DISPLAY,
    "remote_file_uuids_frozen": False,
    "remote_file_sha256_frozen": False,
    "authenticated_api_inventory_available": False,
}

DECISION = "PRIMARY_PUBLICLY_AVAILABLE_FOR_MANUAL_ACQUISITION"


class StageCPrimaryHoldoutAvailabilityError(ValueError):
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
        raise StageCPrimaryHoldoutAvailabilityError(
            f"required JSON file not found: {path}"
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StageCPrimaryHoldoutAvailabilityError(
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
            raise StageCPrimaryHoldoutAvailabilityError(
                f"refusing to replace non-identical frozen Task-27 output: {path}"
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


def validate_task26_policy(policy: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-final-holdout-contingency-policy-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_threshold_pair_frozen": True,
        "primary_final_holdout_candidate_id": PRIMARY_CANDIDATE_ID,
        "primary_final_holdout_still_active": True,
        "fallback_policy_frozen": True,
        "fallback_activated": False,
        "active_fallback_candidate_id": None,
        "final_holdout_touched": False,
        "model_scoring_authorized": False,
        "metric_computation_authorized": False,
        "error_analysis_authorized": False,
        "policy_evidence_sha256": EXPECTED_TASK26_POLICY_EVIDENCE_SHA256,
        "contingency_policy_sha256": EXPECTED_TASK26_POLICY_SHA256,
        "next_gate": (
            "ATTEMPT_PRIMARY_FINAL_HOLDOUT_ACQUISITION_OR_ACTIVATE_"
            "PRECOMMITTED_FALLBACK"
        ),
    }
    for key, value in expected.items():
        if policy.get(key) != value:
            raise StageCPrimaryHoldoutAvailabilityError(
                f"Task-26 policy guard mismatch: {key}"
            )
    if (
        hash_without(policy, "contingency_policy_sha256")
        != EXPECTED_TASK26_POLICY_SHA256
    ):
        raise StageCPrimaryHoldoutAvailabilityError(
            "Task-26 canonical policy hash mismatch"
        )

    selection = policy.get("selection_policy")
    bindings = policy.get("identity_bindings")
    prohibitions = policy.get("prohibitions")
    if not all(isinstance(x, Mapping) for x in (selection, bindings, prohibitions)):
        raise StageCPrimaryHoldoutAvailabilityError(
            "Task-26 policy sections missing"
        )
    primary = selection.get("primary")
    if not isinstance(primary, Mapping):
        raise StageCPrimaryHoldoutAvailabilityError(
            "Task-26 primary holdout missing"
        )

    checks = [
        (primary.get("candidate_id") == PRIMARY_CANDIDATE_ID, "candidate"),
        (primary.get("source_id") == PRIMARY_SOURCE_ID, "source"),
        (primary.get("doi") == PRIMARY_DOI, "DOI"),
        (primary.get("license") == PRIMARY_LICENSE, "license"),
        (
            primary.get("expected_class_counts") == PRIMARY_CLASS_COUNTS,
            "class counts",
        ),
        (primary.get("raw_html_expected") is True, "raw HTML expectation"),
        (selection.get("performance_blind_selection_required") is True, "performance-blind rule"),
        (selection.get("evaluate_multiple_holdouts_then_choose_best") is False, "multi-holdout selection lock"),
        (selection.get("switch_after_evaluation_due_to_bad_model_results") is False, "post-result switch lock"),
        (bindings.get("task25_authorization_sha256") == EXPECTED_TASK25_AUTHORIZATION_SHA256, "Task-25 binding"),
        (prohibitions.get("performance_based_holdout_selection") is True, "performance-selection prohibition"),
        (prohibitions.get("score_backup_before_activation") is True, "backup-scoring prohibition"),
        (prohibitions.get("threshold_change") is True, "threshold-change prohibition"),
        (prohibitions.get("model_refit") is True, "refit prohibition"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCPrimaryHoldoutAvailabilityError(
                f"Task-26 policy changed: {name}"
            )


def validate_public_evidence() -> None:
    e = PUBLIC_EVIDENCE
    checks = [
        (e["page_reachable"] is True, "page reachability"),
        (e["download_all_control_visible"] is True, "download control"),
        (e["version"] == 3, "version"),
        (e["doi"] == PRIMARY_DOI, "DOI"),
        (e["license"] == PRIMARY_LICENSE, "license"),
        (e["sample_count"] == PRIMARY_TOTAL, "sample count"),
        (e["class_counts"] == PRIMARY_CLASS_COUNTS, "class counts"),
        (e["raw_html_described"] is True, "raw HTML"),
        (e["raw_html_archive_name"] == "All_HTML.zip", "HTML archive"),
        (e["mapping_file_name"] == "Mapping_File.xlsx", "mapping file"),
        (e["remote_file_uuids_frozen"] is False, "remote UUID state"),
        (e["remote_file_sha256_frozen"] is False, "remote hash state"),
        (e["authenticated_api_inventory_available"] is False, "API inventory state"),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCPrimaryHoldoutAvailabilityError(
                f"public availability evidence invalid: {name}"
            )

    names = {row["name"] for row in PUBLIC_FILE_INVENTORY_DISPLAY}
    if "All_HTML.zip" not in names or "Mapping_File.xlsx" not in names:
        raise StageCPrimaryHoldoutAvailabilityError(
            "required public file names absent"
        )


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_primary_holdout_availability.py",
        "ml/data/freeze_stage_c_primary_holdout_availability.py",
        "ml/data/stage_c_holdout_contingency_policy.py",
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
            raise StageCPrimaryHoldoutAvailabilityError(
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
        raise StageCPrimaryHoldoutAvailabilityError(
            "Task-27 and bound files must be committed before evidence freeze"
        ) from exc
    if dirty != 0:
        raise StageCPrimaryHoldoutAvailabilityError(
            "Task-27/bound files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task27_module_sha256": sha256_file(repo_root / paths[0]),
        "task27_cli_sha256": sha256_file(repo_root / paths[1]),
        "task26_module_sha256": sha256_file(repo_root / paths[2]),
    }


def freeze_primary_holdout_availability(
    *,
    repo_root: Path,
    contingency_policy_path: Path,
) -> dict[str, Any]:
    policy = load_json(contingency_policy_path)
    validate_task26_policy(policy)
    validate_public_evidence()
    git = _git_provenance(repo_root)

    evidence_identity = {
        "candidate_id": PRIMARY_CANDIDATE_ID,
        "source_id": PRIMARY_SOURCE_ID,
        "public_evidence": PUBLIC_EVIDENCE,
        "decision": DECISION,
    }

    report = {
        "schema_version": EVIDENCE_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "primary_candidate_id": PRIMARY_CANDIDATE_ID,
        "primary_source_id": PRIMARY_SOURCE_ID,
        "primary_still_active": True,
        "fallback_activated": False,
        "availability_decision": DECISION,
        "public_availability_evidence": PUBLIC_EVIDENCE,
        "public_evidence_sha256": canonical_hash(evidence_identity),
        "remote_inventory_cryptographically_frozen": False,
        "download_manifest_cryptographically_frozen": False,
        "manual_download_required": True,
        "required_local_artifacts": [
            "All_HTML.zip",
            "Mapping_File.xlsx",
        ],
        "optional_supporting_artifacts": [
            "Readme.docx",
            "Data_Dictionary.xlsx",
            "requirements.txt.txt",
        ],
        "local_integrity_seal_required_before_feature_extraction": True,
        "local_schema_verification_required_before_feature_extraction": True,
        "final_holdout_touched": False,
        "final_holdout_feature_extraction_authorized": False,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_metrics_authorized": False,
        "identity_bindings": {
            "task26_contingency_policy_sha256": EXPECTED_TASK26_POLICY_SHA256,
            "task26_policy_evidence_sha256": EXPECTED_TASK26_POLICY_EVIDENCE_SHA256,
            **git,
        },
        "prohibitions": {
            "treat_display_file_sizes_as_integrity_hashes": True,
            "feature_extraction_before_local_seal": True,
            "model_scoring_before_local_seal": True,
            "label_metric_access_before_scoring_freeze": True,
            "threshold_change": True,
            "model_refit": True,
            "fallback_activation_while_primary_download_is_available": True,
            "deployment": True,
        },
        "next_gate": (
            "MANUALLY_DOWNLOAD_COMPPHISH_V3_AND_FREEZE_LOCAL_INTEGRITY_SEAL"
        ),
    }
    report["availability_report_sha256"] = canonical_hash(report)
    return report
