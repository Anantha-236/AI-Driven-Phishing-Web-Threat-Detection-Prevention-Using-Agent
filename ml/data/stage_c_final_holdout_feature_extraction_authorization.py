"""Stage C Task 31 — authorize production feature extraction on the clean final holdout.

This task issues authorization only. It does not open the HTML archive, replay
pages, load a model, score samples, compute final metrics, or modify the frozen
candidate/threshold operating point.

The authorization is bound to:
- Task-24 frozen candidate + threshold;
- Task-28 sealed CompPhish v3 local bytes;
- Task-29 frozen final-holdout identities;
- Task-30 contamination-quarantined/deduplicated clean set;
- Task-9 production context-features-1 order and extractor identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-final-holdout-feature-extraction-authorization-1"

EXPECTED_TASK30_GIT_HEAD = "e7e681836bb0c75760d61a91749f816d23637e80"
EXPECTED_CLEAN_SAMPLE_COUNT = 12711
EXPECTED_CLEAN_CLASS_COUNTS = {"legitimate": 7609, "phishing": 5102}
EXPECTED_CLEAN_SAMPLE_SET_SHA256 = (
    "451a45d56def6a70f3e7dc304e610a95691a7317315e374d5dff69721876ed7c"
)
EXPECTED_CLEAN_RECORD_SET_SHA256 = (
    "420b0ab542b4aa488fabecc41494f5f55392698f08c299a1a005b80e93753035"
)
EXPECTED_TASK29_RECORD_SET_SHA256 = (
    "30712d728fdaee1681bf227018ea953a5f52c490ea0e560cf49d257c04609167"
)
EXPECTED_TASK29_INDEX_IDENTITY_SHA256 = (
    "4c3171b1ee2e342a5542b73c58acc8cffc98ac902870fd45b2f4b41b794966c1"
)
EXPECTED_STAGE_C_DEVELOPMENT_RECORD_SET_SHA256 = (
    "65b5feeaa44a44511581f4d4d065aa6daaa70d7376088f591a2a1d3eba09cdd9"
)
EXPECTED_STAGE_B_TEST_PARTITION_SHA256 = (
    "a7d83608610370f7772ee2820bdf0229cd14e97c6f18143130125c7db7a4fd2d"
)

EXPECTED_TASK24_THRESHOLD_FREEZE_SHA256 = (
    "081a36b04e1f319081e84ab23172bd633d799877b58db27a33d80f8087b617ee"
)
EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256 = (
    "25286bcee337d4731eda836f23cf3032c4b9ae0922a3742fa7a15251da5aa0eb"
)
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_ARTIFACT_SHA256 = (
    "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"
)
EXPECTED_THRESHOLD = 0.8637646437995518

EXPECTED_TASK28_SEAL_SHA256 = (
    "bfd50f0ded9819f8212c285e4a9821834b3c67beff79d56cdc8c43d1c602199a"
)
EXPECTED_TASK28_ARTIFACT_SET_SHA256 = (
    "15bb4b7c1ad8536b68b88a64fbd2ea8bc68de49805a25c53df57cfbc0919724f"
)
EXPECTED_HTML_ARCHIVE_SHA256 = (
    "12440e4f911fabf4ec2c712ae014cb43e638e9a6adc6c7c6a506a8a7df24fcf7"
)
EXPECTED_MAPPING_WORKBOOK_SHA256 = (
    "e6dda6a21d925f8aba36090f295b08e9808a5dfe8dd3276bf8cd82022855f14a"
)

EXPECTED_TASK9_AUTHORIZATION_SHA256 = (
    "b83f7038a98704465b4097b7f0b54d3ae62f9d72caa5ec31eb82b4d031bda27b"
)
EXPECTED_FEATURE_CONTRACT_SHA256 = (
    "2ee75478749e347f84e97b6fb8911a5b961019be6e282b28792a3e70b0c95a6b"
)
EXPECTED_EXTRACTOR_SOURCE_SHA256 = (
    "6378a55363653da12a101f1cdae33a8b53313d20aee8db95e1deb21fe1e57d74"
)
EXPECTED_FEATURES = [
    "document_started",
    "has_password",
    "has_otp",
    "has_payment",
    "has_identity",
    "purpose_authentication",
    "purpose_payment",
    "purpose_unknown",
    "sensitive_form_count",
    "same_origin_sensitive_target",
    "cross_origin_sensitive_target",
    "stable_sensitive_target",
    "sensitive_target_changed",
    "target_changed_after_interaction",
    "submission_target_mismatch",
    "https_downgrade_sensitive_target",
    "password_then_otp",
    "dynamic_sensitive_field",
    "foreign_frame_sensitive_field",
    "cross_request_near_interaction",
    "unknown_document_ratio",
    "known_target_ratio",
    "contradiction_count",
    "positive_evidence_count",
    "purpose_sensitive_mismatch",
    "purpose_context_consistent",
    "purpose_observed",
]


class StageCFinalHoldoutFeatureAuthorizationError(ValueError):
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


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFinalHoldoutFeatureAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCFinalHoldoutFeatureAuthorizationError(
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
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"refusing to replace non-identical frozen Task-31 output: {path}"
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


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _require_sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            f"invalid SHA-256 field: {field}"
        )
    try:
        int(value, 16)
    except ValueError as exc:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            f"invalid SHA-256 field: {field}"
        ) from exc
    return value.lower()


def validate_clean_set(clean: Mapping[str, Any]) -> list[dict[str, Any]]:
    expected = {
        "schema_version": "stage-c-final-holdout-clean-evaluation-set-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT_CLEAN_EVALUATION_SUBSET",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
        "class_counts": EXPECTED_CLEAN_CLASS_COUNTS,
        "selection_basis": "IDENTITY_ONLY_NO_MODEL_SCORE_NO_MODEL_PERFORMANCE",
        "deduplication_rule": (
            "ONE_LEXICOGRAPHICALLY_SMALLEST_SAMPLE_ID_PER_CONNECTED_COMPONENT_"
            "OF_EXACT_HTML_OR_SAME_LABEL_NORMALIZED_URL"
        ),
        "cross_label_exact_html_policy": (
            "QUARANTINE_ENTIRE_CONFLICTING_EXACT_HTML_COMPONENT_NO_RELABELING"
        ),
        "contamination_quarantine_applied": True,
        "model_scoring_performed": False,
        "features_extracted": False,
        "metrics_computed": False,
        "sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
        "record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
        "next_gate": (
            "AUTHORIZE_STAGE_C_FINAL_HOLDOUT_FEATURE_EXTRACTION_ON_"
            "CLEAN_IDENTITY_SUBSET"
        ),
    }
    for key, value in expected.items():
        if clean.get(key) != value:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-30 clean-set guard mismatch: {key}"
            )

    records = clean.get("records")
    if not isinstance(records, list) or len(records) != EXPECTED_CLEAN_SAMPLE_COUNT:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 clean-set records missing or incomplete"
        )
    if canonical_hash(records) != EXPECTED_CLEAN_RECORD_SET_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 clean record-set hash mismatch"
        )
    if canonical_hash([row.get("sample_id") for row in records]) != (
        EXPECTED_CLEAN_SAMPLE_SET_SHA256
    ):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 clean sample-set hash mismatch"
        )

    labels = {0: 0, 1: 0}
    seen_ids = set()
    seen_html = set()
    for row in records:
        if not isinstance(row, Mapping):
            raise StageCFinalHoldoutFeatureAuthorizationError(
                "invalid Task-30 clean record"
            )
        sample_id = row.get("sample_id")
        label = row.get("label")
        html = row.get("html_sha256")
        member = row.get("html_member_name")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen_ids:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                "clean sample_id missing or duplicated"
            )
        if label not in (0, 1):
            raise StageCFinalHoldoutFeatureAuthorizationError(
                "clean label invalid"
            )
        if not isinstance(member, str) or not member:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                "clean HTML locator missing"
            )
        _require_sha(html, "clean.html_sha256")
        if html in seen_html:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                "clean set still contains duplicate exact HTML"
            )
        seen_ids.add(sample_id)
        seen_html.add(html)
        labels[label] += 1

    if labels != {0: 7609, 1: 5102}:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            f"clean class counts changed: {labels}"
        )

    core = {
        "candidate_id": clean.get("candidate_id"),
        "source_id": clean.get("source_id"),
        "doi": clean.get("doi"),
        "sample_count": clean.get("sample_count"),
        "class_counts": clean.get("class_counts"),
        "records": records,
    }
    embedded_identity = _require_sha(
        clean.get("clean_set_identity_sha256"),
        "clean.clean_set_identity_sha256",
    )
    if canonical_hash(core) != embedded_identity:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 clean-set identity hash mismatch"
        )

    bindings = clean.get("identity_bindings")
    if not isinstance(bindings, Mapping):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 clean-set identity bindings missing"
        )
    required_bindings = {
        "task29_record_set_sha256": EXPECTED_TASK29_RECORD_SET_SHA256,
        "task29_index_identity_sha256": EXPECTED_TASK29_INDEX_IDENTITY_SHA256,
        "stage_c_development_record_set_sha256": (
            EXPECTED_STAGE_C_DEVELOPMENT_RECORD_SET_SHA256
        ),
        "consumed_stage_b_test_partition_sha256": (
            EXPECTED_STAGE_B_TEST_PARTITION_SHA256
        ),
        "git_head": EXPECTED_TASK30_GIT_HEAD,
    }
    for key, value in required_bindings.items():
        if bindings.get(key) != value:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-30 clean-set binding mismatch: {key}"
            )

    return [dict(row) for row in records]


def validate_task30_audit(audit: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-final-holdout-contamination-audit-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "audit_mode": "IDENTITY_CONTAMINATION_AND_DUPLICATE_WEIGHT_AUDIT_ONLY",
        "research_only": True,
        "deployment_authorized": False,
        "original_final_holdout_samples": 15358,
        "identity_component_count": 13100,
        "eligible_clean_samples": EXPECTED_CLEAN_SAMPLE_COUNT,
        "eligible_clean_class_counts": EXPECTED_CLEAN_CLASS_COUNTS,
        "quarantined_sample_count": 636,
        "hard_overlap_sample_counts": {
            "EXACT_HTML_CROSS_LABEL_CONFLICT_WITHIN_HOLDOUT": 241,
            "NORMALIZED_URL_OVERLAP_STAGE_C_DEVELOPMENT": 395,
        },
        "duplicate_rows_removed_from_clean_weighting": 2011,
        "cross_label_identity_conflict_components": 8,
        "cross_label_identity_conflict_samples": 241,
        "cross_label_identity_conflict_policy": (
            "QUARANTINE_ENTIRE_CONFLICTING_EXACT_HTML_COMPONENT_NO_RELABELING"
        ),
        "wilson_resolution_minimum_legitimate_satisfied": True,
        "recommended_final_scale_satisfied": True,
        "raw_urls_emitted": False,
        "model_loaded": False,
        "model_scoring_performed": False,
        "features_extracted": False,
        "metrics_computed": False,
        "threshold_changed": False,
        "model_refit": False,
        "clean_sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
        "clean_record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
        "next_gate": (
            "AUTHORIZE_STAGE_C_FINAL_HOLDOUT_FEATURE_EXTRACTION_ON_"
            "CLEAN_IDENTITY_SUBSET"
        ),
    }
    for key, value in expected.items():
        if audit.get(key) != value:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-30 audit guard mismatch: {key}"
            )

    quarantine = audit.get("quarantine_records")
    if not isinstance(quarantine, list):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 quarantine records missing"
        )
    if sum(int(row.get("sample_count", -1)) for row in quarantine) != 636:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-30 quarantine sample accounting changed"
        )


def validate_threshold_freeze(record: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-threshold-freeze-record-1",
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
        "threshold_freeze_record_sha256": EXPECTED_TASK24_THRESHOLD_FREEZE_SHA256,
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-24 threshold-freeze guard mismatch: {key}"
            )
    if hash_without(
        record, "threshold_freeze_record_sha256"
    ) != EXPECTED_TASK24_THRESHOLD_FREEZE_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-24 canonical threshold-freeze hash mismatch"
        )

    point = record.get("frozen_operating_point")
    if not isinstance(point, Mapping):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-24 frozen operating point missing"
        )
    checks = [
        (
            point.get("candidate_threshold_pair_sha256")
            == EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
            "candidate-threshold pair",
        ),
        (point.get("candidate_id") == EXPECTED_SELECTED_CANDIDATE_ID, "candidate"),
        (
            point.get("artifact_sha256") == EXPECTED_SELECTED_ARTIFACT_SHA256,
            "artifact",
        ),
        (point.get("threshold") == EXPECTED_THRESHOLD, "threshold"),
        (
            point.get("threshold_rule")
            == "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
            "threshold rule",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-24 operating point changed: {name}"
            )


def validate_task28_seal(seal: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-final-holdout-local-integrity-seal-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "candidate_id": "compphish-v3-2026",
        "source_id": "mendeley-fmbs4kp9wz-v3",
        "doi": "10.17632/fmbs4kp9wz.3",
        "expected_sample_count": 15358,
        "local_integrity_seal_complete": True,
        "html_archive_integrity_passed": True,
        "mapping_container_integrity_passed": True,
        "local_artifact_set_sha256": EXPECTED_TASK28_ARTIFACT_SET_SHA256,
        "local_integrity_seal_sha256": EXPECTED_TASK28_SEAL_SHA256,
    }
    for key, value in expected.items():
        if seal.get(key) != value:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-28 seal guard mismatch: {key}"
            )
    if hash_without(
        seal, "local_integrity_seal_sha256"
    ) != EXPECTED_TASK28_SEAL_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-28 canonical seal hash mismatch"
        )
    artifacts = seal.get("local_artifacts")
    if not isinstance(artifacts, Mapping):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-28 artifact identities missing"
        )
    html = artifacts.get("html_archive")
    mapping = artifacts.get("mapping_workbook")
    if not isinstance(html, Mapping) or not isinstance(mapping, Mapping):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-28 artifact sections missing"
        )
    if html.get("sha256") != EXPECTED_HTML_ARCHIVE_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-28 HTML archive identity changed"
        )
    if mapping.get("sha256") != EXPECTED_MAPPING_WORKBOOK_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-28 mapping identity changed"
        )


def validate_task9_feature_authorization(auth: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-feature-extraction-authorization-2",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
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
    }
    for key, value in expected.items():
        if auth.get(key) != value:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-9 feature authorization guard mismatch: {key}"
            )
    if hash_without(auth, "authorization_sha256") != EXPECTED_TASK9_AUTHORIZATION_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-9 canonical authorization hash mismatch"
        )

    feature = auth.get("feature_contract")
    if not isinstance(feature, Mapping):
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-9 feature contract missing"
        )
    checks = [
        (feature.get("source_feature_version") == "context-features-1", "version"),
        (feature.get("feature_count") == 27, "count"),
        (feature.get("ordered_features") == EXPECTED_FEATURES, "order"),
        (
            feature.get("feature_contract_sha256")
            == EXPECTED_FEATURE_CONTRACT_SHA256,
            "contract SHA",
        ),
        (
            feature.get("extractor_source_sha256")
            == EXPECTED_EXTRACTOR_SOURCE_SHA256,
            "extractor SHA",
        ),
        (
            feature.get("order_source")
            == "PRODUCTION_TSFEG_CONTEXT_FEATURES_EXPORT",
            "order source",
        ),
        (
            feature.get("raw_html_persistence_in_feature_output_authorized") is False,
            "raw HTML persistence",
        ),
        (
            feature.get("raw_url_persistence_in_feature_output_authorized") is False,
            "raw URL persistence",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCFinalHoldoutFeatureAuthorizationError(
                f"Task-9 feature contract changed: {name}"
            )
    return dict(feature)


def validate_live_extractor(repo_root: Path) -> None:
    tsfeg = repo_root / "browser-extension" / "src" / "core" / "tsfeg.ts"
    if not tsfeg.is_file():
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "production TSFEG extractor missing"
        )
    if sha256_file(tsfeg) != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "production TSFEG source differs from frozen Task-9 extractor"
        )


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_final_holdout_feature_extraction_authorization.py",
        "ml/data/authorize_stage_c_final_holdout_feature_extraction.py",
        "ml/data/stage_c_final_holdout_contamination_audit.py",
        "browser-extension/src/core/tsfeg.ts",
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
            raise StageCFinalHoldoutFeatureAuthorizationError(
                "invalid Git HEAD identity"
            )
        for relative in paths[:3]:
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
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-31 and bound files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCFinalHoldoutFeatureAuthorizationError(
            "Task-31/bound files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task31_module_sha256": sha256_file(repo_root / paths[0]),
        "task31_cli_sha256": sha256_file(repo_root / paths[1]),
        "task30_module_sha256": sha256_file(repo_root / paths[2]),
        "live_extractor_source_sha256": sha256_file(repo_root / paths[3]),
    }


def authorize_final_holdout_feature_extraction(
    *,
    repo_root: Path,
    clean_set_path: Path,
    contamination_audit_path: Path,
    threshold_freeze_path: Path,
    task28_seal_path: Path,
    task9_authorization_path: Path,
) -> dict[str, Any]:
    clean = load_json(clean_set_path)
    audit = load_json(contamination_audit_path)
    threshold = load_json(threshold_freeze_path)
    seal = load_json(task28_seal_path)
    task9 = load_json(task9_authorization_path)

    clean_rows = validate_clean_set(clean)
    validate_task30_audit(audit)
    validate_threshold_freeze(threshold)
    validate_task28_seal(seal)
    feature_contract = validate_task9_feature_authorization(task9)
    validate_live_extractor(repo_root)
    git = _git_provenance(repo_root)

    artifact_set_sha256 = canonical_hash(
        sorted(row["html_sha256"] for row in clean_rows)
    )

    authorization = {
        "schema_version": AUTH_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "authorized_action": (
            "EXTRACT_PRODUCTION_CONTEXT_FEATURES_FOR_FROZEN_CLEAN_FINAL_"
            "HOLDOUT_SUBSET_WITHOUT_MODEL_ACCESS"
        ),
        "final_holdout_feature_extraction_authorized": True,
        "final_holdout_model_loading_authorized": False,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_metrics_authorized": False,
        "final_holdout_error_analysis_authorized": False,
        "model_refit_authorized": False,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "threshold_change_authorized": False,
        "scope": {
            "dataset_role": "FINAL_HOLDOUT_CLEAN_EVALUATION_SUBSET",
            "authorized_sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
            "authorized_class_counts": EXPECTED_CLEAN_CLASS_COUNTS,
            "authorized_sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
            "authorized_record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
            "authorized_artifact_set_sha256": artifact_set_sha256,
            "quarantined_or_duplicate_rows_authorized": False,
            "non_clean_holdout_rows_authorized": False,
            "stage_c_development_rows_authorized": False,
            "stage_b_consumed_test_rows_authorized": False,
        },
        "feature_contract": {
            "source_feature_version": feature_contract["source_feature_version"],
            "ordered_features": feature_contract["ordered_features"],
            "feature_count": feature_contract["feature_count"],
            "feature_contract_sha256": feature_contract[
                "feature_contract_sha256"
            ],
            "extractor_source": feature_contract["extractor_source"],
            "extractor_source_sha256": feature_contract[
                "extractor_source_sha256"
            ],
            "order_source": feature_contract["order_source"],
            "raw_html_persistence_in_feature_output_authorized": False,
            "raw_url_persistence_in_feature_output_authorized": False,
            "sample_id_allowed_as_join_key_only": True,
            "label_allowed_as_evaluation_metadata_only": True,
        },
        "collection_integrity_policy": {
            "production_collection_loss_preserved": True,
            "collection_incomplete_rows_may_be_marked": True,
            "collection_incomplete_rows_model_scoring_authorized": False,
            "collection_incomplete_rows_metric_computation_authorized": False,
            "incomplete_exclusion_reason_must_be_collection_integrity_only": True,
            "performance_based_exclusion_authorized": False,
        },
        "frozen_operating_point": {
            "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
            "candidate_artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
            "candidate_threshold_pair_sha256": (
                EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256
            ),
            "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
            "threshold": EXPECTED_THRESHOLD,
            "model_loading_during_feature_extraction_authorized": False,
            "model_scoring_during_feature_extraction_authorized": False,
        },
        "identity_bindings": {
            "task30_clean_sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
            "task30_clean_record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
            "task29_record_set_sha256": EXPECTED_TASK29_RECORD_SET_SHA256,
            "task29_index_identity_sha256": EXPECTED_TASK29_INDEX_IDENTITY_SHA256,
            "task24_threshold_freeze_record_sha256": (
                EXPECTED_TASK24_THRESHOLD_FREEZE_SHA256
            ),
            "task24_candidate_threshold_pair_sha256": (
                EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256
            ),
            "task28_local_integrity_seal_sha256": EXPECTED_TASK28_SEAL_SHA256,
            "task28_local_artifact_set_sha256": (
                EXPECTED_TASK28_ARTIFACT_SET_SHA256
            ),
            "task9_feature_authorization_sha256": (
                EXPECTED_TASK9_AUTHORIZATION_SHA256
            ),
            "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
            "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
            **git,
        },
        "required_post_extraction_audits": [
            "EXACT_AUTHORIZED_SAMPLE_COVERAGE",
            "NO_QUARANTINED_SAMPLE_REAPPEARS",
            "FEATURE_SCHEMA_EXACT_MATCH_27",
            "PRODUCTION_FEATURE_ORDER_EXACT_MATCH",
            "NO_NAN_OR_INF",
            "COLLECTION_INCOMPLETE_COUNT_AND_IDENTITIES_FROZEN",
            "INCOMPLETE_ROWS_EXCLUDED_FROM_LATER_SCORING",
            "NO_RAW_HTML_OR_RAW_URL_IN_FEATURE_OUTPUT",
            "NO_MODEL_LOADING_OR_SCORING_DURING_EXTRACTION",
            "FINAL_FEATURE_DATASET_HASH_FREEZE",
        ],
        "next_gate": (
            "EXTRACT_STAGE_C_FINAL_HOLDOUT_FEATURES_AND_SEAL_WITHOUT_MODEL_SCORING"
        ),
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
