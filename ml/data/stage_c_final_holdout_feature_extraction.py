"""Stage C Task 32 — checkpointed final-holdout production feature extraction.

This task replays only the Task-31-authorized 12,711 clean CompPhish v3 HTML
captures through the hardened Stage-C memory replay collector and derives the
exact production context-features-1 vector.

Critical protocol properties:
- browser collection is label-blind: collector ground_truth is fixed to 0;
- source URLs are unavailable and never persisted;
- raw HTML is streamed one sample at a time from the sealed ZIP to the collector;
- raw HTML is never materialized as ordinary files;
- external network, scripts, forms, frames, and objects remain blocked;
- collection loss is preserved and incomplete rows are excluded from later scoring;
- no model artifact is loaded, scored, refit, selected, calibrated, or thresholded;
- every batch is independently checkpointed and resume-verified.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
from typing import Any, Callable, Iterable, Mapping
import zipfile

STATE_SCHEMA = "stage-c-final-holdout-feature-extraction-state-1"
CHECKPOINT_SCHEMA = "stage-c-final-holdout-feature-checkpoint-1"
AUDIT_SCHEMA = "stage-c-final-holdout-feature-audit-1"
READINESS_SCHEMA = "stage-c-final-holdout-feature-readiness-1"

EXPECTED_TASK31_AUTHORIZATION_SHA256 = (
    "f53787f6131cdb868b1ee1b55618fece41738353f9be7db7d6f9aa7abab37d04"
)
EXPECTED_CLEAN_SAMPLE_COUNT = 12711
EXPECTED_CLEAN_CLASS_COUNTS = {"legitimate": 7609, "phishing": 5102}
EXPECTED_CLEAN_SAMPLE_SET_SHA256 = (
    "451a45d56def6a70f3e7dc304e610a95691a7317315e374d5dff69721876ed7c"
)
EXPECTED_CLEAN_RECORD_SET_SHA256 = (
    "420b0ab542b4aa488fabecc41494f5f55392698f08c299a1a005b80e93753035"
)
EXPECTED_AUTHORIZED_ARTIFACT_SET_SHA256 = (
    "1295f51b8459e80fd9e908dbee32654af30862ab090aaa36216e94790988ea89"
)
EXPECTED_HTML_ARCHIVE_SHA256 = (
    "12440e4f911fabf4ec2c712ae014cb43e638e9a6adc6c7c6a506a8a7df24fcf7"
)
EXPECTED_FEATURE_CONTRACT_SHA256 = (
    "2ee75478749e347f84e97b6fb8911a5b961019be6e282b28792a3e70b0c95a6b"
)
EXPECTED_EXTRACTOR_SOURCE_SHA256 = (
    "6378a55363653da12a101f1cdae33a8b53313d20aee8db95e1deb21fe1e57d74"
)
EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256 = (
    "25286bcee337d4731eda836f23cf3032c4b9ae0922a3742fa7a15251da5aa0eb"
)
EXPECTED_SELECTED_CANDIDATE_ID = "logistic_regression"
EXPECTED_SELECTED_ARTIFACT_SHA256 = (
    "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"
)
EXPECTED_THRESHOLD = 0.8637646437995518

MIN_LEGITIMATE_FOR_WILSON = 381
RECOMMENDED_LEGITIMATE = 1200
RECOMMENDED_PHISHING = 1000

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


class StageCFinalHoldoutFeatureExtractionError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFinalHoldoutFeatureExtractionError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCFinalHoldoutFeatureExtractionError(
            f"JSON root must be object: {path}"
        )
    return value


def _hash_without(value: Mapping[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return canonical_hash(copy)


def _atomic_frozen_text(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"refusing to replace non-identical frozen output: {path}"
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


def frozen_write_json(path: Path, value: Any) -> str:
    return _atomic_frozen_text(
        path,
        (
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        ).encode("utf-8"),
    )


def _require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"invalid SHA-256 field: {name}"
        )
    try:
        int(value, 16)
    except ValueError as exc:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"invalid SHA-256 field: {name}"
        ) from exc
    return value.lower()


def _validate_authorization(
    auth: Mapping[str, Any], *, expected_sha256: str
) -> list[str]:
    expected_sha256 = _require_sha(expected_sha256, "expected authorization")
    if expected_sha256 != EXPECTED_TASK31_AUTHORIZATION_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-32 is frozen to the current Task-31 authorization identity"
        )
    required = {
        "schema_version":
            "stage-c-final-holdout-feature-extraction-authorization-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
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
        "authorization_sha256": EXPECTED_TASK31_AUTHORIZATION_SHA256,
    }
    for key, expected in required.items():
        if auth.get(key) != expected:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"Task-31 authorization guard mismatch: {key}"
            )
    if _hash_without(auth, "authorization_sha256") != (
        EXPECTED_TASK31_AUTHORIZATION_SHA256
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 authorization hash does not reproduce"
        )

    scope = auth.get("scope")
    if not isinstance(scope, Mapping):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 authorization scope missing"
        )
    scope_expected = {
        "dataset_role": "FINAL_HOLDOUT_CLEAN_EVALUATION_SUBSET",
        "authorized_sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
        "authorized_class_counts": EXPECTED_CLEAN_CLASS_COUNTS,
        "authorized_sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
        "authorized_record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
        "authorized_artifact_set_sha256":
            EXPECTED_AUTHORIZED_ARTIFACT_SET_SHA256,
        "quarantined_or_duplicate_rows_authorized": False,
        "non_clean_holdout_rows_authorized": False,
        "stage_c_development_rows_authorized": False,
        "stage_b_consumed_test_rows_authorized": False,
    }
    for key, expected in scope_expected.items():
        if scope.get(key) != expected:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"Task-31 scope changed: {key}"
            )

    feature = auth.get("feature_contract")
    if not isinstance(feature, Mapping):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 feature contract missing"
        )
    if feature.get("source_feature_version") != "context-features-1":
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 feature version changed"
        )
    if feature.get("feature_count") != 27:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 feature count changed"
        )
    if feature.get("ordered_features") != EXPECTED_FEATURES:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 production feature order changed"
        )
    if feature.get("feature_contract_sha256") != (
        EXPECTED_FEATURE_CONTRACT_SHA256
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 feature contract identity changed"
        )
    if feature.get("extractor_source_sha256") != (
        EXPECTED_EXTRACTOR_SOURCE_SHA256
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 extractor identity changed"
        )
    if feature.get(
        "raw_html_persistence_in_feature_output_authorized"
    ) is not False:
        raise StageCFinalHoldoutFeatureExtractionError(
            "raw HTML persistence unexpectedly authorized"
        )
    if feature.get(
        "raw_url_persistence_in_feature_output_authorized"
    ) is not False:
        raise StageCFinalHoldoutFeatureExtractionError(
            "raw URL persistence unexpectedly authorized"
        )

    policy = auth.get("collection_integrity_policy")
    if not isinstance(policy, Mapping):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 collection-integrity policy missing"
        )
    policy_expected = {
        "production_collection_loss_preserved": True,
        "collection_incomplete_rows_may_be_marked": True,
        "collection_incomplete_rows_model_scoring_authorized": False,
        "collection_incomplete_rows_metric_computation_authorized": False,
        "incomplete_exclusion_reason_must_be_collection_integrity_only": True,
        "performance_based_exclusion_authorized": False,
    }
    for key, expected in policy_expected.items():
        if policy.get(key) != expected:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"Task-31 collection policy changed: {key}"
            )

    frozen = auth.get("frozen_operating_point")
    if not isinstance(frozen, Mapping):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 frozen operating point missing"
        )
    frozen_expected = {
        "candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "candidate_artifact_sha256": EXPECTED_SELECTED_ARTIFACT_SHA256,
        "candidate_threshold_pair_sha256":
            EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
        "threshold_rule": "PREDICT_PHISHING_IF_SCORE_GTE_THRESHOLD",
        "threshold": EXPECTED_THRESHOLD,
        "model_loading_during_feature_extraction_authorized": False,
        "model_scoring_during_feature_extraction_authorized": False,
    }
    for key, expected in frozen_expected.items():
        if frozen.get(key) != expected:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"Task-31 frozen operating point changed: {key}"
            )
    return list(feature["ordered_features"])


def _validate_clean_set(clean: Mapping[str, Any]) -> list[dict[str, Any]]:
    required = {
        "schema_version": "stage-c-final-holdout-clean-evaluation-set-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT_CLEAN_EVALUATION_SUBSET",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
        "class_counts": EXPECTED_CLEAN_CLASS_COUNTS,
        "sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
        "record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
        "model_scoring_performed": False,
        "features_extracted": False,
        "metrics_computed": False,
    }
    for key, expected in required.items():
        if clean.get(key) != expected:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"Task-30 clean-set guard mismatch: {key}"
            )
    rows = clean.get("records")
    if not isinstance(rows, list) or len(rows) != EXPECTED_CLEAN_SAMPLE_COUNT:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-30 clean records missing"
        )
    if canonical_hash(rows) != EXPECTED_CLEAN_RECORD_SET_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-30 clean record-set hash mismatch"
        )
    if canonical_hash([row.get("sample_id") for row in rows]) != (
        EXPECTED_CLEAN_SAMPLE_SET_SHA256
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-30 clean sample-set hash mismatch"
        )

    seen_ids: set[str] = set()
    seen_html: set[str] = set()
    labels = Counter()
    normalized: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise StageCFinalHoldoutFeatureExtractionError(
                "Task-30 clean row invalid"
            )
        sid = raw.get("sample_id")
        label = raw.get("label")
        member = raw.get("html_member_name")
        digest = _require_sha(raw.get("html_sha256"), "clean html_sha256")
        if not isinstance(sid, str) or not sid or sid in seen_ids:
            raise StageCFinalHoldoutFeatureExtractionError(
                "Task-30 clean sample identity invalid"
            )
        if label not in (0, 1):
            raise StageCFinalHoldoutFeatureExtractionError(
                "Task-30 clean label invalid"
            )
        if not isinstance(member, str) or not member:
            raise StageCFinalHoldoutFeatureExtractionError(
                "Task-30 clean HTML locator missing"
            )
        pure = PurePosixPath(member)
        if pure.is_absolute() or ".." in pure.parts:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"unsafe clean HTML member path: {member}"
            )
        if digest in seen_html:
            raise StageCFinalHoldoutFeatureExtractionError(
                "Task-30 clean set still contains exact-HTML duplicates"
            )
        seen_ids.add(sid)
        seen_html.add(digest)
        labels[int(label)] += 1
        normalized.append({
            "sample_id": sid,
            "label": int(label),
            "html_member_name": member,
            "html_sha256": digest,
        })
    if labels != Counter({0: 7609, 1: 5102}):
        raise StageCFinalHoldoutFeatureExtractionError(
            f"Task-30 clean class counts changed: {dict(labels)}"
        )
    if canonical_hash(sorted(seen_html)) != EXPECTED_AUTHORIZED_ARTIFACT_SET_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-31 authorized artifact-set identity does not reproduce"
        )
    return normalized


def _load_production_contract(repo_root: Path) -> dict[str, Any]:
    tsfeg = repo_root / "browser-extension" / "src" / "core" / "tsfeg.ts"
    if not tsfeg.is_file():
        raise StageCFinalHoldoutFeatureExtractionError(
            "production TSFEG source not found"
        )
    source_sha = sha256_file(tsfeg)
    if source_sha != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"production extractor SHA-256 changed: {source_sha}"
        )
    source = r"""
import { pathToFileURL } from 'node:url';
const core = await import(pathToFileURL(process.argv[1]).href);
process.stdout.write(JSON.stringify({
  feature_version: core.CONTEXT_FEATURE_VERSION,
  ordered_features: [...core.CONTEXT_FEATURES]
}));
"""
    try:
        completed = subprocess.run(
            [
                "node", "--experimental-strip-types", "--input-type=module",
                "-e", source, str(tsfeg.resolve()),
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        details = getattr(exc, "stderr", "") or str(exc)
        raise StageCFinalHoldoutFeatureExtractionError(
            f"production feature probe failed: {details.strip()}"
        ) from exc
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature probe returned invalid JSON"
        ) from exc
    if payload.get("feature_version") != "context-features-1":
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature version changed"
        )
    if payload.get("ordered_features") != EXPECTED_FEATURES:
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature order changed"
        )
    contract_sha = canonical_hash({
        "feature_version": payload["feature_version"],
        "feature_names": payload["ordered_features"],
    })
    if contract_sha != EXPECTED_FEATURE_CONTRACT_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature contract hash changed"
        )
    return {
        "feature_version": payload["feature_version"],
        "ordered_features": payload["ordered_features"],
        "feature_contract_sha256": contract_sha,
        "extractor_source_sha256": source_sha,
    }


def build_replay_batches(
    rows: Iterable[Mapping[str, Any]], *, batch_size: int
) -> list[dict[str, Any]]:
    if type(batch_size) is not int or not 1 <= batch_size <= 512:
        raise StageCFinalHoldoutFeatureExtractionError(
            "batch_size must be between 1 and 512"
        )
    source = sorted(
        (dict(row) for row in rows),
        key=lambda row: str(row["sample_id"]),
    )
    seen_ids: set[str] = set()
    seen_artifacts: set[str] = set()
    for row in source:
        sid = str(row.get("sample_id", ""))
        digest = _require_sha(row.get("html_sha256"), "batch html_sha256")
        if not sid or sid in seen_ids:
            raise StageCFinalHoldoutFeatureExtractionError(
                "batch sample identity invalid"
            )
        if digest in seen_artifacts:
            raise StageCFinalHoldoutFeatureExtractionError(
                "clean final holdout contains duplicate exact HTML"
            )
        seen_ids.add(sid)
        seen_artifacts.add(digest)

    batches: list[dict[str, Any]] = []
    for start in range(0, len(source), batch_size):
        rows_in_batch = source[start:start + batch_size]
        ids = [str(row["sample_id"]) for row in rows_in_batch]
        hashes = [str(row["html_sha256"]) for row in rows_in_batch]
        core = {"sample_ids": ids, "artifact_sha256": hashes}
        digest = canonical_hash(core)
        sequence = len(batches) + 1
        batches.append({
            "batch_id": f"batch-{sequence:05d}-{digest[:12]}",
            "sample_count": len(rows_in_batch),
            "sample_set_sha256": canonical_hash(ids),
            "artifact_set_sha256": canonical_hash(hashes),
            "rows": rows_in_batch,
        })
    flattened = [
        str(row["sample_id"])
        for batch in batches
        for row in batch["rows"]
    ]
    if flattened != [str(row["sample_id"]) for row in source]:
        raise StageCFinalHoldoutFeatureExtractionError(
            "final-holdout batch schedule lost/reordered samples"
        )
    return batches


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_final_holdout_feature_extraction.py",
        "ml/data/extract_stage_c_final_holdout_features.py",
        "ml/data/stage_c_final_holdout_feature_extraction_authorization.py",
        "scripts/stage-c-collect-memory-replay.mjs",
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
            raise StageCFinalHoldoutFeatureExtractionError(
                "invalid Git HEAD identity"
            )
        for relative in paths[:4]:
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
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-32 implementation and replay dependencies must be committed"
        ) from exc
    if dirty != 0:
        raise StageCFinalHoldoutFeatureExtractionError(
            "Task-32/replay/extractor files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task32_module_sha256": sha256_file(repo_root / paths[0]),
        "task32_cli_sha256": sha256_file(repo_root / paths[1]),
        "task31_authorization_module_sha256":
            sha256_file(repo_root / paths[2]),
        "memory_collector_sha256": sha256_file(repo_root / paths[3]),
        "extractor_source_sha256": sha256_file(repo_root / paths[4]),
    }


def _state_payload(
    *,
    batches: list[dict[str, Any]],
    batch_size: int,
    wait_ms: int,
    archive_sha256: str,
    production: Mapping[str, Any],
    repo_root: Path,
    dist: Path,
    git: Mapping[str, str],
) -> dict[str, Any]:
    if type(wait_ms) is not int or not 250 <= wait_ms <= 10000:
        raise StageCFinalHoldoutFeatureExtractionError(
            "wait_ms must be between 250 and 10000"
        )
    required_dist = [
        dist / "manifest.json",
        dist / "collector.js",
        dist / "service-worker.js",
    ]
    missing = [str(path) for path in required_dist if not path.is_file()]
    if missing:
        raise StageCFinalHoldoutFeatureExtractionError(
            "built extension is missing; run the project build first: "
            + ", ".join(missing)
        )
    collector = repo_root / "scripts" / "stage-c-collect-memory-replay.mjs"
    if not collector.is_file():
        raise StageCFinalHoldoutFeatureExtractionError(
            "Stage-C memory replay collector missing"
        )

    descriptors = [{
        "batch_id": batch["batch_id"],
        "sample_count": batch["sample_count"],
        "sample_set_sha256": batch["sample_set_sha256"],
        "artifact_set_sha256": batch["artifact_set_sha256"],
    } for batch in batches]

    state = {
        "schema_version": STATE_SCHEMA,
        "status": "READY",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "authorization_sha256": EXPECTED_TASK31_AUTHORIZATION_SHA256,
        "authorized_sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
        "authorized_sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
        "authorized_record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
        "authorized_artifact_set_sha256":
            EXPECTED_AUTHORIZED_ARTIFACT_SET_SHA256,
        "feature_extraction_authorized": True,
        "model_loading_authorized": False,
        "model_scoring_authorized": False,
        "metrics_authorized": False,
        "model_refit_authorized": False,
        "threshold_change_authorized": False,
        "archive_sha256": archive_sha256,
        "feature_version": production["feature_version"],
        "feature_count": 27,
        "ordered_features": production["ordered_features"],
        "feature_contract_sha256": production["feature_contract_sha256"],
        "extractor_source_sha256": production["extractor_source_sha256"],
        "batch_size": batch_size,
        "wait_ms": wait_ms,
        "total_batches": len(batches),
        "batch_schedule_sha256": canonical_hash(descriptors),
        "batches": descriptors,
        "memory_replay_transport":
            "STDIN_NDJSON_BASE64_TO_PLAYWRIGHT_ROUTE_FULFILL",
        "raw_html_materialized_to_disk": False,
        "raw_html_sent_over_os_loopback_socket": False,
        "raw_url_available_to_replay": False,
        "collector_ground_truth_blinded": True,
        "collector_ground_truth_constant": 0,
        "collection_loss_policy": "PRESERVE_PRODUCTION_TRUNCATION_AND_FLAG",
        "incomplete_rows_scoring_authorized": False,
        "incomplete_rows_metric_authorized": False,
        "frozen_candidate_threshold_pair_sha256":
            EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
        "frozen_candidate_id": EXPECTED_SELECTED_CANDIDATE_ID,
        "frozen_candidate_artifact_sha256":
            EXPECTED_SELECTED_ARTIFACT_SHA256,
        "frozen_threshold": EXPECTED_THRESHOLD,
        "git_provenance": dict(git),
    }
    state["state_sha256"] = canonical_hash(state)
    return state


def _memory_plan(batch: Mapping[str, Any], *, wait_ms: int) -> dict[str, Any]:
    return {
        "schema_version": "stage-c-memory-replay-plan-1",
        "plan_id": f"stage-c-task32-{batch['batch_id']}",
        "items": [{
            "sample_id": str(row["sample_id"]),
            # Deliberately constant: final labels are not visible to browser collection.
            "ground_truth": 0,
            "artifact_sha256": str(row["html_sha256"]),
            "wait_ms": wait_ms,
        } for row in batch["rows"]],
    }


def _run_collector(
    *,
    repo_root: Path,
    dist: Path,
    batch: Mapping[str, Any],
    archive: zipfile.ZipFile,
    wait_ms: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    collector = repo_root / "scripts" / "stage-c-collect-memory-replay.mjs"
    with tempfile.TemporaryDirectory(prefix="stage-c-task32-meta-") as temp_name:
        root = Path(temp_name)
        plan_path = root / "plan.json"
        output_path = root / "episodes.json"
        plan_path.write_text(
            json.dumps(
                _memory_plan(batch, wait_ms=wait_ms),
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        command = [
            "node", str(collector),
            "--plan", str(plan_path),
            "--output", str(output_path),
            "--dist", str(dist),
        ]
        process: subprocess.Popen[str] | None = None
        feeder_error: Exception | None = None
        try:
            process = subprocess.Popen(
                command,
                cwd=repo_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            if process.stdin is None:
                raise StageCFinalHoldoutFeatureExtractionError(
                    "memory replay stdin pipe unavailable"
                )
            try:
                for row in batch["rows"]:
                    sid = str(row["sample_id"])
                    member = str(row["html_member_name"])
                    try:
                        info = archive.getinfo(member)
                    except KeyError as exc:
                        raise StageCFinalHoldoutFeatureExtractionError(
                            f"sealed HTML member missing for {sid}: {member}"
                        ) from exc
                    if info.is_dir():
                        raise StageCFinalHoldoutFeatureExtractionError(
                            f"sealed HTML member is a directory: {sid}"
                        )
                    payload = archive.read(info)
                    digest = hashlib.sha256(payload).hexdigest()
                    if digest != row["html_sha256"]:
                        raise StageCFinalHoldoutFeatureExtractionError(
                            f"in-memory final HTML SHA-256 mismatch for {sid}"
                        )
                    if not payload:
                        raise StageCFinalHoldoutFeatureExtractionError(
                            f"empty HTML survived clean final-holdout policy: {sid}"
                        )
                    envelope = {
                        "sample_id": sid,
                        "html_base64":
                            base64.b64encode(payload).decode("ascii"),
                    }
                    process.stdin.write(
                        json.dumps(
                            envelope, separators=(",", ":")
                        ) + "\n"
                    )
                    process.stdin.flush()
                    del payload, envelope
            except (BrokenPipeError, OSError) as exc:
                feeder_error = exc
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
                process.stdin = None

            try:
                stdout, stderr = process.communicate(
                    timeout=timeout_seconds
                )
            except subprocess.TimeoutExpired as exc:
                process.kill()
                stdout, stderr = process.communicate()
                raise StageCFinalHoldoutFeatureExtractionError(
                    f"memory browser replay timed out for {batch['batch_id']}"
                ) from exc
        except StageCFinalHoldoutFeatureExtractionError:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            raise
        except OSError as exc:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            raise StageCFinalHoldoutFeatureExtractionError(
                f"memory browser replay execution failed for "
                f"{batch['batch_id']}: {exc}"
            ) from exc

        if process is None:
            raise StageCFinalHoldoutFeatureExtractionError(
                "memory browser replay process unavailable"
            )
        if feeder_error is not None or process.returncode != 0:
            details = (
                stderr or stdout or str(feeder_error) or "collector failed"
            ).strip()
            raise StageCFinalHoldoutFeatureExtractionError(
                f"memory browser replay failed for {batch['batch_id']}: "
                f"{details[-4000:]}"
            )
        episodes = load_json(output_path)

    if episodes.get("schema_version") != "stage-b-event-episodes-1":
        raise StageCFinalHoldoutFeatureExtractionError(
            "replay episode schema changed"
        )
    if episodes.get("collector_version") != "stage-c-memory-replay-5":
        raise StageCFinalHoldoutFeatureExtractionError(
            "memory replay collector version changed"
        )
    if episodes.get("failures") != []:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"memory replay batch contains failures: {batch['batch_id']}"
        )
    rows = episodes.get("episodes")
    if not isinstance(rows, list) or len(rows) != int(batch["sample_count"]):
        raise StageCFinalHoldoutFeatureExtractionError(
            "replay episode count mismatch"
        )
    expected_ids = {str(row["sample_id"]) for row in batch["rows"]}
    actual_ids = {
        row.get("sample_id")
        for row in rows
        if isinstance(row, Mapping)
    }
    if actual_ids != expected_ids or len(actual_ids) != len(rows):
        raise StageCFinalHoldoutFeatureExtractionError(
            "replay episode sample identity mismatch"
        )

    safety = episodes.get("safety_policy")
    if not isinstance(safety, Mapping):
        raise StageCFinalHoldoutFeatureExtractionError(
            "replay safety policy missing"
        )
    required_true = (
        "archived_local_files_only",
        "replay_origin_loopback_only",
        "page_scripts_disabled_by_csp",
        "form_submission_disabled_by_csp",
        "frames_and_objects_disabled_by_csp",
        "external_network_requests_aborted",
        "raw_html_received_via_stdin_memory_stream",
        "browser_document_body_injected_via_playwright_route_fulfill",
        "browser_response_cache_control_no_store",
    )
    for key in required_true:
        if safety.get(key) is not True:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"replay safety guard failed: {key}"
            )
    required_false = (
        "raw_html_persisted_in_episode_output",
        "raw_html_materialized_to_disk",
        "raw_html_sent_over_os_loopback_socket",
        "secondary_main_frame_navigation_external_network_allowed",
        "repeated_controlled_url_reload_refulfilled",
        "incomplete_rows_modeling_candidate",
    )
    for key in required_false:
        if safety.get(key) is not False:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"replay safety guard failed: {key}"
            )
    if safety.get(
        "secondary_main_frame_navigation_policy"
    ) != "FULFILL_204_AFTER_SINGLE_INITIAL_FULFILL":
        raise StageCFinalHoldoutFeatureExtractionError(
            "secondary-navigation policy changed"
        )
    if safety.get(
        "collection_loss_policy"
    ) != "PRESERVE_PRODUCTION_TRUNCATION_AND_FLAG":
        raise StageCFinalHoldoutFeatureExtractionError(
            "collection-loss policy changed"
        )

    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCFinalHoldoutFeatureExtractionError(
                "replay episode row invalid"
            )
        incomplete = row.get("collection_incomplete")
        dropped = row.get("dropped_events")
        delivery = row.get("delivery_errors")
        history = row.get("history_truncated")
        if type(incomplete) is not bool or type(history) is not bool:
            raise StageCFinalHoldoutFeatureExtractionError(
                "replay collection flags invalid"
            )
        if type(dropped) is not int or dropped < 0:
            raise StageCFinalHoldoutFeatureExtractionError(
                "replay dropped-event count invalid"
            )
        if type(delivery) is not int or delivery < 0:
            raise StageCFinalHoldoutFeatureExtractionError(
                "replay delivery-error count invalid"
            )
        if incomplete is not (dropped > 0 or history):
            raise StageCFinalHoldoutFeatureExtractionError(
                "replay collection-incomplete flag mismatch"
            )

    hashes = episodes.get("source_hashes")
    if not isinstance(hashes, Mapping):
        raise StageCFinalHoldoutFeatureExtractionError(
            "replay source hashes missing"
        )
    if hashes.get("tsfeg_source_sha256") != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            "replay used different TSFEG source"
        )
    return episodes


def _extract_vectors(
    episodes: Mapping[str, Any], *, repo_root: Path
) -> dict[str, dict[str, Any]]:
    tsfeg = (
        repo_root / "browser-extension" / "src" / "core" / "tsfeg.ts"
    ).resolve()
    source = r"""
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const core = await import(pathToFileURL(process.argv[1]).href);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const rows = input.map(row => {
  const incomplete = row.collection_incomplete === true;
  const out = core.buildContextFeatures(row.events, incomplete);
  return {
    sample_id: row.sample_id,
    vector: out.vector,
    collection_incomplete: incomplete,
    dropped_events: row.dropped_events,
    delivery_errors: row.delivery_errors,
    history_truncated: row.history_truncated === true,
  };
});
process.stdout.write(JSON.stringify({
  feature_version: core.CONTEXT_FEATURE_VERSION,
  feature_names: [...core.CONTEXT_FEATURES],
  rows
}));
"""
    input_rows = episodes.get("episodes")
    try:
        completed = subprocess.run(
            [
                "node", "--experimental-strip-types",
                "--input-type=module", "-e", source, str(tsfeg),
            ],
            input=json.dumps(input_rows, separators=(",", ":")),
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        details = getattr(exc, "stderr", "") or str(exc)
        raise StageCFinalHoldoutFeatureExtractionError(
            f"production feature extraction failed: {details.strip()}"
        ) from exc
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature extractor returned invalid JSON"
        ) from exc
    if output.get("feature_version") != "context-features-1":
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature version changed during extraction"
        )
    if output.get("feature_names") != EXPECTED_FEATURES:
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature order changed during extraction"
        )
    if canonical_hash({
        "feature_version": output["feature_version"],
        "feature_names": output["feature_names"],
    }) != EXPECTED_FEATURE_CONTRACT_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            "production feature contract hash changed during extraction"
        )

    rows = output.get("rows")
    if not isinstance(rows, list):
        raise StageCFinalHoldoutFeatureExtractionError(
            "production extractor rows missing"
        )
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCFinalHoldoutFeatureExtractionError(
                "production extractor row invalid"
            )
        sid = row.get("sample_id")
        vector = row.get("vector")
        if not isinstance(sid, str) or not sid or sid in result:
            raise StageCFinalHoldoutFeatureExtractionError(
                "production extractor sample identity invalid"
            )
        if not isinstance(vector, list) or len(vector) != 27:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"production feature vector shape mismatch: {sid}"
            )
        if any(
            type(value) not in (int, float) or not math.isfinite(value)
            for value in vector
        ):
            raise StageCFinalHoldoutFeatureExtractionError(
                f"non-finite production feature vector: {sid}"
            )
        incomplete = row.get("collection_incomplete")
        dropped = row.get("dropped_events")
        delivery = row.get("delivery_errors")
        history = row.get("history_truncated")
        if type(incomplete) is not bool or type(history) is not bool:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"production collection flags invalid: {sid}"
            )
        if type(dropped) is not int or dropped < 0:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"production dropped-event count invalid: {sid}"
            )
        if type(delivery) is not int or delivery < 0:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"production delivery-error count invalid: {sid}"
            )
        if incomplete is not (dropped > 0 or history):
            raise StageCFinalHoldoutFeatureExtractionError(
                f"production collection-incomplete mismatch: {sid}"
            )
        result[sid] = {
            "feature_vector": list(vector),
            "collection_incomplete": incomplete,
            "dropped_events": dropped,
            "delivery_errors": delivery,
            "history_truncated": history,
        }
    return result


def _validate_feature_row(row: Mapping[str, Any]) -> None:
    expected = {
        "sample_id",
        "label",
        "feature_vector",
        "collection_incomplete",
        "dropped_events",
        "delivery_errors",
        "history_truncated",
    }
    if set(row) != expected:
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row contains prohibited or unexpected fields"
        )
    if not isinstance(row.get("sample_id"), str) or not row["sample_id"]:
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row sample_id invalid"
        )
    if row.get("label") not in (0, 1):
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row label invalid"
        )
    vector = row.get("feature_vector")
    if not isinstance(vector, list) or len(vector) != 27:
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row vector shape invalid"
        )
    if any(
        type(value) not in (int, float) or not math.isfinite(value)
        for value in vector
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row contains NaN/Infinity/non-numeric value"
        )
    if type(row.get("collection_incomplete")) is not bool:
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row collection_incomplete invalid"
        )
    if type(row.get("history_truncated")) is not bool:
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row history_truncated invalid"
        )
    for key in ("dropped_events", "delivery_errors"):
        if type(row.get(key)) is not int or row[key] < 0:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"feature row {key} invalid"
            )
    if row["collection_incomplete"] is not (
        row["dropped_events"] > 0 or row["history_truncated"]
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "feature row collection-incomplete flag does not match loss metadata"
        )


def _render_checkpoint_rows(
    batch: Mapping[str, Any], vectors: Mapping[str, Mapping[str, Any]]
) -> bytes:
    lines: list[bytes] = []
    for row in batch["rows"]:
        sid = str(row["sample_id"])
        extracted = vectors.get(sid)
        if extracted is None:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"feature vector missing for replayed final sample: {sid}"
            )
        feature_row = {
            "sample_id": sid,
            "label": int(row["label"]),
            "feature_vector": list(extracted["feature_vector"]),
            "collection_incomplete": bool(
                extracted["collection_incomplete"]
            ),
            "dropped_events": int(extracted["dropped_events"]),
            "delivery_errors": int(extracted["delivery_errors"]),
            "history_truncated": bool(extracted["history_truncated"]),
        }
        _validate_feature_row(feature_row)
        lines.append(canonical_bytes(feature_row) + b"\n")
    return b"".join(lines)


def _checkpoint_paths(
    output_root: Path, batch_id: str
) -> tuple[Path, Path]:
    root = output_root / "feature-extraction-checkpoints"
    return (
        root / f"{batch_id}.features.jsonl",
        root / f"{batch_id}.seal.json",
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise StageCFinalHoldoutFeatureExtractionError(
                        f"JSONL row is not object: {path}:{line_number}"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"cannot read checkpoint JSONL {path}: {exc}"
        ) from exc
    return rows


def _verify_checkpoint(
    *,
    output_root: Path,
    batch: Mapping[str, Any],
    state_sha256: str,
) -> bool:
    features_path, seal_path = _checkpoint_paths(
        output_root, str(batch["batch_id"])
    )
    if not features_path.exists() and not seal_path.exists():
        return False
    if features_path.exists() != seal_path.exists():
        raise StageCFinalHoldoutFeatureExtractionError(
            f"incomplete checkpoint pair: {batch['batch_id']}"
        )
    seal = load_json(seal_path)
    required = {
        "schema_version": CHECKPOINT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "batch_id": batch["batch_id"],
        "state_sha256": state_sha256,
        "authorization_sha256": EXPECTED_TASK31_AUTHORIZATION_SHA256,
        "sample_count": batch["sample_count"],
        "sample_set_sha256": batch["sample_set_sha256"],
        "artifact_set_sha256": batch["artifact_set_sha256"],
    }
    for key, expected in required.items():
        if seal.get(key) != expected:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"checkpoint seal guard mismatch: {batch['batch_id']}:{key}"
            )
    if seal.get("features_jsonl_sha256") != sha256_file(features_path):
        raise StageCFinalHoldoutFeatureExtractionError(
            f"checkpoint payload SHA mismatch: {batch['batch_id']}"
        )
    rows = _read_jsonl(features_path)
    if len(rows) != batch["sample_count"]:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"checkpoint row count mismatch: {batch['batch_id']}"
        )
    expected_ids = [str(row["sample_id"]) for row in batch["rows"]]
    observed_ids = [str(row.get("sample_id")) for row in rows]
    if observed_ids != expected_ids:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"checkpoint sample order/identity mismatch: {batch['batch_id']}"
        )
    for row in rows:
        _validate_feature_row(row)
    return True


def _write_checkpoint(
    *,
    output_root: Path,
    batch: Mapping[str, Any],
    payload: bytes,
    state_sha256: str,
    collector_hashes: Mapping[str, Any],
) -> None:
    features_path, seal_path = _checkpoint_paths(
        output_root, str(batch["batch_id"])
    )
    if features_path.exists() or seal_path.exists():
        raise StageCFinalHoldoutFeatureExtractionError(
            f"checkpoint already exists unexpectedly: {batch['batch_id']}"
        )
    _atomic_frozen_text(features_path, payload)
    seal = {
        "schema_version": CHECKPOINT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "batch_id": batch["batch_id"],
        "state_sha256": state_sha256,
        "authorization_sha256": EXPECTED_TASK31_AUTHORIZATION_SHA256,
        "sample_count": batch["sample_count"],
        "sample_set_sha256": batch["sample_set_sha256"],
        "artifact_set_sha256": batch["artifact_set_sha256"],
        "features_jsonl_sha256": sha256_file(features_path),
        "collector_source_hashes": dict(collector_hashes),
        "collector_ground_truth_blinded": True,
        "model_loaded": False,
        "model_scoring_performed": False,
    }
    frozen_write_json(seal_path, seal)


def _finalize(
    *,
    output_root: Path,
    batches: list[dict[str, Any]],
    authorized_rows: list[dict[str, Any]],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    checkpoint_rows: dict[str, dict[str, Any]] = {}
    checkpoint_hashes: list[dict[str, str]] = []
    for batch in batches:
        features_path, seal_path = _checkpoint_paths(
            output_root, str(batch["batch_id"])
        )
        if not _verify_checkpoint(
            output_root=output_root,
            batch=batch,
            state_sha256=str(state["state_sha256"]),
        ):
            raise StageCFinalHoldoutFeatureExtractionError(
                f"cannot finalize with missing checkpoint: {batch['batch_id']}"
            )
        checkpoint_hashes.append({
            "batch_id": str(batch["batch_id"]),
            "features_jsonl_sha256": sha256_file(features_path),
            "seal_file_sha256": sha256_file(seal_path),
        })
        for row in _read_jsonl(features_path):
            sid = str(row["sample_id"])
            if sid in checkpoint_rows:
                raise StageCFinalHoldoutFeatureExtractionError(
                    f"duplicate sample across final checkpoints: {sid}"
                )
            _validate_feature_row(row)
            checkpoint_rows[sid] = row

    expected = {
        str(row["sample_id"]): int(row["label"])
        for row in authorized_rows
    }
    order = [str(row["sample_id"]) for row in authorized_rows]
    if set(checkpoint_rows) != set(expected):
        missing = sorted(set(expected) - set(checkpoint_rows))[:5]
        extras = sorted(set(checkpoint_rows) - set(expected))[:5]
        raise StageCFinalHoldoutFeatureExtractionError(
            f"final feature coverage mismatch; missing={missing} extras={extras}"
        )
    for sid, label in expected.items():
        if checkpoint_rows[sid]["label"] != label:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"final feature label alignment failed: {sid}"
            )

    incomplete_ids = sorted(
        sid for sid, row in checkpoint_rows.items()
        if row["collection_incomplete"]
    )
    complete_ids = sorted(
        sid for sid, row in checkpoint_rows.items()
        if not row["collection_incomplete"]
    )
    incomplete_counts = Counter(
        checkpoint_rows[sid]["label"] for sid in incomplete_ids
    )
    complete_counts = Counter(
        checkpoint_rows[sid]["label"] for sid in complete_ids
    )

    final_path = output_root / "final-holdout-features.jsonl"
    temp_path = final_path.with_name(
        f".{final_path.name}.assemble-{os.getpid()}"
    )
    final_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with temp_path.open("wb") as handle:
            for sid in order:
                handle.write(canonical_bytes(checkpoint_rows[sid]) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        _atomic_frozen_text(final_path, temp_path.read_bytes())
    finally:
        temp_path.unlink(missing_ok=True)

    dataset_sha = sha256_file(final_path)
    feature_row_set_sha = canonical_hash([
        checkpoint_rows[sid]
        for sid in sorted(checkpoint_rows)
    ])
    incomplete_set_sha = canonical_hash(incomplete_ids)
    complete_set_sha = canonical_hash(complete_ids)
    complete_record_set_sha = canonical_hash([
        checkpoint_rows[sid]
        for sid in complete_ids
    ])

    complete_class_counts = {
        "legitimate": complete_counts[0],
        "phishing": complete_counts[1],
    }
    incomplete_class_counts = {
        "legitimate": incomplete_counts[0],
        "phishing": incomplete_counts[1],
    }
    minimum_scale = complete_counts[0] >= MIN_LEGITIMATE_FOR_WILSON
    recommended_scale = (
        complete_counts[0] >= RECOMMENDED_LEGITIMATE
        and complete_counts[1] >= RECOMMENDED_PHISHING
    )

    audits = {
        "EXACT_AUTHORIZED_SAMPLE_COVERAGE": True,
        "NO_QUARANTINED_SAMPLE_REAPPEARS": True,
        "FEATURE_SCHEMA_EXACT_MATCH_27": True,
        "PRODUCTION_FEATURE_ORDER_EXACT_MATCH": True,
        "NO_NAN_OR_INF": True,
        "NO_RAW_HTML_OR_RAW_URL_IN_FEATURE_OUTPUT": True,
        "LABEL_BLIND_BROWSER_COLLECTION": True,
        "COLLECTION_INCOMPLETE_IDENTITIES_FROZEN": True,
        "INCOMPLETE_ROWS_EXCLUDED_FROM_LATER_SCORING": True,
        "NO_MODEL_LOADING_OR_SCORING_DURING_EXTRACTION": True,
        "FROZEN_MODEL_THRESHOLD_UNCHANGED": True,
        "FINAL_FEATURE_DATASET_HASH_FREEZE": True,
    }

    audit = {
        "schema_version": AUDIT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "authorization_sha256": EXPECTED_TASK31_AUTHORIZATION_SHA256,
        "state_sha256": state["state_sha256"],
        "authorized_sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
        "authorized_class_counts": EXPECTED_CLEAN_CLASS_COUNTS,
        "authorized_sample_set_sha256": EXPECTED_CLEAN_SAMPLE_SET_SHA256,
        "authorized_record_set_sha256": EXPECTED_CLEAN_RECORD_SET_SHA256,
        "authorized_artifact_set_sha256":
            EXPECTED_AUTHORIZED_ARTIFACT_SET_SHA256,
        "feature_version": "context-features-1",
        "feature_count": 27,
        "ordered_features": EXPECTED_FEATURES,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
        "total_feature_rows": len(checkpoint_rows),
        "collection_incomplete_count": len(incomplete_ids),
        "collection_incomplete_class_counts": incomplete_class_counts,
        "collection_incomplete_sample_set_sha256": incomplete_set_sha,
        "evaluation_candidate_policy": "COLLECTION_COMPLETE_ONLY",
        "evaluation_candidate_sample_count": len(complete_ids),
        "evaluation_candidate_class_counts": complete_class_counts,
        "evaluation_candidate_sample_set_sha256": complete_set_sha,
        "evaluation_candidate_record_set_sha256": complete_record_set_sha,
        "minimum_low_fpr_resolution_satisfied": minimum_scale,
        "recommended_final_scale_satisfied": recommended_scale,
        "feature_dataset_sha256": dataset_sha,
        "feature_row_set_sha256": feature_row_set_sha,
        "checkpoint_set_sha256": canonical_hash(checkpoint_hashes),
        "collector_ground_truth_blinded": True,
        "raw_html_persisted": False,
        "raw_url_persisted": False,
        "model_loaded": False,
        "model_scoring_performed": False,
        "metrics_computed": False,
        "threshold_changed": False,
        "model_refit": False,
        "final_holdout_bytes_accessed_for_feature_extraction": True,
        "audits": audits,
    }
    audit["audit_sha256"] = canonical_hash(audit)
    audit_path = output_root / "final-holdout-feature-audit.json"
    frozen_write_json(audit_path, audit)

    next_gate = (
        "ISSUE_STAGE_C_FINAL_HOLDOUT_SCORING_AUTHORIZATION_FOR_"
        "COMPLETE_COLLECTION_SUBSET"
        if minimum_scale and recommended_scale
        else "FINAL_HOLDOUT_COLLECTION_SCALE_INSUFFICIENT_FOR_FROZEN_EVALUATION"
    )
    readiness = {
        "schema_version": READINESS_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_complete": True,
        "authorization_sha256": EXPECTED_TASK31_AUTHORIZATION_SHA256,
        "feature_audit_sha256": audit["audit_sha256"],
        "feature_dataset_sha256": dataset_sha,
        "feature_row_set_sha256": feature_row_set_sha,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "authorized_sample_count": EXPECTED_CLEAN_SAMPLE_COUNT,
        "collection_incomplete_count": len(incomplete_ids),
        "collection_incomplete_sample_set_sha256": incomplete_set_sha,
        "evaluation_candidate_policy": "COLLECTION_COMPLETE_ONLY",
        "evaluation_candidate_sample_count": len(complete_ids),
        "evaluation_candidate_class_counts": complete_class_counts,
        "evaluation_candidate_sample_set_sha256": complete_set_sha,
        "evaluation_candidate_record_set_sha256": complete_record_set_sha,
        "minimum_low_fpr_resolution_satisfied": minimum_scale,
        "recommended_final_scale_satisfied": recommended_scale,
        "all_required_post_extraction_audits_passed":
            all(audits.values()),
        "model_loading_authorized": False,
        "model_scoring_authorized": False,
        "metrics_authorized": False,
        "threshold_change_authorized": False,
        "next_gate": next_gate,
    }
    readiness["readiness_sha256"] = canonical_hash(readiness)
    readiness_path = output_root / "final-holdout-feature-readiness.json"
    frozen_write_json(readiness_path, readiness)

    return {
        "status": "PASS",
        "feature_dataset": str(final_path),
        "feature_dataset_sha256": dataset_sha,
        "feature_audit": str(audit_path),
        "feature_audit_sha256": audit["audit_sha256"],
        "feature_readiness": str(readiness_path),
        "feature_readiness_sha256": readiness["readiness_sha256"],
        "rows": len(checkpoint_rows),
        "feature_count": 27,
        "collection_incomplete_count": len(incomplete_ids),
        "evaluation_candidate_sample_count": len(complete_ids),
        "evaluation_candidate_class_counts": complete_class_counts,
        "evaluation_candidate_sample_set_sha256": complete_set_sha,
        "evaluation_candidate_record_set_sha256": complete_record_set_sha,
        "recommended_final_scale_satisfied": recommended_scale,
        "model_loaded": False,
        "model_scoring_performed": False,
        "metrics_computed": False,
        "threshold_changed": False,
        "next_gate": next_gate,
    }


def run_stage_c_final_holdout_feature_extraction(
    *,
    repo_root: Path,
    html_archive_path: Path,
    clean_set_path: Path,
    authorization_path: Path,
    output_root: Path,
    expected_authorization_sha256: str,
    batch_size: int = 256,
    wait_ms: int = 250,
    timeout_seconds: int = 1800,
    max_batches: int | None = None,
    dist_path: Path | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    html_archive_path = html_archive_path.resolve()
    output_root = output_root.resolve()
    dist = (dist_path or (repo_root / "dist")).resolve()

    if max_batches is not None and (
        type(max_batches) is not int or max_batches < 1
    ):
        raise StageCFinalHoldoutFeatureExtractionError(
            "max_batches must be a positive integer"
        )
    if type(timeout_seconds) is not int or timeout_seconds < 60:
        raise StageCFinalHoldoutFeatureExtractionError(
            "timeout_seconds must be at least 60"
        )

    auth = load_json(authorization_path)
    _validate_authorization(
        auth, expected_sha256=expected_authorization_sha256
    )
    authorized = _validate_clean_set(load_json(clean_set_path))
    production = _load_production_contract(repo_root)
    git = _git_provenance(repo_root)

    if not html_archive_path.is_file():
        raise StageCFinalHoldoutFeatureExtractionError(
            f"sealed final HTML archive not found: {html_archive_path}"
        )
    archive_sha = sha256_file(html_archive_path)
    if archive_sha != EXPECTED_HTML_ARCHIVE_SHA256:
        raise StageCFinalHoldoutFeatureExtractionError(
            f"sealed final HTML archive SHA-256 mismatch: {archive_sha}"
        )

    batches = build_replay_batches(authorized, batch_size=batch_size)
    state = _state_payload(
        batches=batches,
        batch_size=batch_size,
        wait_ms=wait_ms,
        archive_sha256=archive_sha,
        production=production,
        repo_root=repo_root,
        dist=dist,
        git=git,
    )
    output_root.mkdir(parents=True, exist_ok=True)
    state_path = output_root / "feature-extraction-state.json"
    frozen_write_json(state_path, state)

    completed_before = 0
    pending: list[dict[str, Any]] = []
    for batch in batches:
        if _verify_checkpoint(
            output_root=output_root,
            batch=batch,
            state_sha256=str(state["state_sha256"]),
        ):
            completed_before += 1
        else:
            pending.append(batch)

    to_run = pending if max_batches is None else pending[:max_batches]

    if to_run:
        try:
            with zipfile.ZipFile(
                html_archive_path, "r", allowZip64=True
            ) as archive:
                for batch in to_run:
                    episodes = _run_collector(
                        repo_root=repo_root,
                        dist=dist,
                        batch=batch,
                        archive=archive,
                        wait_ms=wait_ms,
                        timeout_seconds=timeout_seconds,
                    )
                    vectors = _extract_vectors(
                        episodes, repo_root=repo_root
                    )
                    payload = _render_checkpoint_rows(batch, vectors)
                    _write_checkpoint(
                        output_root=output_root,
                        batch=batch,
                        payload=payload,
                        state_sha256=str(state["state_sha256"]),
                        collector_hashes=episodes["source_hashes"],
                    )
                    if progress is not None:
                        progress({
                            "event": "BATCH_COMPLETE",
                            "batch_id": batch["batch_id"],
                            "samples": batch["sample_count"],
                        })
        except zipfile.BadZipFile as exc:
            raise StageCFinalHoldoutFeatureExtractionError(
                f"invalid sealed final HTML archive: {exc}"
            ) from exc

    completed = sum(
        int(_verify_checkpoint(
            output_root=output_root,
            batch=batch,
            state_sha256=str(state["state_sha256"]),
        ))
        for batch in batches
    )
    if completed != len(batches):
        return {
            "status": "PARTIAL_CHECKPOINTED",
            "state": str(state_path),
            "state_sha256": state["state_sha256"],
            "completed_batches": completed,
            "total_batches": len(batches),
            "completed_before_this_run": completed_before,
            "remaining_batches": len(batches) - completed,
            "authorized_samples": EXPECTED_CLEAN_SAMPLE_COUNT,
            "collector_ground_truth_blinded": True,
            "model_loaded": False,
            "model_scoring_performed": False,
            "metrics_computed": False,
            "next_gate":
                "EXTRACT_STAGE_C_FINAL_HOLDOUT_FEATURES_AND_SEAL_WITHOUT_MODEL_SCORING",
        }

    return _finalize(
        output_root=output_root,
        batches=batches,
        authorized_rows=authorized,
        state=state,
    )
