"""Stage C Task 10 — checkpointed development feature extraction and audit.

This module is deliberately research-only.  It consumes only the frozen Stage-C
train/selection/calibration membership, replays the corresponding archived HTML
through the existing hardened browser replay collector, and derives the exact
production ``context-features-1`` vector from ``tsfeg.ts``.

It does not train, select, calibrate, threshold, score, or authorize a model.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import base64
from copy import deepcopy
from io import BytesIO
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
from typing import Any, Callable, Iterable, Mapping
import zipfile

STATE_SCHEMA = "stage-c-development-feature-extraction-state-2"
CHECKPOINT_SCHEMA = "stage-c-development-feature-checkpoint-1"
AUDIT_SCHEMA = "stage-c-development-feature-audit-1"
READINESS_SCHEMA = "stage-c-development-feature-readiness-1"

PARTITIONS = ("train", "selection", "calibration")
EXPECTED_PARTITION_COUNTS = {
    "train": {"total": 45750, "legitimate": 22702, "phishing": 23048},
    "selection": {"total": 20712, "legitimate": 19643, "phishing": 1069},
    "calibration": {"total": 7315, "legitimate": 5585, "phishing": 1730},
}
EXPECTED_TOTAL = 73777
EXPECTED_UNIQUE_ARTIFACTS = 61574
EXPECTED_ARCHIVE_SHA256 = "20dc563784f08c31e03665390abb542b325b1120432437bd70a774449f9415c0"
EXPECTED_RECORD_SET_SHA256 = "65b5feeaa44a44511581f4d4d065aa6daaa70d7376088f591a2a1d3eba09cdd9"
EXPECTED_INDEX_EVIDENCE_SHA256 = "d1ee64ef9d08ef8664f85d1e2b123540c6f0d3ecc6e8491a1bd57dd32dd52dd7"
EXPECTED_SPLIT_MANIFEST_SHA256 = "b36708d960bc21f3c325bc5ac9e5a25bb0627b244c378ac643914df38d1365b9"
EXPECTED_AUTHORIZATION_SHA256 = "b83f7038a98704465b4097b7f0b54d3ae62f9d72caa5ec31eb82b4d031bda27b"
EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256 = "9217d4100c711e038229e2c1de2679f0452969067c098c819e1e8b851dabfb16"
EXPECTED_FEATURE_CONTRACT_SHA256 = "2ee75478749e347f84e97b6fb8911a5b961019be6e282b28792a3e70b0c95a6b"
EXPECTED_EXTRACTOR_SOURCE_SHA256 = "6378a55363653da12a101f1cdae33a8b53313d20aee8db95e1deb21fe1e57d74"
EXPECTED_FEATURES = [
    "document_started", "has_password", "has_otp", "has_payment", "has_identity",
    "purpose_authentication", "purpose_payment", "purpose_unknown",
    "sensitive_form_count", "same_origin_sensitive_target",
    "cross_origin_sensitive_target", "stable_sensitive_target",
    "sensitive_target_changed", "target_changed_after_interaction",
    "submission_target_mismatch", "https_downgrade_sensitive_target",
    "password_then_otp", "dynamic_sensitive_field",
    "foreign_frame_sensitive_field", "cross_request_near_interaction",
    "unknown_document_ratio", "known_target_ratio", "contradiction_count",
    "positive_evidence_count", "purpose_sensitive_mismatch",
    "purpose_context_consistent", "purpose_observed",
]

# Compatibility-only sentinel required by the older replay-plan validator.  It is
# never copied into a checkpoint or final feature row and is not source evidence.
REPLAY_ADAPTER_TIME_SENTINEL = "2000-01-01T00:00:00+00:00"
REPLAY_SOURCE_GROUP = "mendeley-n96ncsr5g4-v1"


class StageCFeatureExtractionError(ValueError):
    """Raised when a Task-10 integrity or resume guard fails."""


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
        raise StageCFeatureExtractionError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFeatureExtractionError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCFeatureExtractionError(f"JSON root must be an object: {path}")
    return value


def _hash_without(value: Mapping[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return canonical_hash(copy)


def _atomic_frozen_text(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = path.read_bytes()
        if current != payload:
            raise StageCFeatureExtractionError(
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
        if tmp.exists():
            tmp.unlink(missing_ok=True)
    return "CREATED"


def frozen_write_json(path: Path, value: Any) -> str:
    rendered = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return _atomic_frozen_text(path, rendered)


def _require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise StageCFeatureExtractionError(f"invalid SHA-256 field: {name}")
    try:
        int(value, 16)
    except ValueError as exc:
        raise StageCFeatureExtractionError(f"invalid SHA-256 field: {name}") from exc
    return value.lower()


def _validate_record_index(index: Mapping[str, Any]) -> list[dict[str, Any]]:
    required = {
        "schema_version": "stage-c-development-record-index-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "record_count": 80000,
        "record_set_sha256": EXPECTED_RECORD_SET_SHA256,
    }
    for key, expected in required.items():
        if index.get(key) != expected:
            raise StageCFeatureExtractionError(f"Task-6 record-index guard mismatch: {key}")
    rows = index.get("records")
    if not isinstance(rows, list) or len(rows) != 80000:
        raise StageCFeatureExtractionError("Task-6 record rows are missing or incomplete")
    if canonical_hash(rows) != EXPECTED_RECORD_SET_SHA256:
        raise StageCFeatureExtractionError("Task-6 record-set hash does not reproduce")
    source = index.get("source")
    if not isinstance(source, Mapping):
        raise StageCFeatureExtractionError("Task-6 source identity missing")
    if str(source.get("archive_sha256", "")).lower() != EXPECTED_ARCHIVE_SHA256:
        raise StageCFeatureExtractionError("Task-6 archive identity changed")
    return rows


def _validate_index_report(report: Mapping[str, Any]) -> dict[str, str]:
    required = {
        "schema_version": "stage-c-development-record-index-report-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "record_count": 80000,
        "record_set_sha256": EXPECTED_RECORD_SET_SHA256,
        "index_evidence_sha256": EXPECTED_INDEX_EVIDENCE_SHA256,
    }
    for key, expected in required.items():
        if report.get(key) != expected:
            raise StageCFeatureExtractionError(f"Task-6 report guard mismatch: {key}")
    if _hash_without(report, "index_evidence_sha256") != EXPECTED_INDEX_EVIDENCE_SHA256:
        raise StageCFeatureExtractionError("Task-6 report evidence hash does not reproduce")
    nested = report.get("nested_archives")
    if not isinstance(nested, list) or len(nested) != 8:
        raise StageCFeatureExtractionError("Task-6 nested archive inventory is invalid")
    hashes: dict[str, str] = {}
    for row in nested:
        if not isinstance(row, Mapping):
            raise StageCFeatureExtractionError("Task-6 nested archive row is invalid")
        name = row.get("nested_archive")
        digest = row.get("nested_archive_sha256")
        if not isinstance(name, str) or not name:
            raise StageCFeatureExtractionError("Task-6 nested archive name missing")
        hashes[name] = _require_sha(digest, f"nested archive {name}")
    if len(hashes) != 8:
        raise StageCFeatureExtractionError("Task-6 nested archive identities are not unique")
    return hashes


def _validate_split_manifest(manifest: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    required = {
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
        "partition_counts": EXPECTED_PARTITION_COUNTS,
    }
    for key, expected in required.items():
        if manifest.get(key) != expected:
            raise StageCFeatureExtractionError(f"Task-8 split-manifest guard mismatch: {key}")
    if _hash_without(manifest, "manifest_sha256") != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise StageCFeatureExtractionError("Task-8 split-manifest hash does not reproduce")
    parts = manifest.get("partitions")
    if not isinstance(parts, Mapping) or set(parts) != set(PARTITIONS):
        raise StageCFeatureExtractionError("Task-8 supervised partitions are invalid")
    out: dict[str, list[dict[str, Any]]] = {}
    all_ids: list[str] = []
    artifacts: dict[str, str] = {}
    for part in PARTITIONS:
        rows = parts.get(part)
        if not isinstance(rows, list):
            raise StageCFeatureExtractionError(f"Task-8 partition rows missing: {part}")
        if len(rows) != EXPECTED_PARTITION_COUNTS[part]["total"]:
            raise StageCFeatureExtractionError(f"Task-8 partition count changed: {part}")
        legit = phish = 0
        normalized: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                raise StageCFeatureExtractionError("Task-8 split row is not an object")
            sid = raw.get("sample_id")
            digest = raw.get("html_sha256")
            label = raw.get("label")
            if not isinstance(sid, str) or not sid:
                raise StageCFeatureExtractionError("Task-8 sample_id missing")
            digest = _require_sha(digest, "Task-8 html_sha256")
            if label not in (0, 1):
                raise StageCFeatureExtractionError("Task-8 label is not binary")
            if sid in all_ids:
                raise StageCFeatureExtractionError(f"duplicate supervised sample: {sid}")
            all_ids.append(sid)
            if digest in artifacts and artifacts[digest] != part:
                raise StageCFeatureExtractionError("artifact identity crosses supervised partitions")
            artifacts[digest] = part
            legit += int(label == 0)
            phish += int(label == 1)
            normalized.append(dict(raw))
        if {"total": len(rows), "legitimate": legit, "phishing": phish} != EXPECTED_PARTITION_COUNTS[part]:
            raise StageCFeatureExtractionError(f"Task-8 label counts changed: {part}")
        out[part] = normalized
    if len(all_ids) != EXPECTED_TOTAL:
        raise StageCFeatureExtractionError("Task-8 supervised sample count changed")
    if canonical_hash(sorted(all_ids)) != EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256:
        raise StageCFeatureExtractionError("Task-8 supervised sample identity changed")
    if len(artifacts) != EXPECTED_UNIQUE_ARTIFACTS:
        raise StageCFeatureExtractionError("Task-8 unique artifact count changed")
    return out


def _validate_authorization(auth: Mapping[str, Any], *, expected_sha256: str) -> list[str]:
    expected_sha256 = _require_sha(expected_sha256, "expected authorization")
    if expected_sha256 != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCFeatureExtractionError(
            "Task-10 is frozen to the current Task-9-v2 authorization identity"
        )
    required = {
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
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
    }
    for key, expected in required.items():
        if auth.get(key) != expected:
            raise StageCFeatureExtractionError(f"Task-9-v2 authorization guard mismatch: {key}")
    if _hash_without(auth, "authorization_sha256") != EXPECTED_AUTHORIZATION_SHA256:
        raise StageCFeatureExtractionError("Task-9-v2 authorization hash does not reproduce")
    scope = auth.get("scope")
    if not isinstance(scope, Mapping):
        raise StageCFeatureExtractionError("Task-9-v2 authorization scope missing")
    if scope.get("authorized_partitions") != list(PARTITIONS):
        raise StageCFeatureExtractionError("Task-9-v2 authorized partitions changed")
    if scope.get("authorized_sample_count") != EXPECTED_TOTAL:
        raise StageCFeatureExtractionError("Task-9-v2 authorized sample count changed")
    if scope.get("authorized_sample_set_sha256") != EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256:
        raise StageCFeatureExtractionError("Task-9-v2 authorized sample identity changed")
    if scope.get("task8_quarantine_authorized") is not False:
        raise StageCFeatureExtractionError("Task-8 quarantine unexpectedly authorized")
    if scope.get("stage_b_consumed_test_authorized") is not False:
        raise StageCFeatureExtractionError("consumed evaluation data unexpectedly authorized")
    if scope.get("stage_c_final_holdout_authorized") is not False:
        raise StageCFeatureExtractionError("independent evaluation data unexpectedly authorized")
    feature = auth.get("feature_contract")
    if not isinstance(feature, Mapping):
        raise StageCFeatureExtractionError("Task-9-v2 feature contract missing")
    names = feature.get("ordered_features")
    if names != EXPECTED_FEATURES or feature.get("feature_count") != 27:
        raise StageCFeatureExtractionError("Task-9-v2 production feature order changed")
    if feature.get("source_feature_version") != "context-features-1":
        raise StageCFeatureExtractionError("Task-9-v2 feature version changed")
    if feature.get("feature_contract_sha256") != EXPECTED_FEATURE_CONTRACT_SHA256:
        raise StageCFeatureExtractionError("Task-9-v2 feature contract identity changed")
    if feature.get("extractor_source_sha256") != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCFeatureExtractionError("Task-9-v2 extractor identity changed")
    if feature.get("order_source") != "PRODUCTION_TSFEG_CONTEXT_FEATURES_EXPORT":
        raise StageCFeatureExtractionError("Task-9-v2 feature order source changed")
    if feature.get("raw_html_persistence_in_feature_output_authorized") is not False:
        raise StageCFeatureExtractionError("raw HTML persistence unexpectedly authorized")
    if feature.get("raw_url_persistence_in_feature_output_authorized") is not False:
        raise StageCFeatureExtractionError("raw URL persistence unexpectedly authorized")
    if feature.get("sample_id_model_observable") is not False:
        raise StageCFeatureExtractionError("sample_id unexpectedly model-observable")
    bindings = auth.get("identity_bindings")
    if not isinstance(bindings, Mapping) or bindings.get("split_manifest_sha256") != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise StageCFeatureExtractionError("Task-9-v2 split binding changed")
    return list(names)


def _load_production_contract(repo_root: Path) -> dict[str, Any]:
    tsfeg = repo_root / "browser-extension" / "src" / "core" / "tsfeg.ts"
    if not tsfeg.is_file():
        raise StageCFeatureExtractionError("production TSFEG source not found")
    source_sha = sha256_file(tsfeg)
    if source_sha != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCFeatureExtractionError(
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
            ["node", "--experimental-strip-types", "--input-type=module", "-e", source, str(tsfeg.resolve())],
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8", check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        details = getattr(exc, "stderr", "") or str(exc)
        raise StageCFeatureExtractionError(f"production feature probe failed: {details.strip()}") from exc
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StageCFeatureExtractionError("production feature probe returned invalid JSON") from exc
    names = payload.get("ordered_features")
    version = payload.get("feature_version")
    if version != "context-features-1" or names != EXPECTED_FEATURES:
        raise StageCFeatureExtractionError("production feature exports differ from Task-9-v2")
    contract_sha = canonical_hash({"feature_version": version, "feature_names": names})
    if contract_sha != EXPECTED_FEATURE_CONTRACT_SHA256:
        raise StageCFeatureExtractionError("production feature contract hash changed")
    return {
        "feature_version": version,
        "ordered_features": names,
        "feature_contract_sha256": contract_sha,
        "extractor_source_sha256": source_sha,
    }


def _authorized_rows(
    *, index_rows: list[dict[str, Any]], partitions: Mapping[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in index_rows:
        sid = row.get("sample_id")
        if not isinstance(sid, str) or not sid or sid in by_id:
            raise StageCFeatureExtractionError("Task-6 sample identity is missing or duplicated")
        by_id[sid] = row
    out: list[dict[str, Any]] = []
    for partition in PARTITIONS:
        for split_row in partitions[partition]:
            sid = str(split_row["sample_id"])
            source = by_id.get(sid)
            if source is None:
                raise StageCFeatureExtractionError(f"authorized sample missing from Task-6 index: {sid}")
            if int(source.get("label", -1)) != int(split_row["label"]):
                raise StageCFeatureExtractionError(f"label mismatch for authorized sample: {sid}")
            if str(source.get("html_sha256", "")).lower() != str(split_row["html_sha256"]).lower():
                raise StageCFeatureExtractionError(f"artifact mismatch for authorized sample: {sid}")
            if bool(source.get("oversized_over_12_mib")):
                raise StageCFeatureExtractionError(f"oversized sample survived authorization: {sid}")
            nested = source.get("nested_archive")
            member = source.get("member_name")
            if not isinstance(nested, str) or not nested or not isinstance(member, str) or not member:
                raise StageCFeatureExtractionError(f"archive locator missing for authorized sample: {sid}")
            size = source.get("html_size_bytes")
            if type(size) is not int or not 0 < size <= 12 * 1024 * 1024:
                raise StageCFeatureExtractionError(f"invalid authorized HTML size: {sid}")
            out.append({
                "sample_id": sid,
                "partition": partition,
                "label": int(split_row["label"]),
                "html_sha256": str(split_row["html_sha256"]).lower(),
                "nested_archive": nested,
                "member_name": member,
                "html_size_bytes": size,
            })
    if len(out) != EXPECTED_TOTAL or len({x["sample_id"] for x in out}) != EXPECTED_TOTAL:
        raise StageCFeatureExtractionError("authorized Task-10 row accounting failed")
    if canonical_hash(sorted(x["sample_id"] for x in out)) != EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256:
        raise StageCFeatureExtractionError("authorized Task-10 sample set changed")
    return out


def build_replay_batches(rows: Iterable[Mapping[str, Any]], *, batch_size: int) -> list[dict[str, Any]]:
    """Build deterministic batches with no duplicate artifact inside one replay plan.

    Every authorized sample is replayed exactly once. Exact duplicate artifacts
    are placed in different batches instead of reusing one sample's vector. For
    each nested ZIP, the number of batches is the lower-bound maximum of
    ``ceil(samples / batch_size)`` and the largest duplicate multiplicity, with
    deterministic least-loaded assignment.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise StageCFeatureExtractionError("batch_size must be between 1 and 1000")
    source_rows = [dict(raw) for raw in rows]
    by_nested: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in source_rows:
        nested = row.get("nested_archive")
        digest = row.get("html_sha256")
        if not isinstance(nested, str) or not nested:
            raise StageCFeatureExtractionError("replay row nested_archive missing")
        _require_sha(digest, "replay row html_sha256")
        by_nested[nested].append(row)

    batches: list[dict[str, Any]] = []
    sequence = 0
    for nested in sorted(by_nested):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in by_nested[nested]:
            groups[str(row["html_sha256"])].append(row)
        for members in groups.values():
            members.sort(key=lambda x: (str(x["member_name"]), str(x["sample_id"])))
        total = sum(len(members) for members in groups.values())
        max_multiplicity = max((len(members) for members in groups.values()), default=0)
        bin_count = max(max_multiplicity, (total + batch_size - 1) // batch_size)
        bins: list[list[dict[str, Any]]] = [[] for _ in range(bin_count)]

        # Place the hardest groups first. For one artifact group, each member
        # must occupy a different bin so the compatibility validator never sees
        # the same byte-identical artifact twice in one plan.
        ordered_groups = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
        for _, members in ordered_groups:
            candidates = sorted(
                (i for i in range(bin_count) if len(bins[i]) < batch_size),
                key=lambda i: (len(bins[i]), i),
            )
            if len(candidates) < len(members):
                raise StageCFeatureExtractionError(
                    "cannot construct duplicate-safe replay batches within batch_size"
                )
            for row, bin_index in zip(members, candidates[:len(members)], strict=True):
                bins[bin_index].append(row)

        for rows_in_bin in bins:
            if not rows_in_bin:
                continue
            rows_in_bin.sort(key=lambda x: (str(x["member_name"]), str(x["sample_id"])))
            hashes = [str(x["html_sha256"]) for x in rows_in_bin]
            if len(hashes) != len(set(hashes)):
                raise StageCFeatureExtractionError("duplicate artifact entered one replay batch")
            sequence += 1
            descriptor_core = {
                "nested_archive": nested,
                "sample_ids": [str(x["sample_id"]) for x in rows_in_bin],
                "artifact_sha256": hashes,
            }
            digest = canonical_hash(descriptor_core)
            batches.append({
                "batch_id": f"batch-{sequence:05d}-{digest[:12]}",
                "nested_archive": nested,
                "sample_count": len(rows_in_bin),
                "sample_set_sha256": canonical_hash(sorted(descriptor_core["sample_ids"])),
                "artifact_set_sha256": canonical_hash(sorted(hashes)),
                "rows": rows_in_bin,
            })
    flattened = [sid for batch in batches for sid in [str(x["sample_id"]) for x in batch["rows"]]]
    expected = [str(x["sample_id"]) for x in source_rows]
    if len(flattened) != len(expected) or set(flattened) != set(expected):
        raise StageCFeatureExtractionError("replay batch schedule lost or added samples")
    return batches



def _git_provenance(repo_root: Path) -> dict[str, str]:
    committed_paths = [
        "ml/data/stage_c_development_feature_extraction.py",
        "ml/data/extract_stage_c_development_features.py",
        "scripts/stage-b-collect-archive-replay.mjs",
        "browser-extension/src/core/tsfeg.ts",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, capture_output=True,
            text=True, encoding="utf-8", check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCFeatureExtractionError("invalid Git HEAD identity")
        for relative in committed_paths[:3]:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"], cwd=repo_root,
                capture_output=True, check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *committed_paths], cwd=repo_root
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCFeatureExtractionError(
            "Task-10 implementation must be committed before feature extraction"
        ) from exc
    if dirty != 0:
        raise StageCFeatureExtractionError(
            "Task-10/collector/extractor tracked files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task10_module_sha256": sha256_file(repo_root / committed_paths[0]),
        "task10_cli_sha256": sha256_file(repo_root / committed_paths[1]),
    }

def _state_payload(
    *, batches: list[dict[str, Any]], batch_size: int, wait_ms: int,
    archive_sha256: str, production: Mapping[str, Any], repo_root: Path, dist: Path,
    git_provenance: Mapping[str, str],
) -> dict[str, Any]:
    if type(wait_ms) is not int or not 250 <= wait_ms <= 10000:
        raise StageCFeatureExtractionError("wait_ms must be between 250 and 10000")
    collector = repo_root / "scripts" / "stage-c-collect-memory-replay.mjs"
    required_dist = [dist / "manifest.json", dist / "collector.js", dist / "service-worker.js"]
    if not collector.is_file():
        raise StageCFeatureExtractionError("existing archive replay collector not found")
    missing = [str(p) for p in required_dist if not p.is_file()]
    if missing:
        raise StageCFeatureExtractionError(
            "built extension is missing; run the project build first: " + ", ".join(missing)
        )
    descriptors = [{
        "batch_id": b["batch_id"],
        "nested_archive": b["nested_archive"],
        "sample_count": b["sample_count"],
        "sample_set_sha256": b["sample_set_sha256"],
        "artifact_set_sha256": b["artifact_set_sha256"],
    } for b in batches]
    state = {
        "schema_version": STATE_SCHEMA,
        "status": "READY",
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
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "record_set_sha256": EXPECTED_RECORD_SET_SHA256,
        "archive_sha256": archive_sha256,
        "authorized_sample_set_sha256": EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256,
        "authorized_sample_count": EXPECTED_TOTAL,
        "feature_contract_sha256": production["feature_contract_sha256"],
        "extractor_source_sha256": production["extractor_source_sha256"],
        "configuration": {
            "batch_size": batch_size,
            "wait_ms": wait_ms,
            "replay_each_authorized_sample_exactly_once": True,
            "duplicate_artifacts_never_share_one_replay_batch": True,
            "memory_replay_transport": "STDIN_NDJSON_BASE64",
            "raw_html_materialized_to_disk": False,
            "git_head": git_provenance["git_head"],
            "task10_module_sha256": git_provenance["task10_module_sha256"],
            "task10_cli_sha256": git_provenance["task10_cli_sha256"],
            "collector_script_sha256": sha256_file(collector),
            "dist_manifest_sha256": sha256_file(dist / "manifest.json"),
            "dist_collector_sha256": sha256_file(dist / "collector.js"),
            "dist_service_worker_sha256": sha256_file(dist / "service-worker.js"),
        },
        "schedule": {
            "batch_count": len(batches),
            "sample_count": sum(int(b["sample_count"]) for b in batches),
            "batches": descriptors,
        },
    }
    state["schedule"]["schedule_sha256"] = canonical_hash(descriptors)
    state["state_sha256"] = canonical_hash(state)
    return state


def _memory_plan(batch: Mapping[str, Any], *, wait_ms: int) -> dict[str, Any]:
    return {
        "schema_version": "stage-c-memory-replay-plan-1",
        "plan_id": f"stage-c-task10-{batch['batch_id']}",
        "items": [
            {
                "sample_id": str(row["sample_id"]),
                "ground_truth": int(row["label"]),
                "artifact_sha256": str(row["html_sha256"]),
                "wait_ms": wait_ms,
            }
            for row in batch["rows"]
        ],
    }


def _run_collector(
    *, repo_root: Path, dist: Path, batch: Mapping[str, Any], nested: zipfile.ZipFile,
    wait_ms: int, timeout_seconds: int,
) -> dict[str, Any]:
    collector = repo_root / "scripts" / "stage-c-collect-memory-replay.mjs"
    with tempfile.TemporaryDirectory(prefix="stage-c-task10-meta-") as temp_name:
        root = Path(temp_name)
        plan_path = root / "plan.json"
        output_path = root / "episodes.json"
        plan_path.write_text(
            json.dumps(_memory_plan(batch, wait_ms=wait_ms), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        command = [
            "node", str(collector), "--plan", str(plan_path),
            "--output", str(output_path), "--dist", str(dist),
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
                raise StageCFeatureExtractionError("memory replay stdin pipe unavailable")
            try:
                for row in batch["rows"]:
                    sid = str(row["sample_id"])
                    member = str(row["member_name"])
                    try:
                        info = nested.getinfo(member)
                    except KeyError as exc:
                        raise StageCFeatureExtractionError(
                            f"nested HTML member missing for {sid}: {member}"
                        ) from exc
                    if info.is_dir() or int(info.file_size) != int(row["html_size_bytes"]):
                        raise StageCFeatureExtractionError(
                            f"nested HTML size/type mismatch for {sid}"
                        )
                    payload = nested.read(info)
                    if len(payload) != int(row["html_size_bytes"]):
                        raise StageCFeatureExtractionError(
                            f"in-memory HTML size mismatch for {sid}"
                        )
                    digest = hashlib.sha256(payload).hexdigest()
                    if digest != row["html_sha256"]:
                        raise StageCFeatureExtractionError(
                            f"in-memory HTML SHA-256 mismatch for {sid}"
                        )
                    envelope = {
                        "sample_id": sid,
                        "html_base64": base64.b64encode(payload).decode("ascii"),
                    }
                    process.stdin.write(
                        json.dumps(envelope, separators=(",", ":")) + "\n"
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
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                stdout, stderr = process.communicate()
                raise StageCFeatureExtractionError(
                    f"memory browser replay timed out for {batch['batch_id']}"
                ) from exc
        except StageCFeatureExtractionError:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            raise
        except OSError as exc:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            raise StageCFeatureExtractionError(
                f"memory browser replay failed to execute for {batch['batch_id']}: {exc}"
            ) from exc

        if process is None:
            raise StageCFeatureExtractionError("memory browser replay process unavailable")
        if feeder_error is not None or process.returncode != 0:
            details = (stderr or stdout or str(feeder_error) or "collector failed").strip()
            raise StageCFeatureExtractionError(
                f"memory browser replay failed for {batch['batch_id']}: {details[-4000:]}"
            )
        episodes = load_json(output_path)

    if episodes.get("schema_version") != "stage-b-event-episodes-1":
        raise StageCFeatureExtractionError("replay episode schema changed")
    if episodes.get("collector_version") != "stage-c-memory-replay-1":
        raise StageCFeatureExtractionError("memory replay collector version changed")
    failures = episodes.get("failures")
    if failures != []:
        raise StageCFeatureExtractionError(
            f"memory replay batch contains failures: {batch['batch_id']}"
        )
    rows = episodes.get("episodes")
    if not isinstance(rows, list) or len(rows) != int(batch["sample_count"]):
        raise StageCFeatureExtractionError("replay episode count mismatch")
    expected_ids = {str(x["sample_id"]) for x in batch["rows"]}
    actual_ids = {x.get("sample_id") for x in rows if isinstance(x, Mapping)}
    if actual_ids != expected_ids or len(actual_ids) != len(rows):
        raise StageCFeatureExtractionError("replay episode sample identity mismatch")
    safety = episodes.get("safety_policy")
    if not isinstance(safety, Mapping):
        raise StageCFeatureExtractionError("replay safety policy missing")
    for key in (
        "archived_local_files_only", "replay_origin_loopback_only",
        "page_scripts_disabled_by_csp", "form_submission_disabled_by_csp",
        "frames_and_objects_disabled_by_csp", "external_network_requests_aborted",
        "raw_html_received_via_stdin_memory_stream",
        "browser_response_cache_control_no_store",
    ):
        if safety.get(key) is not True:
            raise StageCFeatureExtractionError(f"replay safety guard failed: {key}")
    if safety.get("raw_html_persisted_in_episode_output") is not False:
        raise StageCFeatureExtractionError("replay unexpectedly persisted raw HTML")
    if safety.get("raw_html_materialized_to_disk") is not False:
        raise StageCFeatureExtractionError("replay materialized raw HTML to disk")
    source_hashes = episodes.get("source_hashes")
    if not isinstance(source_hashes, Mapping):
        raise StageCFeatureExtractionError("replay source hashes missing")
    if source_hashes.get("tsfeg_source_sha256") != EXPECTED_EXTRACTOR_SOURCE_SHA256:
        raise StageCFeatureExtractionError("replay used a different TSFEG source")
    return episodes


def _extract_vectors(
    episodes: Mapping[str, Any], *, repo_root: Path
) -> dict[str, list[float | int]]:
    tsfeg = (repo_root / "browser-extension" / "src" / "core" / "tsfeg.ts").resolve()
    source = r"""
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const core = await import(pathToFileURL(process.argv[1]).href);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const rows = input.map(row => {
  const out = core.buildContextFeatures(row.events, false);
  return { sample_id: row.sample_id, vector: out.vector };
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
            ["node", "--experimental-strip-types", "--input-type=module", "-e", source, str(tsfeg)],
            input=json.dumps(input_rows, separators=(",", ":")),
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8", check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        details = getattr(exc, "stderr", "") or str(exc)
        raise StageCFeatureExtractionError(f"production feature extraction failed: {details.strip()}") from exc
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StageCFeatureExtractionError("production feature extractor returned invalid JSON") from exc
    if output.get("feature_version") != "context-features-1" or output.get("feature_names") != EXPECTED_FEATURES:
        raise StageCFeatureExtractionError("production feature contract changed during extraction")
    if canonical_hash({"feature_version": output["feature_version"], "feature_names": output["feature_names"]}) != EXPECTED_FEATURE_CONTRACT_SHA256:
        raise StageCFeatureExtractionError("production feature contract hash changed during extraction")
    result: dict[str, list[float | int]] = {}
    rows = output.get("rows")
    if not isinstance(rows, list):
        raise StageCFeatureExtractionError("production extractor rows missing")
    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCFeatureExtractionError("production extractor row invalid")
        sid = row.get("sample_id")
        vector = row.get("vector")
        if not isinstance(sid, str) or sid in result:
            raise StageCFeatureExtractionError("production extractor sample identity invalid")
        if not isinstance(vector, list) or len(vector) != 27:
            raise StageCFeatureExtractionError(f"production feature vector shape mismatch: {sid}")
        if any(type(value) not in (int, float) or not math.isfinite(value) for value in vector):
            raise StageCFeatureExtractionError(f"non-finite production feature vector: {sid}")
        result[sid] = list(vector)
    return result


def _render_checkpoint_rows(batch: Mapping[str, Any], vectors: Mapping[str, list[float | int]]) -> bytes:
    lines: list[bytes] = []
    for row in sorted(batch["rows"], key=lambda x: str(x["sample_id"])):
        sid = str(row["sample_id"])
        vector = vectors.get(sid)
        if vector is None:
            raise StageCFeatureExtractionError(f"feature vector missing for replayed sample: {sid}")
        feature_row = {
            "sample_id": sid,
            "partition": str(row["partition"]),
            "label": int(row["label"]),
            "feature_vector": vector,
        }
        lines.append(canonical_bytes(feature_row) + b"\n")
    return b"".join(lines)


def _checkpoint_paths(output_root: Path, batch_id: str) -> tuple[Path, Path]:
    root = output_root / "feature-extraction-checkpoints"
    return root / f"{batch_id}.features.jsonl", root / f"{batch_id}.seal.json"


def _verify_checkpoint(
    *, output_root: Path, batch: Mapping[str, Any], state_sha256: str,
) -> bool:
    features_path, seal_path = _checkpoint_paths(output_root, str(batch["batch_id"]))
    if not features_path.exists() and not seal_path.exists():
        return False
    if features_path.exists() != seal_path.exists():
        raise StageCFeatureExtractionError(
            f"incomplete checkpoint pair; remove only after investigation: {batch['batch_id']}"
        )
    seal = load_json(seal_path)
    required = {
        "schema_version": CHECKPOINT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "batch_id": batch["batch_id"],
        "state_sha256": state_sha256,
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "record_set_sha256": EXPECTED_RECORD_SET_SHA256,
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
        "sample_count": batch["sample_count"],
        "sample_set_sha256": batch["sample_set_sha256"],
        "artifact_set_sha256": batch["artifact_set_sha256"],
        "raw_html_persisted": False,
        "raw_url_persisted": False,
        "model_training_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
    }
    for key, expected in required.items():
        if seal.get(key) != expected:
            raise StageCFeatureExtractionError(
                f"non-identical checkpoint resume state: {batch['batch_id']}:{key}"
            )
    if _hash_without(seal, "checkpoint_sha256") != seal.get("checkpoint_sha256"):
        raise StageCFeatureExtractionError(f"checkpoint seal hash mismatch: {batch['batch_id']}")
    actual_features_sha = sha256_file(features_path)
    if seal.get("features_jsonl_sha256") != actual_features_sha:
        raise StageCFeatureExtractionError(f"checkpoint feature-file hash mismatch: {batch['batch_id']}")
    rows = _read_jsonl(features_path)
    if len(rows) != int(batch["sample_count"]):
        raise StageCFeatureExtractionError(f"checkpoint row count mismatch: {batch['batch_id']}")
    expected_ids = {str(x["sample_id"]) for x in batch["rows"]}
    actual_ids = {x.get("sample_id") for x in rows}
    if actual_ids != expected_ids or len(actual_ids) != len(rows):
        raise StageCFeatureExtractionError(f"checkpoint sample identity mismatch: {batch['batch_id']}")
    for row in rows:
        _validate_feature_row(row)
    return True


def _write_checkpoint(
    *, output_root: Path, batch: Mapping[str, Any], payload: bytes,
    state_sha256: str, collector_hashes: Mapping[str, Any],
) -> None:
    features_path, seal_path = _checkpoint_paths(output_root, str(batch["batch_id"]))
    if features_path.exists() or seal_path.exists():
        raise StageCFeatureExtractionError(f"checkpoint already exists unexpectedly: {batch['batch_id']}")
    _atomic_frozen_text(features_path, payload)
    seal = {
        "schema_version": CHECKPOINT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "batch_id": batch["batch_id"],
        "state_sha256": state_sha256,
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "record_set_sha256": EXPECTED_RECORD_SET_SHA256,
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
        "sample_count": batch["sample_count"],
        "sample_set_sha256": batch["sample_set_sha256"],
        "artifact_set_sha256": batch["artifact_set_sha256"],
        "features_jsonl_sha256": hashlib.sha256(payload).hexdigest(),
        "collector_source_hashes": dict(collector_hashes),
        "raw_html_persisted": False,
        "raw_url_persisted": False,
        "model_training_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
    }
    seal["checkpoint_sha256"] = canonical_hash(seal)
    frozen_write_json(seal_path, seal)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                raise StageCFeatureExtractionError(f"blank JSONL row at {path}:{line_number}")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCFeatureExtractionError(f"invalid JSONL at {path}:{line_number}") from exc
            if not isinstance(row, dict):
                raise StageCFeatureExtractionError(f"JSONL row is not an object at {path}:{line_number}")
            rows.append(row)
    return rows


def _validate_feature_row(row: Mapping[str, Any]) -> None:
    if set(row) != {"sample_id", "partition", "label", "feature_vector"}:
        raise StageCFeatureExtractionError("feature row contains prohibited or unexpected fields")
    if not isinstance(row.get("sample_id"), str) or not row.get("sample_id"):
        raise StageCFeatureExtractionError("feature row sample_id invalid")
    if row.get("partition") not in PARTITIONS:
        raise StageCFeatureExtractionError("feature row partition invalid")
    if row.get("label") not in (0, 1):
        raise StageCFeatureExtractionError("feature row label invalid")
    vector = row.get("feature_vector")
    if not isinstance(vector, list) or len(vector) != 27:
        raise StageCFeatureExtractionError("feature row vector shape invalid")
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in vector):
        raise StageCFeatureExtractionError("feature row contains NaN/Infinity/non-numeric value")


def _finalize(
    *, output_root: Path, batches: list[dict[str, Any]], partitions: Mapping[str, list[dict[str, Any]]],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    checkpoint_rows: dict[str, dict[str, Any]] = {}
    checkpoint_file_hashes: list[dict[str, str]] = []
    for batch in batches:
        features_path, seal_path = _checkpoint_paths(output_root, str(batch["batch_id"]))
        if not _verify_checkpoint(output_root=output_root, batch=batch, state_sha256=str(state["state_sha256"])):
            raise StageCFeatureExtractionError(f"cannot finalize with missing checkpoint: {batch['batch_id']}")
        checkpoint_file_hashes.append({
            "batch_id": str(batch["batch_id"]),
            "features_jsonl_sha256": sha256_file(features_path),
            "seal_sha256": sha256_file(seal_path),
        })
        for row in _read_jsonl(features_path):
            sid = str(row["sample_id"])
            if sid in checkpoint_rows:
                raise StageCFeatureExtractionError(f"duplicate sample across checkpoints: {sid}")
            _validate_feature_row(row)
            checkpoint_rows[sid] = row

    expected: dict[str, tuple[str, int]] = {}
    manifest_order: list[str] = []
    for part in PARTITIONS:
        for raw in partitions[part]:
            sid = str(raw["sample_id"])
            expected[sid] = (part, int(raw["label"]))
            manifest_order.append(sid)
    if set(checkpoint_rows) != set(expected):
        missing = sorted(set(expected) - set(checkpoint_rows))[:5]
        extras = sorted(set(checkpoint_rows) - set(expected))[:5]
        raise StageCFeatureExtractionError(f"feature sample coverage mismatch; missing={missing} extras={extras}")

    observed_counts: dict[str, Counter[int]] = {part: Counter() for part in PARTITIONS}
    for sid, (part, label) in expected.items():
        row = checkpoint_rows[sid]
        if row["partition"] != part or row["label"] != label:
            raise StageCFeatureExtractionError(f"feature label/partition alignment failed: {sid}")
        observed_counts[part][label] += 1
    reproduced_counts = {
        part: {
            "total": observed_counts[part][0] + observed_counts[part][1],
            "legitimate": observed_counts[part][0],
            "phishing": observed_counts[part][1],
        }
        for part in PARTITIONS
    }
    if reproduced_counts != EXPECTED_PARTITION_COUNTS:
        raise StageCFeatureExtractionError("final feature partition counts changed")

    final_path = output_root / "development-features.jsonl"
    temp_path = final_path.with_name(f".{final_path.name}.assemble-{os.getpid()}")
    final_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with temp_path.open("wb") as handle:
            for sid in manifest_order:
                handle.write(canonical_bytes(checkpoint_rows[sid]) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        assembled = temp_path.read_bytes()
        _atomic_frozen_text(final_path, assembled)
    finally:
        temp_path.unlink(missing_ok=True)

    dataset_sha = sha256_file(final_path)
    feature_rows_identity = canonical_hash([
        {
            "sample_id": sid,
            "partition": checkpoint_rows[sid]["partition"],
            "label": checkpoint_rows[sid]["label"],
            "feature_vector": checkpoint_rows[sid]["feature_vector"],
        }
        for sid in sorted(checkpoint_rows)
    ])
    audits = {
        "EXACT_ROW_COUNT_PER_PARTITION": True,
        "FEATURE_SCHEMA_EXACT_MATCH": True,
        "PRODUCTION_FEATURE_ORDER_EXACT_MATCH": True,
        "NO_NAN_OR_INF": True,
        "NO_PROHIBITED_MODEL_OBSERVABLES": True,
        "SAMPLE_ID_JOIN_COVERAGE": True,
        "LABEL_ALIGNMENT": True,
        "PARTITION_IDENTITY_REPRODUCTION": True,
        "FEATURE_DATASET_HASH_FREEZE": True,
    }
    audit = {
        "schema_version": AUDIT_SCHEMA,
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
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "state_sha256": state["state_sha256"],
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "record_set_sha256": EXPECTED_RECORD_SET_SHA256,
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "authorized_sample_set_sha256": EXPECTED_AUTHORIZED_SAMPLE_SET_SHA256,
        "feature_version": "context-features-1",
        "feature_count": 27,
        "ordered_features": EXPECTED_FEATURES,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "extractor_source_sha256": EXPECTED_EXTRACTOR_SOURCE_SHA256,
        "partition_counts": reproduced_counts,
        "total_rows": len(checkpoint_rows),
        "feature_dataset_sha256": dataset_sha,
        "feature_row_set_sha256": feature_rows_identity,
        "checkpoint_set_sha256": canonical_hash(checkpoint_file_hashes),
        "model_observable_fields": ["feature_vector"],
        "metadata_only_fields": ["sample_id", "partition", "label"],
        "raw_html_persisted": False,
        "raw_url_persisted": False,
        "audits": audits,
    }
    audit["audit_sha256"] = canonical_hash(audit)
    audit_path = output_root / "development-feature-audit.json"
    frozen_write_json(audit_path, audit)

    readiness = {
        "schema_version": READINESS_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
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
        "authorization_sha256": EXPECTED_AUTHORIZATION_SHA256,
        "feature_audit_sha256": audit["audit_sha256"],
        "feature_dataset_sha256": dataset_sha,
        "feature_row_set_sha256": feature_rows_identity,
        "feature_contract_sha256": EXPECTED_FEATURE_CONTRACT_SHA256,
        "authorized_sample_count": EXPECTED_TOTAL,
        "partition_counts": reproduced_counts,
        "all_required_post_extraction_audits_passed": all(audits.values()),
        "next_gate": "ISSUE_STAGE_C_MODEL_TRAINING_AUTHORIZATION",
    }
    readiness["readiness_sha256"] = canonical_hash(readiness)
    readiness_path = output_root / "development-feature-readiness.json"
    frozen_write_json(readiness_path, readiness)
    return {
        "status": "PASS",
        "feature_dataset": str(final_path),
        "feature_dataset_sha256": dataset_sha,
        "feature_audit": str(audit_path),
        "feature_audit_sha256": audit["audit_sha256"],
        "feature_readiness": str(readiness_path),
        "feature_readiness_sha256": readiness["readiness_sha256"],
        "rows": EXPECTED_TOTAL,
        "feature_count": 27,
        "model_training_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
        "next_gate": readiness["next_gate"],
    }


def run_stage_c_development_feature_extraction(
    *, repo_root: Path, archive_path: Path, record_index_path: Path,
    index_report_path: Path, split_manifest_path: Path, authorization_path: Path,
    output_root: Path, expected_authorization_sha256: str,
    batch_size: int = 256, wait_ms: int = 250, timeout_seconds: int = 1800,
    max_batches: int | None = None, dist_path: Path | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    archive_path = archive_path.resolve()
    output_root = output_root.resolve()
    dist = (dist_path or (repo_root / "dist")).resolve()
    if max_batches is not None and (type(max_batches) is not int or max_batches < 1):
        raise StageCFeatureExtractionError("max_batches must be a positive integer")
    if type(timeout_seconds) is not int or timeout_seconds < 60:
        raise StageCFeatureExtractionError("timeout_seconds must be at least 60")

    auth = load_json(authorization_path)
    _validate_authorization(auth, expected_sha256=expected_authorization_sha256)
    partitions = _validate_split_manifest(load_json(split_manifest_path))
    index = load_json(record_index_path)
    index_rows = _validate_record_index(index)
    nested_hashes = _validate_index_report(load_json(index_report_path))
    production = _load_production_contract(repo_root)
    git_provenance = _git_provenance(repo_root)

    if not archive_path.is_file():
        raise StageCFeatureExtractionError(f"sealed development archive not found: {archive_path}")
    archive_sha = sha256_file(archive_path)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise StageCFeatureExtractionError(
            f"sealed development archive SHA-256 mismatch: {archive_sha}"
        )

    authorized = _authorized_rows(index_rows=index_rows, partitions=partitions)
    batches = build_replay_batches(authorized, batch_size=batch_size)
    state = _state_payload(
        batches=batches, batch_size=batch_size, wait_ms=wait_ms,
        archive_sha256=archive_sha, production=production,
        repo_root=repo_root, dist=dist, git_provenance=git_provenance,
    )
    output_root.mkdir(parents=True, exist_ok=True)
    state_path = output_root / "feature-extraction-state.json"
    frozen_write_json(state_path, state)

    completed_before = 0
    pending: list[dict[str, Any]] = []
    for batch in batches:
        if _verify_checkpoint(
            output_root=output_root, batch=batch, state_sha256=str(state["state_sha256"])
        ):
            completed_before += 1
        else:
            pending.append(batch)

    to_run = pending if max_batches is None else pending[:max_batches]
    if to_run:
        by_nested: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for batch in to_run:
            by_nested[str(batch["nested_archive"])].append(batch)
        try:
            with zipfile.ZipFile(archive_path, "r", allowZip64=True) as outer:
                for nested_name in sorted(by_nested):
                    try:
                        info = outer.getinfo(nested_name)
                    except KeyError as exc:
                        raise StageCFeatureExtractionError(
                            f"Task-6 nested archive missing from sealed archive: {nested_name}"
                        ) from exc
                    payload = outer.read(info)
                    nested_sha = hashlib.sha256(payload).hexdigest()
                    if nested_sha != nested_hashes.get(nested_name):
                        raise StageCFeatureExtractionError(
                            f"nested archive SHA-256 mismatch: {nested_name}"
                        )
                    with zipfile.ZipFile(BytesIO(payload), "r", allowZip64=True) as nested:
                        bad = nested.testzip()
                        if bad is not None:
                            raise StageCFeatureExtractionError(
                                f"nested archive integrity failure: {nested_name}:{bad}"
                            )
                        for batch in by_nested[nested_name]:
                            episodes = _run_collector(
                                repo_root=repo_root, dist=dist, batch=batch, nested=nested,
                                wait_ms=wait_ms, timeout_seconds=timeout_seconds,
                            )
                            vectors = _extract_vectors(episodes, repo_root=repo_root)
                            payload_rows = _render_checkpoint_rows(batch, vectors)
                            _write_checkpoint(
                                output_root=output_root, batch=batch, payload=payload_rows,
                                state_sha256=str(state["state_sha256"]),
                                collector_hashes=episodes["source_hashes"],
                            )
                            if progress is not None:
                                progress({
                                    "event": "BATCH_COMPLETE",
                                    "batch_id": batch["batch_id"],
                                    "samples": batch["sample_count"],
                                })
                    del payload
        except zipfile.BadZipFile as exc:
            raise StageCFeatureExtractionError(f"invalid sealed development archive: {exc}") from exc

    completed = 0
    for batch in batches:
        if _verify_checkpoint(
            output_root=output_root, batch=batch, state_sha256=str(state["state_sha256"])
        ):
            completed += 1
    if completed != len(batches):
        return {
            "status": "PARTIAL_CHECKPOINTED",
            "state": str(state_path),
            "state_sha256": state["state_sha256"],
            "completed_batches": completed,
            "total_batches": len(batches),
            "completed_before_this_run": completed_before,
            "remaining_batches": len(batches) - completed,
            "model_training_authorized": False,
            "model_scoring_authorized": False,
            "final_holdout_touched": False,
            "next_gate": "EXTRACT_STAGE_C_DEVELOPMENT_FEATURES_AND_AUDIT",
        }
    return _finalize(
        output_root=output_root, batches=batches, partitions=partitions, state=state
    )
