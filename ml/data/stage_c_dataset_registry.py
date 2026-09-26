"""Stage C Task 2: dataset/holdout registration and contamination guards.

The Stage-B contextual-v2 final test is consumed. Stage C therefore registers
new data through hashed identity indexes and refuses sample/artifact overlap
with that consumed test or between development and final holdout data.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ml.data.stage_b_features import validate_feature_dataset
from ml.data.stage_c_protocol import (
    STAGE_B_CONSUMED_TEST_SHA256,
    StageCProtocolError,
    canonical_hash,
    load_json,
    minimum_zero_fp_legitimate_count,
)
from ml.training.stage_b_contextual_locked_final_v2 import (
    _test_partition_fingerprint,
)

CONSUMED_GUARD_SCHEMA = "stage-c-consumed-test-guard-1"
IDENTITY_INDEX_SCHEMA = "stage-c-dataset-identity-index-1"
REGISTRY_SCHEMA = "stage-c-dataset-registry-1"
READINESS_SCHEMA = "stage-c-dataset-readiness-1"
ROLES = {"DEVELOPMENT", "FINAL_HOLDOUT"}


class StageCDatasetRegistryError(StageCProtocolError):
    pass


def _hash_token(namespace: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise StageCDatasetRegistryError(
            f"{namespace} identity value must be a non-empty string"
        )
    return hashlib.sha256(
        f"stage-c::{namespace}::{value}".encode("utf-8")
    ).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise StageCDatasetRegistryError("observed_at is required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StageCDatasetRegistryError(
            f"invalid observed_at: {value}"
        ) from exc


def build_consumed_stage_b_guard(
    feature_data: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a privacy-reduced exact-identity guard from the consumed test."""
    try:
        validated = validate_feature_dataset(feature_data)
        fingerprint = _test_partition_fingerprint(validated)
    except Exception as exc:
        raise StageCDatasetRegistryError(
            f"invalid Stage-B frozen feature dataset: {exc}"
        ) from exc

    if fingerprint["sha256"] != STAGE_B_CONSUMED_TEST_SHA256:
        raise StageCDatasetRegistryError(
            "Stage-B feature dataset does not contain the consumed final-test partition"
        )

    rows = validated["partitions"]["test"]["records"]
    identities = []
    for row in rows:
        artifact = row.get("artifact_group")
        domain = row.get("domain_group")
        if not isinstance(artifact, str) or not artifact:
            raise StageCDatasetRegistryError(
                "consumed Stage-B test row missing artifact_group"
            )
        if not isinstance(domain, str) or not domain:
            raise StageCDatasetRegistryError(
                "consumed Stage-B test row missing domain_group"
            )
        identities.append({
            "sample_key_sha256": _hash_token("sample", row["sample_id"]),
            "artifact_sha256": _hash_token("artifact", artifact),
            "domain_group_sha256": _hash_token("domain", domain),
            "events_sha256": row["events_sha256"],
            "ground_truth": row["ground_truth"],
            "observed_at": row["observed_at"],
        })

    identities.sort(key=lambda r: r["sample_key_sha256"])
    counts = Counter(row["ground_truth"] for row in rows)
    return {
        "schema_version": CONSUMED_GUARD_SCHEMA,
        "stage": "B",
        "role": "CONSUMED_FINAL_TEST",
        "research_only": True,
        "reuse_as_stage_c_final_holdout_prohibited": True,
        "source_feature_dataset_sha256": canonical_hash(validated),
        "test_partition_sha256": fingerprint["sha256"],
        "sample_count": len(identities),
        "class_counts": {
            "legitimate": counts[0],
            "phishing": counts[1],
        },
        "identities": identities,
        "identity_set_sha256": canonical_hash(identities),
        "privacy": {
            "raw_sample_ids_emitted": False,
            "raw_artifact_groups_emitted": False,
            "raw_domain_groups_emitted": False,
        },
    }


def validate_consumed_guard(data: Mapping[str, Any]) -> dict[str, Any]:
    if data.get("schema_version") != CONSUMED_GUARD_SCHEMA:
        raise StageCDatasetRegistryError("unsupported consumed-test guard schema")
    if data.get("test_partition_sha256") != STAGE_B_CONSUMED_TEST_SHA256:
        raise StageCDatasetRegistryError("consumed-test partition identity mismatch")
    if data.get("reuse_as_stage_c_final_holdout_prohibited") is not True:
        raise StageCDatasetRegistryError("consumed-test reuse prohibition missing")
    rows = data.get("identities")
    if not isinstance(rows, list) or not rows:
        raise StageCDatasetRegistryError("consumed-test identity set is empty")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCDatasetRegistryError("invalid consumed-test identity row")
        for key in (
            "sample_key_sha256",
            "artifact_sha256",
            "domain_group_sha256",
            "events_sha256",
        ):
            if not _is_sha256(row.get(key)):
                raise StageCDatasetRegistryError(
                    f"invalid consumed-test digest: {key}"
                )
        sample = str(row["sample_key_sha256"]).lower()
        if sample in seen:
            raise StageCDatasetRegistryError("duplicate consumed-test sample identity")
        seen.add(sample)
        if row.get("ground_truth") not in (0, 1):
            raise StageCDatasetRegistryError("invalid consumed-test label")
        _parse_time(row.get("observed_at"))
    if data.get("identity_set_sha256") != canonical_hash(list(rows)):
        raise StageCDatasetRegistryError("consumed-test identity-set hash mismatch")
    return dict(data)


def build_identity_index(
    *,
    dataset_id: str,
    source_id: str,
    role: str,
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(dataset_id, str) or not dataset_id:
        raise StageCDatasetRegistryError("dataset_id is required")
    if not isinstance(source_id, str) or not source_id:
        raise StageCDatasetRegistryError("source_id is required")
    if role not in ROLES:
        raise StageCDatasetRegistryError("unsupported Stage-C dataset role")
    if not records:
        raise StageCDatasetRegistryError("identity index cannot be empty")

    out = []
    seen_samples: set[str] = set()
    for raw in records:
        if not isinstance(raw, Mapping):
            raise StageCDatasetRegistryError("identity source record must be an object")
        label = raw.get("ground_truth")
        if label not in (0, 1):
            raise StageCDatasetRegistryError("identity records require binary labels")
        sample = _hash_token("sample", raw.get("sample_id"))
        artifact = _hash_token("artifact", raw.get("artifact_group"))
        domain = _hash_token("domain", raw.get("domain_group"))
        if sample in seen_samples:
            raise StageCDatasetRegistryError("duplicate sample in identity index")
        seen_samples.add(sample)
        observed_at = raw.get("observed_at")
        _parse_time(observed_at)
        out.append({
            "sample_key_sha256": sample,
            "artifact_sha256": artifact,
            "domain_group_sha256": domain,
            "ground_truth": label,
            "observed_at": observed_at,
        })

    out.sort(key=lambda r: r["sample_key_sha256"])
    counts = Counter(row["ground_truth"] for row in out)
    return {
        "schema_version": IDENTITY_INDEX_SCHEMA,
        "dataset_id": dataset_id,
        "source_id": source_id,
        "role": role,
        "research_only": True,
        "sample_count": len(out),
        "class_counts": {
            "legitimate": counts[0],
            "phishing": counts[1],
        },
        "min_observed_at": min(_parse_time(r["observed_at"]) for r in out).isoformat(),
        "max_observed_at": max(_parse_time(r["observed_at"]) for r in out).isoformat(),
        "records": out,
        "identity_set_sha256": canonical_hash(out),
    }


def validate_identity_index(data: Mapping[str, Any]) -> dict[str, Any]:
    if data.get("schema_version") != IDENTITY_INDEX_SCHEMA:
        raise StageCDatasetRegistryError("unsupported Stage-C identity-index schema")
    if data.get("role") not in ROLES:
        raise StageCDatasetRegistryError("invalid Stage-C identity-index role")
    if data.get("research_only") is not True:
        raise StageCDatasetRegistryError("Stage-C dataset identity must be research-only")
    for key in ("dataset_id", "source_id"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise StageCDatasetRegistryError(f"identity index missing {key}")
    rows = data.get("records")
    if not isinstance(rows, list) or not rows:
        raise StageCDatasetRegistryError("Stage-C identity index is empty")
    seen: set[str] = set()
    counts = Counter()
    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCDatasetRegistryError("invalid identity-index record")
        for key in ("sample_key_sha256", "artifact_sha256", "domain_group_sha256"):
            if not _is_sha256(row.get(key)):
                raise StageCDatasetRegistryError(f"invalid identity-index digest: {key}")
        sample = str(row["sample_key_sha256"]).lower()
        if sample in seen:
            raise StageCDatasetRegistryError("duplicate identity-index sample")
        seen.add(sample)
        if row.get("ground_truth") not in (0, 1):
            raise StageCDatasetRegistryError("invalid identity-index label")
        counts[row["ground_truth"]] += 1
        _parse_time(row.get("observed_at"))
    if data.get("sample_count") != len(rows):
        raise StageCDatasetRegistryError("identity-index sample_count mismatch")
    expected_counts = {"legitimate": counts[0], "phishing": counts[1]}
    if data.get("class_counts") != expected_counts:
        raise StageCDatasetRegistryError("identity-index class_counts mismatch")
    if data.get("identity_set_sha256") != canonical_hash(list(rows)):
        raise StageCDatasetRegistryError("identity-index set hash mismatch")
    return dict(data)


def validate_registry(data: Mapping[str, Any]) -> dict[str, Any]:
    if data.get("schema_version") != REGISTRY_SCHEMA:
        raise StageCDatasetRegistryError("unsupported Stage-C dataset-registry schema")
    if data.get("stage") != "C":
        raise StageCDatasetRegistryError("dataset registry must declare stage C")
    if data.get("research_only") is not True:
        raise StageCDatasetRegistryError("dataset registry must remain research-only")
    if data.get("deployment_authorized") is not False:
        raise StageCDatasetRegistryError("dataset registry cannot authorize deployment")
    development = data.get("development_datasets")
    if not isinstance(development, list):
        raise StageCDatasetRegistryError("development_datasets must be a list")
    final = data.get("final_holdout")
    if final is not None and not isinstance(final, Mapping):
        raise StageCDatasetRegistryError("final_holdout must be null or an object")
    return dict(data)


def _load_registered_index(entry: Mapping[str, Any], repo_root: Path) -> dict[str, Any]:
    for key in ("dataset_id", "source_id", "identity_index_path"):
        if not isinstance(entry.get(key), str) or not entry[key]:
            raise StageCDatasetRegistryError(f"registry entry missing {key}")
    path = (repo_root / entry["identity_index_path"]).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise StageCDatasetRegistryError("identity_index_path escapes repo root") from exc
    index = validate_identity_index(load_json(path))
    if index["dataset_id"] != entry["dataset_id"]:
        raise StageCDatasetRegistryError("registry/index dataset_id mismatch")
    if index["source_id"] != entry["source_id"]:
        raise StageCDatasetRegistryError("registry/index source_id mismatch")
    return index


def _sets(index: Mapping[str, Any]) -> dict[str, set[str]]:
    rows = index["records"]
    return {
        "sample": {str(r["sample_key_sha256"]).lower() for r in rows},
        "artifact": {str(r["artifact_sha256"]).lower() for r in rows},
        "domain": {str(r["domain_group_sha256"]).lower() for r in rows},
    }


def _guard_sets(guard: Mapping[str, Any]) -> dict[str, set[str]]:
    rows = guard["identities"]
    return {
        "sample": {str(r["sample_key_sha256"]).lower() for r in rows},
        "artifact": {str(r["artifact_sha256"]).lower() for r in rows},
        "domain": {str(r["domain_group_sha256"]).lower() for r in rows},
    }


def audit_dataset_registry(
    *,
    protocol_readiness: Mapping[str, Any],
    consumed_guard: Mapping[str, Any],
    registry: Mapping[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    if protocol_readiness.get("status") != "PASS":
        raise StageCDatasetRegistryError("Stage-C protocol readiness is not PASS")
    if protocol_readiness.get("model_training_authorized") is not False:
        raise StageCDatasetRegistryError(
            "Task 2 expects training to still be unauthorized before registration"
        )
    guard = validate_consumed_guard(consumed_guard)
    active = validate_registry(registry)

    reasons: list[str] = []
    warnings: list[str] = []
    dev_entries = active["development_datasets"]
    final_entry = active["final_holdout"]

    if not dev_entries:
        reasons.append("DEVELOPMENT_DATASET_NOT_REGISTERED")
    if final_entry is None:
        reasons.append("FINAL_HOLDOUT_NOT_REGISTERED")

    loaded_dev: list[dict[str, Any]] = []
    for entry in dev_entries:
        if not isinstance(entry, Mapping):
            raise StageCDatasetRegistryError("development registry entry must be an object")
        index = _load_registered_index(entry, repo_root)
        if index["role"] != "DEVELOPMENT":
            raise StageCDatasetRegistryError("development registry entry has wrong role")
        loaded_dev.append(index)

    loaded_final: dict[str, Any] | None = None
    if final_entry is not None:
        loaded_final = _load_registered_index(final_entry, repo_root)
        if loaded_final["role"] != "FINAL_HOLDOUT":
            raise StageCDatasetRegistryError("final-holdout registry entry has wrong role")

    consumed = _guard_sets(guard)
    dev_union = {"sample": set(), "artifact": set(), "domain": set()}
    dev_source_ids: set[str] = set()
    development_overlap = []

    for index in loaded_dev:
        current = _sets(index)
        stage_b_sample_overlap = current["sample"] & consumed["sample"]
        stage_b_artifact_overlap = current["artifact"] & consumed["artifact"]
        if stage_b_sample_overlap or stage_b_artifact_overlap:
            raise StageCDatasetRegistryError(
                f"development dataset {index['dataset_id']} overlaps consumed Stage-B final test"
            )
        duplicate_samples = current["sample"] & dev_union["sample"]
        duplicate_artifacts = current["artifact"] & dev_union["artifact"]
        if duplicate_samples or duplicate_artifacts:
            raise StageCDatasetRegistryError(
                f"development dataset {index['dataset_id']} duplicates another registered development dataset"
            )
        development_overlap.append({
            "dataset_id": index["dataset_id"],
            "stage_b_consumed_domain_overlap": len(current["domain"] & consumed["domain"]),
        })
        for key in dev_union:
            dev_union[key].update(current[key])
        dev_source_ids.add(index["source_id"])

    final_audit = None
    if loaded_final is not None:
        current = _sets(loaded_final)
        sample_overlap = current["sample"] & consumed["sample"]
        artifact_overlap = current["artifact"] & consumed["artifact"]
        if sample_overlap or artifact_overlap:
            raise StageCDatasetRegistryError(
                "Stage-C final holdout overlaps the consumed Stage-B final test"
            )
        if current["sample"] & dev_union["sample"]:
            raise StageCDatasetRegistryError(
                "Stage-C final holdout overlaps development sample identity"
            )
        if current["artifact"] & dev_union["artifact"]:
            raise StageCDatasetRegistryError(
                "Stage-C final holdout overlaps development artifact identity"
            )
        if loaded_final["source_id"] in dev_source_ids:
            reasons.append("FINAL_HOLDOUT_SOURCE_NOT_INDEPENDENT")

        counts = loaded_final["class_counts"]
        minimum_legitimate = minimum_zero_fp_legitimate_count(0.01)
        if counts["legitimate"] < minimum_legitimate:
            reasons.append("FINAL_HOLDOUT_LOW_FPR_RESOLUTION_INSUFFICIENT")
        if counts["phishing"] < 1:
            reasons.append("FINAL_HOLDOUT_HAS_NO_PHISHING")
        if counts["legitimate"] < 1200:
            warnings.append("FINAL_HOLDOUT_BELOW_RECOMMENDED_LEGITIMATE_COUNT")
        if counts["phishing"] < 1000:
            warnings.append("FINAL_HOLDOUT_BELOW_RECOMMENDED_PHISHING_COUNT")

        final_audit = {
            "dataset_id": loaded_final["dataset_id"],
            "source_id": loaded_final["source_id"],
            "sample_count": loaded_final["sample_count"],
            "class_counts": loaded_final["class_counts"],
            "independent_source": loaded_final["source_id"] not in dev_source_ids,
            "stage_b_consumed_sample_overlap": 0,
            "stage_b_consumed_artifact_overlap": 0,
            "stage_b_consumed_domain_overlap": len(current["domain"] & consumed["domain"]),
            "development_sample_overlap": 0,
            "development_artifact_overlap": 0,
            "development_domain_overlap": len(current["domain"] & dev_union["domain"]),
        }

    status = "PASS" if not reasons else "WAITING"
    training_authorized = status == "PASS"
    return {
        "schema_version": READINESS_SCHEMA,
        "status": status,
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": training_authorized,
        "consumed_stage_b_test_sha256": STAGE_B_CONSUMED_TEST_SHA256,
        "registered_development_datasets": len(loaded_dev),
        "registered_final_holdout": loaded_final is not None,
        "blocking_reasons": reasons,
        "warnings": warnings,
        "development_audit": development_overlap,
        "final_holdout_audit": final_audit,
        "next_gate": (
            "BEGIN_STAGE_C_FEATURE_AND_MODEL_EXPERIMENTS"
            if training_authorized
            else "REGISTER_STAGE_C_DATASET_AND_NEW_FINAL_HOLDOUT"
        ),
    }
