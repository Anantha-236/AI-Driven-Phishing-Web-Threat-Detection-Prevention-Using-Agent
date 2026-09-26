"""Stage C Task 9 hotfix — bind authorization to production TSFEG feature order."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from .stage_c_protocol import (
    EXPECTED_CONTEXT_FEATURES,
    StageCProtocolError,
    canonical_hash as protocol_hash,
    validate_feature_semantics,
    validate_stage_c_contract,
)
from .stage_c_feature_extraction_authorization import (
    StageCFeatureAuthorizationError,
    _audit_rows,
    _require_split_contract,
    _require_split_manifest,
    canonical_hash,
    frozen_write_json,
    load_json,
)

REG_SCHEMA = "stage-c-development-split-registration-2"
AUTH_SCHEMA = "stage-c-feature-extraction-authorization-2"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_production_feature_contract(repo_root: Path) -> dict[str, Any]:
    tsfeg = (repo_root / "browser-extension" / "src" / "core" / "tsfeg.ts").resolve()
    if not tsfeg.is_file():
        raise StageCFeatureAuthorizationError(
            f"production extractor not found: {tsfeg}"
        )

    node_source = r"""
import { pathToFileURL } from 'node:url';
const p = process.argv[1];
const core = await import(pathToFileURL(p).href);
if (!Array.isArray(core.CONTEXT_FEATURES) ||
    typeof core.CONTEXT_FEATURE_VERSION !== 'string') {
  throw new Error('production contextual feature exports unavailable');
}
process.stdout.write(JSON.stringify({
  feature_version: core.CONTEXT_FEATURE_VERSION,
  ordered_features: [...core.CONTEXT_FEATURES],
}));
"""
    try:
        completed = subprocess.run(
            [
                "node",
                "--experimental-strip-types",
                "--input-type=module",
                "-e",
                node_source,
                str(tsfeg),
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        details = getattr(exc, "stderr", "") or str(exc)
        raise StageCFeatureAuthorizationError(
            f"cannot read production feature contract: {details.strip()}"
        ) from exc

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StageCFeatureAuthorizationError(
            "production feature contract probe returned invalid JSON"
        ) from exc

    names = payload.get("ordered_features")
    version = payload.get("feature_version")
    if version != "context-features-1":
        raise StageCFeatureAuthorizationError(
            f"unexpected production feature version: {version!r}"
        )
    if (
        not isinstance(names, list)
        or len(names) != 27
        or not all(isinstance(x, str) and x for x in names)
        or len(set(names)) != len(names)
    ):
        raise StageCFeatureAuthorizationError(
            "production contextual feature order is invalid"
        )
    if set(names) != set(EXPECTED_CONTEXT_FEATURES):
        raise StageCFeatureAuthorizationError(
            "production contextual feature set differs from Stage-C semantics"
        )

    return {
        "feature_version": version,
        "ordered_features": names,
        "feature_count": len(names),
        "feature_contract_sha256": canonical_hash(
            {"feature_version": version, "feature_names": names}
        ),
        "extractor_source_sha256": sha256_file(tsfeg),
        "extractor_source": "browser-extension/src/core/tsfeg.ts",
    }


def _require_superseded_v1(old: Mapping[str, Any]) -> None:
    required = {
        "schema_version": "stage-c-feature-extraction-authorization-1",
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": True,
        "model_training_authorized": False,
        "model_selection_authorized": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "model_scoring_authorized": False,
        "final_holdout_touched": False,
    }
    for key, expected in required.items():
        if old.get(key) != expected:
            raise StageCFeatureAuthorizationError(
                f"superseded Task-9 v1 authorization guard mismatch: {key}"
            )
    digest = old.get("authorization_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise StageCFeatureAuthorizationError(
            "superseded Task-9 v1 authorization hash missing"
        )


def register_and_authorize_v2(
    *,
    experiment_contract: Mapping[str, Any],
    feature_semantics: Mapping[str, Any],
    split_contract: Mapping[str, Any],
    split_manifest: Mapping[str, Any],
    superseded_authorization: Mapping[str, Any],
    production_feature_contract: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        exp = validate_stage_c_contract(experiment_contract)
        sem = validate_feature_semantics(feature_semantics)
    except StageCProtocolError as exc:
        raise StageCFeatureAuthorizationError(str(exc)) from exc

    _require_split_contract(split_contract)
    _require_split_manifest(split_manifest, split_contract)
    _require_superseded_v1(superseded_authorization)

    audit = _audit_rows(split_manifest)
    if audit["total_samples"] != split_contract["counts"]["total_supervised_development"]:
        raise StageCFeatureAuthorizationError(
            "supervised sample total differs from Task-8 contract"
        )
    if audit["partition_counts"] != split_manifest.get("partition_counts"):
        raise StageCFeatureAuthorizationError(
            "partition row counts differ from Task-8 manifest"
        )

    version = production_feature_contract.get("feature_version")
    ordered = production_feature_contract.get("ordered_features")
    source_hash = production_feature_contract.get("extractor_source_sha256")
    contract_hash = production_feature_contract.get("feature_contract_sha256")

    if version != "context-features-1":
        raise StageCFeatureAuthorizationError(
            "production feature version mismatch"
        )
    if (
        not isinstance(ordered, list)
        or len(ordered) != 27
        or len(set(ordered)) != 27
        or set(ordered) != set(EXPECTED_CONTEXT_FEATURES)
    ):
        raise StageCFeatureAuthorizationError(
            "production feature order/set is not the exact 27-feature contract"
        )
    if not isinstance(source_hash, str) or len(source_hash) != 64:
        raise StageCFeatureAuthorizationError("invalid extractor source hash")
    expected_contract_hash = canonical_hash(
        {"feature_version": version, "feature_names": ordered}
    )
    if contract_hash != expected_contract_hash:
        raise StageCFeatureAuthorizationError(
            "production feature-contract hash mismatch"
        )

    old_scope = superseded_authorization.get("scope")
    if not isinstance(old_scope, Mapping):
        raise StageCFeatureAuthorizationError("v1 authorization scope missing")
    if old_scope.get("authorized_sample_count") != audit["total_samples"]:
        raise StageCFeatureAuthorizationError(
            "v1/v2 authorized sample counts differ"
        )
    if (
        old_scope.get("authorized_sample_set_sha256")
        != audit["sample_set_sha256"]
    ):
        raise StageCFeatureAuthorizationError(
            "v1/v2 authorized sample identity differs"
        )

    registration = {
        "schema_version": REG_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": False,
        "model_training_authorized": False,
        "final_holdout_touched": False,
        "source_identities": {
            "experiment_contract_sha256": protocol_hash(exp),
            "feature_semantics_sha256": protocol_hash(sem),
            "split_contract_sha256": split_contract["contract_sha256"],
            "split_manifest_sha256": split_manifest["manifest_sha256"],
        },
        "partition_counts": split_manifest["partition_counts"],
        "partition_audit": audit,
        "registered_split_state": "FROZEN_DEVELOPMENT_ONLY",
        "superseded_authorization_sha256": superseded_authorization[
            "authorization_sha256"
        ],
        "correction": "PRODUCTION_FEATURE_ORDER_BOUND_DIRECTLY_FROM_TSFEG",
        "next_gate": "ISSUE_STAGE_C_FEATURE_EXTRACTION_AUTHORIZATION_V2",
    }
    registration["registration_sha256"] = canonical_hash(registration)

    rules = sem["rules"]
    prohibited = []
    for rule, name in (
        ("brand_group_model_observable", "brand_group"),
        ("raw_url_model_observable", "raw_url"),
        ("literal_origin_model_observable", "literal_origin"),
        ("sample_id_model_observable", "sample_id"),
    ):
        if rules.get(rule) is not False:
            raise StageCFeatureAuthorizationError(
                f"unsafe observability rule enabled: {rule}"
            )
        prohibited.append(name)

    authorization = {
        "schema_version": AUTH_SCHEMA,
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
        "scope": {
            "dataset_role": "DEVELOPMENT",
            "authorized_partitions": [
                "train", "selection", "calibration"
            ],
            "authorized_sample_count": audit["total_samples"],
            "authorized_sample_set_sha256": audit["sample_set_sha256"],
            "task8_quarantine_authorized": False,
            "stage_b_consumed_test_authorized": False,
            "stage_c_final_holdout_authorized": False,
        },
        "feature_contract": {
            "source_feature_version": version,
            "ordered_features": ordered,
            "feature_count": 27,
            "feature_contract_sha256": contract_hash,
            "extractor_source": production_feature_contract.get(
                "extractor_source",
                "browser-extension/src/core/tsfeg.ts",
            ),
            "extractor_source_sha256": source_hash,
            "semantic_groups": sem["groups"],
            "rules": rules,
            "prohibited_model_observables": prohibited,
            "raw_html_persistence_in_feature_output_authorized": False,
            "raw_url_persistence_in_feature_output_authorized": False,
            "sample_id_allowed_as_join_key_only": True,
            "sample_id_model_observable": False,
            "label_allowed_as_supervision_metadata_only": True,
            "order_source": "PRODUCTION_TSFEG_CONTEXT_FEATURES_EXPORT",
        },
        "identity_bindings": {
            "development_registration_sha256": registration[
                "registration_sha256"
            ],
            "split_contract_sha256": split_contract["contract_sha256"],
            "split_manifest_sha256": split_manifest["manifest_sha256"],
            "feature_semantics_sha256": protocol_hash(sem),
            "extractor_source_sha256": source_hash,
        },
        "supersedes": {
            "schema_version": superseded_authorization["schema_version"],
            "authorization_sha256": superseded_authorization[
                "authorization_sha256"
            ],
            "reason": (
                "v1 preserved the correct feature set but serialized names "
                "in semantic-group order instead of production vector order"
            ),
        },
        "required_post_extraction_audits": [
            "EXACT_ROW_COUNT_PER_PARTITION",
            "FEATURE_SCHEMA_EXACT_MATCH",
            "PRODUCTION_FEATURE_ORDER_EXACT_MATCH",
            "NO_NAN_OR_INF",
            "NO_PROHIBITED_MODEL_OBSERVABLES",
            "SAMPLE_ID_JOIN_COVERAGE",
            "LABEL_ALIGNMENT",
            "PARTITION_IDENTITY_REPRODUCTION",
            "FEATURE_DATASET_HASH_FREEZE",
        ],
        "next_gate": "EXTRACT_STAGE_C_DEVELOPMENT_FEATURES_AND_AUDIT",
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)

    return registration, authorization
