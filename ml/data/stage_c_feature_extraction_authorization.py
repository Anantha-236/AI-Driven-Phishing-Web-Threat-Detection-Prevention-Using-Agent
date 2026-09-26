from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping
from .stage_c_protocol import (
    EXPECTED_CONTEXT_FEATURES,
    StageCProtocolError,
    canonical_hash as protocol_hash,
    validate_feature_semantics,
    validate_stage_c_contract,
)

AUTH_SCHEMA = "stage-c-feature-extraction-authorization-1"
REG_SCHEMA = "stage-c-development-split-registration-1"

class StageCFeatureAuthorizationError(ValueError):
    pass

def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")).hexdigest()

def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFeatureAuthorizationError(f"required JSON file not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StageCFeatureAuthorizationError(f"JSON root must be object: {path}")
    return value

def frozen_write_json(path: Path, value: Any) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = json.loads(path.read_text(encoding="utf-8"))
        if current != value:
            raise StageCFeatureAuthorizationError(f"refusing to replace non-identical frozen Task-9 output: {path}")
        return "EXISTING_MATCH"
    path.write_text(rendered, encoding="utf-8")
    return "CREATED"

def _require_split_contract(c: Mapping[str, Any]) -> None:
    required = {
        "schema_version":"stage-c-development-split-contract-1",
        "status":"PASS","stage":"C","protocol_id":"low-fpr-generalization-v1",
        "research_only":True,"deployment_authorized":False,
        "feature_extraction_authorized":False,
        "model_training_authorized":False,"final_holdout_touched":False,
        "next_gate":"REGISTER_STAGE_C_DEVELOPMENT_SPLIT_AND_AUTHORIZE_FEATURE_EXTRACTION",
    }
    for k,v in required.items():
        if c.get(k) != v:
            raise StageCFeatureAuthorizationError(f"Task-8 split contract mismatch: {k}")
    if c.get("artifact_isolation",{}).get("all_zero") is not True:
        raise StageCFeatureAuthorizationError("Task-8 artifact isolation is not clean")
    if c.get("cutoffs",{}).get("strict_forward") is not True:
        raise StageCFeatureAuthorizationError("Task-8 split is not strict-forward")
    counts = c.get("counts",{})
    if counts.get("input") != 80000 or counts.get("total_supervised_development") != 73777 or counts.get("total_quarantined") != 6223:
        raise StageCFeatureAuthorizationError("Task-8 counts changed")

def _require_split_manifest(m: Mapping[str, Any], c: Mapping[str, Any]) -> None:
    required = {
        "schema_version":"stage-c-development-split-manifest-1","status":"PASS",
        "stage":"C","role":"DEVELOPMENT","research_only":True,
        "deployment_authorized":False,"feature_extraction_authorized":False,
        "model_training_authorized":False,"final_holdout_touched":False,
    }
    for k,v in required.items():
        if m.get(k) != v:
            raise StageCFeatureAuthorizationError(f"Task-8 split manifest mismatch: {k}")
    if m.get("manifest_sha256") != c.get("partition_manifest_sha256"):
        raise StageCFeatureAuthorizationError("Task-8 split-manifest identity mismatch")

def _audit_rows(m: Mapping[str, Any]) -> dict[str, Any]:
    parts = m.get("partitions")
    if not isinstance(parts, Mapping):
        raise StageCFeatureAuthorizationError("Task-8 partition rows missing")
    all_ids, artifacts = set(), {}
    counts = {}
    for part in ("train","selection","calibration"):
        rows = parts.get(part)
        if not isinstance(rows, list):
            raise StageCFeatureAuthorizationError(f"partition rows missing: {part}")
        legit=phish=0
        for r in rows:
            sid = r.get("sample_id"); sha = r.get("html_sha256"); label = r.get("label")
            if not isinstance(sid,str) or not sid:
                raise StageCFeatureAuthorizationError(f"invalid sample_id in {part}")
            if not isinstance(sha,str) or len(sha)!=64:
                raise StageCFeatureAuthorizationError(f"invalid html_sha256 in {part}")
            if label not in (0,1):
                raise StageCFeatureAuthorizationError(f"invalid label in {part}")
            if sid in all_ids:
                raise StageCFeatureAuthorizationError(f"sample identity overlap involving {part}")
            all_ids.add(sid)
            if sha in artifacts and artifacts[sha] != part:
                raise StageCFeatureAuthorizationError(f"artifact identity crosses partitions: {artifacts[sha]} vs {part}")
            artifacts[sha] = part
            if label == 0: legit += 1
            else: phish += 1
        counts[part] = {"total":len(rows),"legitimate":legit,"phishing":phish}
    return {
        "total_samples":len(all_ids),
        "partition_counts":counts,
        "unique_artifacts":len(artifacts),
        "sample_set_sha256":canonical_hash(sorted(all_ids)),
        "artifact_cross_partition_overlap":0,
    }

def register_and_authorize(*, experiment_contract, feature_semantics, split_contract, split_manifest):
    try:
        exp = validate_stage_c_contract(experiment_contract)
        sem = validate_feature_semantics(feature_semantics)
    except StageCProtocolError as exc:
        raise StageCFeatureAuthorizationError(str(exc)) from exc

    _require_split_contract(split_contract)
    _require_split_manifest(split_manifest, split_contract)
    audit = _audit_rows(split_manifest)

    frozen_counts = split_contract["counts"]
    if audit["total_samples"] != frozen_counts["total_supervised_development"]:
        raise StageCFeatureAuthorizationError("supervised sample total differs from Task-8 contract")
    if audit["partition_counts"] != split_manifest.get("partition_counts"):
        raise StageCFeatureAuthorizationError("partition row counts differ from Task-8 manifest")

    ordered=[]
    for group in ("evidence_quality","page_context","consistency_or_trust","mismatch_or_risk_evidence"):
        ordered.extend(sem["groups"][group])
    if set(ordered) != set(EXPECTED_CONTEXT_FEATURES) or len(ordered) != len(EXPECTED_CONTEXT_FEATURES):
        raise StageCFeatureAuthorizationError("feature semantics do not exactly match context-features-1")

    rules = sem["rules"]
    prohibited=[]
    for rule, name in (
        ("brand_group_model_observable","brand_group"),
        ("raw_url_model_observable","raw_url"),
        ("literal_origin_model_observable","literal_origin"),
        ("sample_id_model_observable","sample_id"),
    ):
        if rules.get(rule) is not False:
            raise StageCFeatureAuthorizationError(f"unsafe observability rule enabled: {rule}")
        prohibited.append(name)

    reg = {
        "schema_version":REG_SCHEMA,"status":"PASS","stage":"C",
        "protocol_id":"low-fpr-generalization-v1","research_only":True,
        "deployment_authorized":False,"feature_extraction_authorized":False,
        "model_training_authorized":False,"final_holdout_touched":False,
        "source_identities":{
            "experiment_contract_sha256":protocol_hash(exp),
            "feature_semantics_sha256":protocol_hash(sem),
            "split_contract_sha256":split_contract["contract_sha256"],
            "split_manifest_sha256":split_manifest["manifest_sha256"],
        },
        "partition_counts":split_manifest["partition_counts"],
        "partition_audit":audit,
        "registered_split_state":"FROZEN_DEVELOPMENT_ONLY",
        "next_gate":"ISSUE_STAGE_C_FEATURE_EXTRACTION_AUTHORIZATION",
    }
    reg["registration_sha256"]=canonical_hash(reg)

    auth = {
        "schema_version":AUTH_SCHEMA,"status":"PASS","stage":"C",
        "protocol_id":"low-fpr-generalization-v1","research_only":True,
        "deployment_authorized":False,
        "feature_extraction_authorized":True,
        "model_training_authorized":False,
        "model_selection_authorized":False,
        "calibration_fitting_authorized":False,
        "threshold_selection_authorized":False,
        "model_scoring_authorized":False,
        "final_holdout_touched":False,
        "scope":{
            "dataset_role":"DEVELOPMENT",
            "authorized_partitions":["train","selection","calibration"],
            "authorized_sample_count":audit["total_samples"],
            "authorized_sample_set_sha256":audit["sample_set_sha256"],
            "task8_quarantine_authorized":False,
            "stage_b_consumed_test_authorized":False,
            "stage_c_final_holdout_authorized":False,
        },
        "feature_contract":{
            "source_feature_version":sem["source_feature_version"],
            "ordered_features":ordered,
            "feature_count":len(ordered),
            "semantic_groups":sem["groups"],
            "rules":rules,
            "prohibited_model_observables":prohibited,
            "raw_html_persistence_in_feature_output_authorized":False,
            "raw_url_persistence_in_feature_output_authorized":False,
            "sample_id_allowed_as_join_key_only":True,
            "sample_id_model_observable":False,
            "label_allowed_as_supervision_metadata_only":True,
        },
        "identity_bindings":{
            "development_registration_sha256":reg["registration_sha256"],
            "split_contract_sha256":split_contract["contract_sha256"],
            "split_manifest_sha256":split_manifest["manifest_sha256"],
            "feature_semantics_sha256":protocol_hash(sem),
        },
        "required_post_extraction_audits":[
            "EXACT_ROW_COUNT_PER_PARTITION","FEATURE_SCHEMA_EXACT_MATCH","NO_NAN_OR_INF",
            "NO_PROHIBITED_MODEL_OBSERVABLES","SAMPLE_ID_JOIN_COVERAGE","LABEL_ALIGNMENT",
            "PARTITION_IDENTITY_REPRODUCTION","FEATURE_DATASET_HASH_FREEZE",
        ],
        "next_gate":"EXTRACT_STAGE_C_DEVELOPMENT_FEATURES_AND_AUDIT",
    }
    auth["authorization_sha256"]=canonical_hash(auth)
    return reg, auth
