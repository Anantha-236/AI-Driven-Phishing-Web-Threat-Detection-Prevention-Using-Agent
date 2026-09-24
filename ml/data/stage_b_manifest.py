"""Stage B dataset provenance, sample metadata, and split-contract validation.

This module validates *metadata contracts*. It does not download datasets, inspect
raw website payloads, assign labels, or create model splits. Later Stage B tasks
consume only manifests/samples that satisfy these contracts.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import re
from typing import Any, Iterable, Mapping


SOURCE_SCHEMA = "stage-b-source-manifest-1"
SAMPLE_SCHEMA = "stage-b-sample-provenance-1"
SPLIT_SCHEMA = "stage-b-split-contract-1"

PROVENANCE = {"REAL", "ARCHIVED", "CONTROLLED", "SYNTHETIC"}
COLLECTION_METHODS = {
    "PUBLIC_FEED",
    "PUBLIC_DATASET",
    "CONTROLLED_CAPTURE",
    "SYNTHETIC_GENERATOR",
    "OTHER",
}
LABEL_SOURCES_BY_PROVENANCE = {
    "REAL": {"INDEPENDENT_REVIEW", "VERIFIED_SOURCE_REVIEW"},
    "ARCHIVED": {"INDEPENDENT_REVIEW", "VERIFIED_SOURCE_REVIEW"},
    "CONTROLLED": {"CONTROLLED_SCENARIO_SPEC"},
    "SYNTHETIC": {"SYNTHETIC_AUTHOR_SPEC"},
}
INTENDED_USE = {"TRAIN", "SELECTION", "CALIBRATION", "TEST"}
GROUP_STATUS = {"AVAILABLE", "PARTIAL", "UNAVAILABLE"}
PII_STATUS = {"NOT_EXPECTED", "REVIEWED", "REQUIRES_REVIEW"}
PARTITIONS = ["train", "selection", "calibration", "test"]
REQUIRED_ISOLATION = {"artifact_sha256", "domain_group", "brand_group", "source_group"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATASET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


class ManifestValidationError(ValueError):
    """Raised when Stage B metadata is incomplete, unsafe, or ambiguous."""


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestValidationError(f"{name} must be an object")
    return value


def _require_nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestValidationError(f"{name} is required")
    return value.strip()


def _require_sha256(value: Any, name: str) -> str:
    text = _require_nonempty_string(value, name).lower()
    if not SHA256_RE.fullmatch(text):
        raise ManifestValidationError(f"{name} must be a lowercase 64-character SHA-256")
    return text


def _require_timezone_timestamp(value: Any, name: str) -> str:
    text = _require_nonempty_string(value, name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestValidationError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ManifestValidationError(f"{name} must include a timezone")
    return text


def _reject_unknown_fields(value: Mapping[str, Any], allowed: set[str], name: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise ManifestValidationError(f"unexpected {name} fields: {', '.join(extras)}")


def validate_source_manifest(data: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(dict(_require_mapping(data, "source manifest")))
    _reject_unknown_fields(
        manifest,
        {
            "schema_version",
            "dataset_id",
            "display_name",
            "source",
            "labeling",
            "privacy",
            "grouping",
            "intended_use",
            "limitations",
        },
        "source manifest",
    )
    if manifest.get("schema_version") != SOURCE_SCHEMA:
        raise ManifestValidationError(f"schema_version must be {SOURCE_SCHEMA}")

    dataset_id = _require_nonempty_string(manifest.get("dataset_id"), "dataset_id")
    if not DATASET_ID_RE.fullmatch(dataset_id):
        raise ManifestValidationError("dataset_id must be stable lowercase slug metadata")
    _require_nonempty_string(manifest.get("display_name"), "display_name")

    source = dict(_require_mapping(manifest.get("source"), "source"))
    _reject_unknown_fields(
        source,
        {
            "provider",
            "homepage",
            "retrieval_url",
            "retrieved_at",
            "content_sha256",
            "provenance",
            "collection_method",
            "independence_group",
            "license",
        },
        "source",
    )
    _require_nonempty_string(source.get("provider"), "source.provider")
    _require_nonempty_string(source.get("homepage"), "source.homepage")
    _require_nonempty_string(source.get("retrieval_url"), "source.retrieval_url")
    source["retrieved_at"] = _require_timezone_timestamp(source.get("retrieved_at"), "source.retrieved_at")
    source["content_sha256"] = _require_sha256(source.get("content_sha256"), "source.content_sha256")
    provenance = _require_nonempty_string(source.get("provenance"), "source.provenance")
    if provenance not in PROVENANCE:
        raise ManifestValidationError(f"unsupported provenance: {provenance}")
    method = _require_nonempty_string(source.get("collection_method"), "source.collection_method")
    if method not in COLLECTION_METHODS:
        raise ManifestValidationError(f"unsupported collection_method: {method}")
    _require_nonempty_string(source.get("independence_group"), "source.independence_group")

    license_data = dict(_require_mapping(source.get("license"), "source.license"))
    _reject_unknown_fields(
        license_data,
        {"name", "url", "redistributable", "research_use_allowed"},
        "license",
    )
    _require_nonempty_string(license_data.get("name"), "source.license.name")
    _require_nonempty_string(license_data.get("url"), "source.license.url")
    if type(license_data.get("redistributable")) is not bool:
        raise ManifestValidationError("source.license.redistributable must be boolean")
    if license_data.get("research_use_allowed") is not True:
        raise ManifestValidationError("source license must explicitly allow research use")
    source["license"] = license_data
    manifest["source"] = source

    labeling = dict(_require_mapping(manifest.get("labeling"), "labeling"))
    _reject_unknown_fields(
        labeling,
        {
            "positive_class",
            "negative_class",
            "label_source",
            "validation_reference",
            "model_predictions_used_as_ground_truth",
        },
        "labeling",
    )
    if labeling.get("positive_class") != "PHISHING" or labeling.get("negative_class") != "LEGITIMATE":
        raise ManifestValidationError("Stage B class semantics must be PHISHING vs LEGITIMATE")
    label_source = _require_nonempty_string(labeling.get("label_source"), "labeling.label_source")
    if label_source not in LABEL_SOURCES_BY_PROVENANCE[provenance]:
        raise ManifestValidationError(f"label_source {label_source} is not valid for provenance {provenance}")
    _require_nonempty_string(labeling.get("validation_reference"), "labeling.validation_reference")
    if labeling.get("model_predictions_used_as_ground_truth") is not False:
        raise ManifestValidationError("model predictions must never be used as Stage B ground-truth labels")
    manifest["labeling"] = labeling

    privacy = dict(_require_mapping(manifest.get("privacy"), "privacy"))
    _reject_unknown_fields(
        privacy,
        {"contains_raw_page_content", "contains_secrets", "pii_review_status"},
        "privacy",
    )
    if type(privacy.get("contains_raw_page_content")) is not bool:
        raise ManifestValidationError("privacy.contains_raw_page_content must be boolean")
    if privacy.get("contains_secrets") is not False:
        raise ManifestValidationError("datasets containing secrets are not accepted")
    if privacy.get("pii_review_status") not in PII_STATUS:
        raise ManifestValidationError("privacy.pii_review_status is invalid")
    manifest["privacy"] = privacy

    grouping = dict(_require_mapping(manifest.get("grouping"), "grouping"))
    required_group_fields = {"domain_group", "brand_group", "time_group", "source_group"}
    _reject_unknown_fields(grouping, required_group_fields, "grouping")
    if set(grouping) != required_group_fields:
        raise ManifestValidationError("all grouping availability fields are required")
    for key, value in grouping.items():
        if value not in GROUP_STATUS:
            raise ManifestValidationError(f"grouping.{key} has invalid status")
    manifest["grouping"] = grouping

    intended_use = manifest.get("intended_use")
    if not isinstance(intended_use, list) or not intended_use or len(set(intended_use)) != len(intended_use):
        raise ManifestValidationError("intended_use must be a non-empty unique list")
    if set(intended_use) - INTENDED_USE:
        raise ManifestValidationError("intended_use contains unsupported partition purpose")

    limitations = manifest.get("limitations")
    if not isinstance(limitations, list) or not limitations or any(not isinstance(v, str) or not v.strip() for v in limitations):
        raise ManifestValidationError("at least one explicit dataset limitation is required")

    return manifest


def validate_manifest_set(items: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    manifests: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for raw in items:
        manifest = validate_source_manifest(raw)
        dataset_id = manifest["dataset_id"]
        content_hash = manifest["source"]["content_sha256"]
        if dataset_id in manifests:
            raise ManifestValidationError(f"duplicate dataset_id: {dataset_id}")
        if content_hash in hashes:
            raise ManifestValidationError(
                f"duplicate content SHA-256 shared by {hashes[content_hash]} and {dataset_id}"
            )
        manifests[dataset_id] = manifest
        hashes[content_hash] = dataset_id
    if not manifests:
        raise ManifestValidationError("at least one source manifest is required")
    return manifests


def validate_sample_provenance(
    data: Mapping[str, Any],
    manifests: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    sample = deepcopy(dict(_require_mapping(data, "sample provenance")))
    allowed = {
        "schema_version",
        "sample_id",
        "dataset_id",
        "ground_truth",
        "label_source",
        "label_reference",
        "artifact_sha256",
        "observed_at",
        "domain_group",
        "brand_group",
        "source_group",
    }
    _reject_unknown_fields(sample, allowed, "sample")
    if sample.get("schema_version") != SAMPLE_SCHEMA:
        raise ManifestValidationError(f"schema_version must be {SAMPLE_SCHEMA}")
    _require_nonempty_string(sample.get("sample_id"), "sample_id")
    dataset_id = _require_nonempty_string(sample.get("dataset_id"), "dataset_id")
    if dataset_id not in manifests:
        raise ManifestValidationError(f"unknown dataset_id: {dataset_id}")

    source_manifest = validate_source_manifest(manifests[dataset_id])
    if type(sample.get("ground_truth")) is not int or sample["ground_truth"] not in (0, 1):
        raise ManifestValidationError("ground_truth must be integer 0 or 1")
    if sample.get("label_source") != source_manifest["labeling"]["label_source"]:
        raise ManifestValidationError("sample label_source must match its source manifest")
    _require_nonempty_string(sample.get("label_reference"), "label_reference")
    sample["artifact_sha256"] = _require_sha256(sample.get("artifact_sha256"), "artifact_sha256")
    sample["observed_at"] = _require_timezone_timestamp(sample.get("observed_at"), "observed_at")
    _require_nonempty_string(sample.get("domain_group"), "domain_group")
    _require_nonempty_string(sample.get("brand_group"), "brand_group")
    source_group = _require_nonempty_string(sample.get("source_group"), "source_group")
    if source_group != source_manifest["source"]["independence_group"]:
        raise ManifestValidationError("sample source_group must match source.independence_group")
    return sample


def validate_split_contract(data: Mapping[str, Any]) -> dict[str, Any]:
    contract = deepcopy(dict(_require_mapping(data, "split contract")))
    _reject_unknown_fields(
        contract,
        {
            "schema_version",
            "partition_order",
            "group_isolation",
            "chronology",
            "threshold_policy",
            "final_test_locked",
        },
        "split contract",
    )
    if contract.get("schema_version") != SPLIT_SCHEMA:
        raise ManifestValidationError(f"schema_version must be {SPLIT_SCHEMA}")
    if contract.get("partition_order") != PARTITIONS:
        raise ManifestValidationError("partition_order must be train, selection, calibration, test")

    isolation = contract.get("group_isolation")
    if not isinstance(isolation, list) or len(set(isolation)) != len(isolation):
        raise ManifestValidationError("group_isolation must be a unique list")
    missing = REQUIRED_ISOLATION - set(isolation)
    if missing:
        raise ManifestValidationError(f"group_isolation must include {', '.join(sorted(missing))}")

    chronology = dict(_require_mapping(contract.get("chronology"), "chronology"))
    _reject_unknown_fields(chronology, {"field", "strict_forward_test"}, "chronology")
    if chronology.get("field") != "observed_at" or chronology.get("strict_forward_test") is not True:
        raise ManifestValidationError("chronology must enforce strict forward test using observed_at")
    contract["chronology"] = chronology

    policy = dict(_require_mapping(contract.get("threshold_policy"), "threshold_policy"))
    expected_keys = {
        "model_fit_partition",
        "candidate_selection_partition",
        "probability_calibration_partition",
        "threshold_selection_partition",
        "final_evaluation_partition",
    }
    _reject_unknown_fields(policy, expected_keys, "threshold_policy")
    if set(policy) != expected_keys:
        raise ManifestValidationError("all threshold_policy roles are required")
    if policy["model_fit_partition"] != "train":
        raise ManifestValidationError("model fitting must use train only")
    if policy["candidate_selection_partition"] != "selection":
        raise ManifestValidationError("candidate selection must use selection only")
    if policy["probability_calibration_partition"] != "calibration":
        raise ManifestValidationError("probability calibration must use calibration only")
    if policy["threshold_selection_partition"] != "calibration":
        raise ManifestValidationError("threshold selection must not use the final test partition")
    if policy["final_evaluation_partition"] != "test":
        raise ManifestValidationError("final evaluation must use test only")
    if contract.get("final_test_locked") is not True:
        raise ManifestValidationError("final test must be locked until final evaluation")
    contract["threshold_policy"] = policy
    return contract
