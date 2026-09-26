"""Stage C Task 1: experiment protocol and feature-semantics guardrails."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

CONTRACT_SCHEMA = "stage-c-experiment-contract-1"
SEMANTICS_SCHEMA = "stage-c-feature-semantics-2"

STAGE_B_CONSUMED_TEST_SHA256 = (
    "a7d83608610370f7772ee2820bdf0229cd14e97c6f18143130125c7db7a4fd2d"
)
STAGE_B_FINAL_SCORE_SHA256 = (
    "46c2ec3747bceb7fdc950ddea1ea5733f37efe023cde9d6782f8c3fc0a3de438"
)
EXPECTED_CONTEXT_FEATURES = {
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
}


class StageCProtocolError(ValueError):
    pass


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCProtocolError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCProtocolError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCProtocolError(f"JSON root must be an object: {path}")
    return value


def wilson_upper(successes: int, total: int, confidence_z: float = 1.959963984540054) -> float:
    if type(successes) is not int or type(total) is not int:
        raise StageCProtocolError("Wilson inputs must be integers")
    if total <= 0 or successes < 0 or successes > total:
        raise StageCProtocolError("invalid Wilson inputs")
    p = successes / total
    z2 = confidence_z * confidence_z
    denominator = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denominator
    half = (
        confidence_z
        * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total)
        / denominator
    )
    return center + half


def minimum_zero_fp_legitimate_count(fpr_cap: float = 0.01) -> int:
    if not 0 < float(fpr_cap) < 1:
        raise StageCProtocolError("FPR cap must be between zero and one")
    total = 1
    while wilson_upper(0, total) > fpr_cap:
        total += 1
    return total


def validate_stage_c_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != CONTRACT_SCHEMA:
        raise StageCProtocolError("unsupported Stage C experiment-contract schema")
    if contract.get("stage") != "C":
        raise StageCProtocolError("Stage C contract must declare stage C")
    if contract.get("research_only") is not True:
        raise StageCProtocolError("Stage C must begin research-only")
    if contract.get("deployment_authorized") is not False:
        raise StageCProtocolError("Stage C contract cannot authorize deployment")

    parent = contract.get("parent_generation")
    if not isinstance(parent, Mapping):
        raise StageCProtocolError("parent_generation is required")
    if parent.get("final_test_partition_sha256") != STAGE_B_CONSUMED_TEST_SHA256:
        raise StageCProtocolError("Stage B consumed-test identity mismatch")
    if parent.get("final_test_score_sha256") != STAGE_B_FINAL_SCORE_SHA256:
        raise StageCProtocolError("Stage B frozen-score identity mismatch")
    if parent.get("consumed") is not True:
        raise StageCProtocolError("Stage B final test must remain marked consumed")
    if parent.get("reuse_as_fresh_final_test_prohibited") is not True:
        raise StageCProtocolError("Stage B final-test reuse guard is missing")

    objective = contract.get("objective")
    if not isinstance(objective, Mapping):
        raise StageCProtocolError("Stage C objective is required")
    cap = objective.get("primary_fpr_cap")
    if type(cap) not in (int, float) or float(cap) != 0.01:
        raise StageCProtocolError("Stage C primary FPR cap must remain 0.01")
    if objective.get("require_observed_fpr_at_or_below_cap") is not True:
        raise StageCProtocolError("observed-FPR requirement is missing")
    if objective.get("require_wilson_upper_at_or_below_cap") is not True:
        raise StageCProtocolError("Wilson-confidence requirement is missing")

    holdout = contract.get("holdout_contract")
    if not isinstance(holdout, Mapping):
        raise StageCProtocolError("holdout_contract is required")
    for key in (
        "new_final_holdout_required",
        "stage_b_final_test_samples_prohibited",
        "selection_use_prohibited",
        "calibration_use_prohibited",
        "threshold_selection_use_prohibited",
    ):
        if holdout.get(key) is not True:
            raise StageCProtocolError(f"Stage C holdout guard missing: {key}")

    expected_min = minimum_zero_fp_legitimate_count(float(cap))
    if holdout.get("minimum_legitimate_samples_for_zero_fp_wilson_resolution") != expected_min:
        raise StageCProtocolError(
            "zero-FP Wilson-resolution sample count does not match the 1%/95% contract"
        )

    development = contract.get("development_contract")
    if not isinstance(development, Mapping):
        raise StageCProtocolError("development_contract is required")
    if development.get("purpose_context_must_not_be_treated_as_maliciousness_by_definition") is not True:
        raise StageCProtocolError("purpose/risk decoupling guard is missing")

    return dict(contract)


def validate_feature_semantics(semantics: Mapping[str, Any]) -> dict[str, Any]:
    if semantics.get("schema_version") != SEMANTICS_SCHEMA:
        raise StageCProtocolError("unsupported Stage C feature-semantics schema")
    if semantics.get("source_feature_version") != "context-features-1":
        raise StageCProtocolError("Task 1 must classify context-features-1")

    groups = semantics.get("groups")
    if not isinstance(groups, Mapping):
        raise StageCProtocolError("feature semantic groups are required")

    expected_group_names = {
        "evidence_quality",
        "page_context",
        "consistency_or_trust",
        "mismatch_or_risk_evidence",
    }
    if set(groups) != expected_group_names:
        raise StageCProtocolError("unexpected feature semantic group set")

    seen: dict[str, str] = {}
    for group_name, values in groups.items():
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise StageCProtocolError(f"invalid feature list for {group_name}")
        for feature in values:
            if feature in seen:
                raise StageCProtocolError(
                    f"feature {feature} appears in both {seen[feature]} and {group_name}"
                )
            seen[feature] = group_name

    actual = set(seen)
    missing = EXPECTED_CONTEXT_FEATURES - actual
    extra = actual - EXPECTED_CONTEXT_FEATURES
    if missing or extra:
        raise StageCProtocolError(
            f"feature semantics do not cover exact Stage B contract; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )

    rules = semantics.get("rules")
    if not isinstance(rules, Mapping):
        raise StageCProtocolError("feature-semantics rules are required")
    if rules.get("page_context_is_not_intrinsically_malicious") is not True:
        raise StageCProtocolError("page-context/risk separation rule is missing")
    for sensitive_name in (
        "brand_group_model_observable",
        "raw_url_model_observable",
        "literal_origin_model_observable",
        "sample_id_model_observable",
    ):
        if rules.get(sensitive_name) is not False:
            raise StageCProtocolError(f"model-observability guard failed: {sensitive_name}")

    return dict(semantics)


def reject_consumed_stage_b_holdout(dataset_identity: Mapping[str, Any]) -> None:
    """Reject any candidate final holdout that aliases the consumed Stage-B test."""
    candidates = {
        dataset_identity.get("partition_sha256"),
        dataset_identity.get("dataset_sha256"),
        dataset_identity.get("source_partition_sha256"),
    }
    if STAGE_B_CONSUMED_TEST_SHA256 in candidates:
        raise StageCProtocolError(
            "Stage C final holdout aliases the consumed Stage B final test"
        )


def build_protocol_readiness(
    contract: Mapping[str, Any],
    semantics: Mapping[str, Any],
) -> dict[str, Any]:
    validated_contract = validate_stage_c_contract(contract)
    validated_semantics = validate_feature_semantics(semantics)
    return {
        "schema_version": "stage-c-protocol-readiness-1",
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "reason": "PROTOCOL_READY_NEW_DATASET_NOT_YET_REGISTERED",
        "contract_sha256": canonical_hash(validated_contract),
        "feature_semantics_sha256": canonical_hash(validated_semantics),
        "consumed_stage_b_test_sha256": STAGE_B_CONSUMED_TEST_SHA256,
        "new_final_holdout_required": True,
        "next_gate": "REGISTER_STAGE_C_DATASET_AND_NEW_FINAL_HOLDOUT",
    }
