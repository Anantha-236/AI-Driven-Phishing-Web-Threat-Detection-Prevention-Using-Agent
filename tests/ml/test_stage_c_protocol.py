from __future__ import annotations

import json
from pathlib import Path

import pytest

from ml.data.stage_c_protocol import (
    EXPECTED_CONTEXT_FEATURES,
    STAGE_B_CONSUMED_TEST_SHA256,
    StageCProtocolError,
    build_protocol_readiness,
    minimum_zero_fp_legitimate_count,
    reject_consumed_stage_b_holdout,
    validate_feature_semantics,
    validate_stage_c_contract,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "ml" / "data" / "manifests" / "stage-c-experiment-contract-v1.json"
SEMANTICS = ROOT / "ml" / "data" / "manifests" / "stage-c-feature-semantics-v2.json"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_stage_c_contract_locks_consumed_stage_b_test_and_low_fpr_goal():
    data = validate_stage_c_contract(load(CONTRACT))
    assert data["parent_generation"]["consumed"] is True
    assert data["parent_generation"]["final_test_partition_sha256"] == STAGE_B_CONSUMED_TEST_SHA256
    assert data["objective"]["primary_fpr_cap"] == 0.01
    assert data["objective"]["require_wilson_upper_at_or_below_cap"] is True


def test_zero_fp_wilson_resolution_matches_95_percent_one_percent_cap():
    assert minimum_zero_fp_legitimate_count(0.01) == 381


def test_feature_semantics_cover_every_existing_context_feature_once():
    data = validate_feature_semantics(load(SEMANTICS))
    grouped = [
        feature
        for values in data["groups"].values()
        for feature in values
    ]
    assert len(grouped) == len(set(grouped))
    assert set(grouped) == EXPECTED_CONTEXT_FEATURES


def test_authentication_presence_is_context_not_risk_by_definition():
    data = validate_feature_semantics(load(SEMANTICS))
    context = set(data["groups"]["page_context"])
    risk = set(data["groups"]["mismatch_or_risk_evidence"])
    assert {"has_password", "purpose_authentication", "purpose_payment"} <= context
    assert not ({"has_password", "purpose_authentication", "purpose_payment"} & risk)


def test_consumed_stage_b_test_cannot_be_registered_as_stage_c_holdout():
    with pytest.raises(StageCProtocolError, match="consumed Stage B"):
        reject_consumed_stage_b_holdout(
            {"partition_sha256": STAGE_B_CONSUMED_TEST_SHA256}
        )


def test_protocol_readiness_does_not_authorize_training_or_deployment():
    result = build_protocol_readiness(load(CONTRACT), load(SEMANTICS))
    assert result["status"] == "PASS"
    assert result["model_training_authorized"] is False
    assert result["deployment_authorized"] is False
    assert result["next_gate"] == "REGISTER_STAGE_C_DATASET_AND_NEW_FINAL_HOLDOUT"
