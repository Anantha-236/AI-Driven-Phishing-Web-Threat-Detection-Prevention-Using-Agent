from pathlib import Path
import pytest
import ml.data.stage_c_feature_extraction_authorization_v2 as mod
from ml.data.stage_c_feature_extraction_authorization import (
    StageCFeatureAuthorizationError,
)

PROD = [
    "document_started","has_password","has_otp","has_payment","has_identity",
    "purpose_authentication","purpose_payment","purpose_unknown",
    "sensitive_form_count","same_origin_sensitive_target",
    "cross_origin_sensitive_target","stable_sensitive_target",
    "sensitive_target_changed","target_changed_after_interaction",
    "submission_target_mismatch","https_downgrade_sensitive_target",
    "password_then_otp","dynamic_sensitive_field",
    "foreign_frame_sensitive_field","cross_request_near_interaction",
    "unknown_document_ratio","known_target_ratio","contradiction_count",
    "positive_evidence_count","purpose_sensitive_mismatch",
    "purpose_context_consistent","purpose_observed"
]


def production():
    return {
        "feature_version":"context-features-1",
        "ordered_features":PROD,
        "feature_count":27,
        "feature_contract_sha256":mod.canonical_hash({
            "feature_version":"context-features-1",
            "feature_names":PROD,
        }),
        "extractor_source_sha256":"a"*64,
        "extractor_source":"browser-extension/src/core/tsfeg.ts",
    }


def test_production_order_frozen():
    assert PROD[:5] == [
        "document_started","has_password","has_otp","has_payment","has_identity"
    ]
    assert PROD[20:23] == [
        "unknown_document_ratio","known_target_ratio","contradiction_count"
    ]


def test_semantic_group_order_is_not_vector_order():
    grouped = [
        "document_started","unknown_document_ratio",
        "known_target_ratio","purpose_observed"
    ]
    assert PROD[:4] != grouped


def test_feature_contract_hash_order_sensitive():
    p = production()
    reversed_names = list(reversed(PROD))
    other = mod.canonical_hash({
        "feature_version":"context-features-1",
        "feature_names":reversed_names,
    })
    assert p["feature_contract_sha256"] != other


def test_v1_training_guard_rejected():
    old = {
        "schema_version":"stage-c-feature-extraction-authorization-1",
        "status":"PASS","stage":"C","research_only":True,
        "deployment_authorized":False,
        "feature_extraction_authorized":True,
        "model_training_authorized":True,
        "model_selection_authorized":False,
        "calibration_fitting_authorized":False,
        "threshold_selection_authorized":False,
        "model_scoring_authorized":False,
        "final_holdout_touched":False,
        "authorization_sha256":"b"*64,
    }
    with pytest.raises(StageCFeatureAuthorizationError):
        mod._require_superseded_v1(old)


def test_feature_set_matches_expected():
    assert set(PROD) == set(mod.EXPECTED_CONTEXT_FEATURES)
    assert len(PROD) == 27


def test_source_hash_shape():
    assert len(production()["extractor_source_sha256"]) == 64


def test_no_training_dependency():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src


def test_no_final_holdout_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src
