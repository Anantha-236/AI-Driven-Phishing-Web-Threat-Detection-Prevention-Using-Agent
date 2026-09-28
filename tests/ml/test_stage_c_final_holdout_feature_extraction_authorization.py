from copy import deepcopy
from pathlib import Path

import pytest

import ml.data.stage_c_final_holdout_feature_extraction_authorization as mod
from ml.data.stage_c_final_holdout_feature_extraction_authorization import (
    StageCFinalHoldoutFeatureAuthorizationError,
)


def clean_fixture():
    records = []
    for i, label in [(1, 0), (2, 1)]:
        records.append({
            "sample_id": f"s{i}",
            "label": label,
            "html_member_name": f"{i}.txt",
            "html_basename": f"{i}.txt",
            "html_sha256": (str(i) * 64)[:64],
            "normalized_url_sha256": ("a" * 64 if i == 1 else "b" * 64),
            "hostname_sha256": ("c" * 64 if i == 1 else "d" * 64),
            "identity_component_size": 1,
            "identity_component_sha256": ("e" * 64 if i == 1 else "f" * 64),
        })
    core = {
        "candidate_id": "compphish-v3-2026",
        "source_id": "mendeley-fmbs4kp9wz-v3",
        "doi": "10.17632/fmbs4kp9wz.3",
        "sample_count": 2,
        "class_counts": {"legitimate": 1, "phishing": 1},
        "records": records,
    }
    return {
        "schema_version": "stage-c-final-holdout-clean-evaluation-set-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT_CLEAN_EVALUATION_SUBSET",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        **core,
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
        "sample_set_sha256": mod.canonical_hash(["s1", "s2"]),
        "record_set_sha256": mod.canonical_hash(records),
        "clean_set_identity_sha256": mod.canonical_hash(core),
        "identity_bindings": {
            "task29_record_set_sha256": mod.EXPECTED_TASK29_RECORD_SET_SHA256,
            "task29_index_identity_sha256": mod.EXPECTED_TASK29_INDEX_IDENTITY_SHA256,
            "stage_c_development_record_set_sha256": (
                mod.EXPECTED_STAGE_C_DEVELOPMENT_RECORD_SET_SHA256
            ),
            "consumed_stage_b_test_partition_sha256": (
                mod.EXPECTED_STAGE_B_TEST_PARTITION_SHA256
            ),
            "git_head": mod.EXPECTED_TASK30_GIT_HEAD,
        },
        "next_gate": (
            "AUTHORIZE_STAGE_C_FINAL_HOLDOUT_FEATURE_EXTRACTION_ON_"
            "CLEAN_IDENTITY_SUBSET"
        ),
    }


def test_frozen_clean_counts():
    assert mod.EXPECTED_CLEAN_SAMPLE_COUNT == 12711
    assert mod.EXPECTED_CLEAN_CLASS_COUNTS == {
        "legitimate": 7609,
        "phishing": 5102,
    }


def test_clean_hashes_are_frozen():
    assert mod.EXPECTED_CLEAN_SAMPLE_SET_SHA256.startswith("451a45d5")
    assert mod.EXPECTED_CLEAN_RECORD_SET_SHA256.startswith("420b0ab5")


def test_task30_git_head_is_exact_commit():
    assert mod.EXPECTED_TASK30_GIT_HEAD == (
        "e7e681836bb0c75760d61a91749f816d23637e80"
    )


def test_frozen_operating_point_is_bound():
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"
    assert mod.EXPECTED_THRESHOLD == 0.8637646437995518
    assert mod.EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256.startswith("25286bce")


def test_feature_contract_is_exact_27():
    assert len(mod.EXPECTED_FEATURES) == 27
    assert len(set(mod.EXPECTED_FEATURES)) == 27
    assert mod.EXPECTED_FEATURES[0] == "document_started"
    assert mod.EXPECTED_FEATURES[-1] == "purpose_observed"


def test_feature_contract_hash_is_frozen():
    assert mod.EXPECTED_FEATURE_CONTRACT_SHA256 == (
        "2ee75478749e347f84e97b6fb8911a5b961019be6e282b28792a3e70b0c95a6b"
    )


def test_task28_bytes_are_bound():
    assert mod.EXPECTED_HTML_ARCHIVE_SHA256.startswith("12440e4f")
    assert mod.EXPECTED_MAPPING_WORKBOOK_SHA256.startswith("e6dda6a2")


def test_synthetic_clean_fixture_identity_self_consistent():
    fixture = clean_fixture()
    core = {
        "candidate_id": fixture["candidate_id"],
        "source_id": fixture["source_id"],
        "doi": fixture["doi"],
        "sample_count": fixture["sample_count"],
        "class_counts": fixture["class_counts"],
        "records": fixture["records"],
    }
    assert fixture["clean_set_identity_sha256"] == mod.canonical_hash(core)


def test_duplicate_html_would_be_rejected(monkeypatch):
    fixture = clean_fixture()
    fixture["records"][1]["html_sha256"] = fixture["records"][0]["html_sha256"]
    assert fixture["records"][0]["html_sha256"] == fixture["records"][1]["html_sha256"]


def test_no_model_scoring_dependency():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "predict_proba" not in src
    assert ".fit(" not in src


def test_authorization_declares_scoring_locked():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"final_holdout_model_scoring_authorized": False' in src
    assert '"final_holdout_metrics_authorized": False' in src
    assert '"threshold_change_authorized": False' in src


def test_collection_loss_policy_is_precommitted():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"collection_incomplete_rows_model_scoring_authorized": False' in src
    assert '"performance_based_exclusion_authorized": False' in src


def test_only_clean_subset_is_authorized():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"quarantined_or_duplicate_rows_authorized": False' in src
    assert '"non_clean_holdout_rows_authorized": False' in src


def test_next_gate_is_extraction_without_scoring():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "EXTRACT_STAGE_C_FINAL_HOLDOUT_FEATURES_AND_SEAL_WITHOUT_MODEL_SCORING"
        in src
    )


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCFinalHoldoutFeatureAuthorizationError):
        mod.frozen_write_json(path, {"x": 2})


def test_task31_task24_schema_matches_task24_producer():
    import ml.evaluation.stage_c_threshold_freeze as task24

    assert task24.FREEZE_SCHEMA == "stage-c-threshold-freeze-1"

    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"schema_version": "stage-c-threshold-freeze-1"' in source
    assert '"schema_version": "stage-c-threshold-freeze-record-1"' not in source
