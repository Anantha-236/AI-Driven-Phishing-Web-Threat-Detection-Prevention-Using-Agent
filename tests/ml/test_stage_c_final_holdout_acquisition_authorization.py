from pathlib import Path

import pytest

import ml.data.stage_c_final_holdout_acquisition_authorization as mod
from ml.data.stage_c_final_holdout_acquisition_authorization import (
    StageCFinalHoldoutAcquisitionAuthorizationError,
)


def test_schema_and_task24_identities_are_frozen():
    assert mod.AUTH_SCHEMA == (
        "stage-c-final-holdout-acquisition-authorization-1"
    )
    assert mod.EXPECTED_TASK24_FREEZE_RECORD_SHA256 == (
        "081a36b04e1f319081e84ab23172bd633d799877b58db27a33d80f8087b617ee"
    )
    assert mod.EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256 == (
        "25286bcee337d4731eda836f23cf3032c4b9ae0922a3742fa7a15251da5aa0eb"
    )


def test_hash_constants_are_full_lower_hex():
    for value in (
        mod.EXPECTED_TASK24_FREEZE_RECORD_SHA256,
        mod.EXPECTED_CANDIDATE_THRESHOLD_PAIR_SHA256,
        mod.EXPECTED_SELECTED_ARTIFACT_SHA256,
    ):
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_frozen_operating_point_is_exact():
    assert mod.EXPECTED_SELECTED_CANDIDATE_ID == "logistic_regression"
    assert mod.EXPECTED_THRESHOLD == 0.8637646437995518
    assert mod.EXPECTED_SELECTED_ARTIFACT_SHA256 == (
        "32cdbaf338b731dc1e8a7a1fb4a15ef614aa8ba86c43a491c5a573e14359ac70"
    )


def test_holdout_identity_is_exact():
    assert mod.EXPECTED_HOLDOUT_CANDIDATE_ID == "compphish-v3-2026"
    assert mod.EXPECTED_HOLDOUT_SOURCE_ID == "mendeley-fmbs4kp9wz-v3"
    assert mod.EXPECTED_HOLDOUT_DOI == "10.17632/fmbs4kp9wz.3"
    assert mod.EXPECTED_HOLDOUT_LICENSE == "CC BY 4.0"


def test_holdout_expected_counts_are_frozen():
    assert mod.EXPECTED_HOLDOUT_COUNTS == {
        "legitimate": 8154,
        "phishing": 7204,
    }


def test_task25_authorizes_acquisition_not_scoring():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"final_holdout_acquisition_authorized": True' in src
    assert '"final_holdout_download_authorized": True' in src
    assert '"final_holdout_feature_extraction_authorized": False' in src
    assert '"final_holdout_model_scoring_authorized": False' in src
    assert '"final_holdout_metrics_authorized": False' in src


def test_task25_does_not_touch_holdout():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert '"final_holdout_touched": false' in src
    assert "urlopen(" not in src
    assert "requests.get(" not in src


def test_task25_does_not_execute_model():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "predict_proba" not in src
    assert "pickle.load" not in src
    assert ".fit(" not in src


def test_scoring_and_analysis_are_explicitly_prohibited():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"model_scoring": True' in src
    assert '"metric_computation": True' in src
    assert '"error_analysis": True' in src
    assert '"threshold_change": True' in src


def test_only_expected_pre_scoring_operations_are_authorized():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "FETCH_PINNED_REMOTE_METADATA" in src
    assert "FREEZE_REMOTE_FILE_INVENTORY" in src
    assert "VERIFY_ARCHIVE_SHA256_AND_SIZE" in src
    assert "BUILD_PRIVACY_REDUCED_IDENTITY_INDEX" in src
    assert "AUDIT_CONTAMINATION_AGAINST_DEVELOPMENT_AND_CONSUMED_STAGE_B_TEST" in src


def test_stage_b_consumed_final_test_reuse_stays_prohibited():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"use_stage_b_consumed_final_test": True' in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "auth.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(
        StageCFinalHoldoutAcquisitionAuthorizationError,
        match="non-identical",
    ):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_remote_inventory_freeze():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "FREEZE_STAGE_C_FINAL_HOLDOUT_REMOTE_INVENTORY_AND_DOWNLOAD_MANIFEST"
        in src
    )
