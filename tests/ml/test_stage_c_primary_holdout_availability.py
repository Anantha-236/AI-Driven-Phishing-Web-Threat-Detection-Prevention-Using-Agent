from pathlib import Path

import pytest

import ml.data.stage_c_primary_holdout_availability as mod
from ml.data.stage_c_primary_holdout_availability import (
    StageCPrimaryHoldoutAvailabilityError,
)


def test_schema_and_task26_hashes_are_frozen():
    assert mod.EVIDENCE_SCHEMA == (
        "stage-c-primary-holdout-availability-evidence-1"
    )
    assert mod.EXPECTED_TASK26_POLICY_SHA256 == (
        "dd7a3e9c9abc5040fa857564a8413903a94a2597f3d5c8589655f55abae522d8"
    )


def test_primary_identity_is_exact():
    assert mod.PRIMARY_CANDIDATE_ID == "compphish-v3-2026"
    assert mod.PRIMARY_DOI == "10.17632/fmbs4kp9wz.3"
    assert mod.PRIMARY_VERSION == 3


def test_public_evidence_reports_expected_counts():
    assert mod.PUBLIC_EVIDENCE["sample_count"] == 15358
    assert mod.PUBLIC_EVIDENCE["class_counts"] == {
        "legitimate": 8154,
        "phishing": 7204,
    }


def test_public_evidence_reports_download_control():
    assert mod.PUBLIC_EVIDENCE["page_reachable"] is True
    assert mod.PUBLIC_EVIDENCE["download_all_control_visible"] is True


def test_required_raw_files_are_visible():
    names = {x["name"] for x in mod.PUBLIC_FILE_INVENTORY_DISPLAY}
    assert "All_HTML.zip" in names
    assert "Mapping_File.xlsx" in names


def test_remote_crypto_manifest_is_not_fabricated():
    assert mod.PUBLIC_EVIDENCE["remote_file_uuids_frozen"] is False
    assert mod.PUBLIC_EVIDENCE["remote_file_sha256_frozen"] is False
    assert mod.PUBLIC_EVIDENCE["authenticated_api_inventory_available"] is False


def test_decision_keeps_primary_active():
    assert mod.DECISION == "PRIMARY_PUBLICLY_AVAILABLE_FOR_MANUAL_ACQUISITION"


def test_task27_does_not_touch_holdout_bytes():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "urlopen(" not in src
    assert "requests.get(" not in src
    assert '"final_holdout_touched": false' in src


def test_task27_does_not_score_or_extract_features():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "predict_proba" not in src
    assert ".fit(" not in src
    assert '"final_holdout_feature_extraction_authorized": False' in src
    assert '"final_holdout_model_scoring_authorized": False' in src


def test_local_seal_required_before_feature_extraction():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"local_integrity_seal_required_before_feature_extraction": True' in src
    assert '"feature_extraction_before_local_seal": True' in src


def test_primary_download_prevents_premature_fallback():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        '"fallback_activation_while_primary_download_is_available": True'
        in src
    )


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "availability.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCPrimaryHoldoutAvailabilityError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_manual_download_and_local_seal():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "MANUALLY_DOWNLOAD_COMPPHISH_V3_AND_FREEZE_LOCAL_INTEGRITY_SEAL"
        in src
    )
