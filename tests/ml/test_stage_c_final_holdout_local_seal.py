from pathlib import Path
import json
import zipfile

import pytest

import ml.data.stage_c_final_holdout_local_seal as mod
from ml.data.stage_c_final_holdout_local_seal import (
    StageCFinalHoldoutLocalSealError,
)


def test_schema_and_task27_hashes_are_frozen():
    assert mod.SEAL_SCHEMA == "stage-c-final-holdout-local-integrity-seal-1"
    assert mod.EXPECTED_TASK27_AVAILABILITY_REPORT_SHA256 == (
        "c130c28f3d3678abe2df6e1d56fcb3bd64b3915b8f8ccefaf80b0d4b223ec61c"
    )
    assert mod.EXPECTED_TASK27_PUBLIC_EVIDENCE_SHA256 == (
        "d553af085a5bd256b3624b7cdf7ca7e3a9ab128d98a4e158a679cd9d020d488d"
    )


def test_primary_identity_is_exact():
    assert mod.EXPECTED_CANDIDATE_ID == "compphish-v3-2026"
    assert mod.EXPECTED_DOI == "10.17632/fmbs4kp9wz.3"
    assert mod.EXPECTED_CAPTURE_COUNT == 15358


def test_required_local_filenames_are_exact():
    assert mod.EXPECTED_HTML_ARCHIVE_NAME == "All_HTML.zip"
    assert mod.EXPECTED_MAPPING_NAME == "Mapping_File.xlsx"


def test_safe_archive_member_accepts_nested_txt():
    assert mod._safe_archive_member_name("All_HTML/00001.txt") is True


@pytest.mark.parametrize(
    "name",
    [
        "../escape.txt",
        "/absolute.txt",
        "C:/absolute.txt",
        "folder\\file.txt",
    ],
)
def test_safe_archive_member_rejects_unsafe_names(name):
    assert mod._safe_archive_member_name(name) is False


def test_html_archive_requires_exact_capture_count(tmp_path, monkeypatch):
    archive = tmp_path / "All_HTML.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("x/1.txt", b"<html></html>")
    monkeypatch.setattr(mod, "EXPECTED_CAPTURE_COUNT", 2)
    with pytest.raises(StageCFinalHoldoutLocalSealError, match="capture count"):
        mod.inspect_html_archive(archive)


def test_html_archive_rejects_non_txt_member(tmp_path, monkeypatch):
    archive = tmp_path / "All_HTML.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("x/1.txt", b"<html></html>")
        z.writestr("x/readme.md", b"x")
    monkeypatch.setattr(mod, "EXPECTED_CAPTURE_COUNT", 1)
    with pytest.raises(StageCFinalHoldoutLocalSealError, match="non-.txt"):
        mod.inspect_html_archive(archive)


def test_mapping_xlsx_integrity_without_reading_cells(tmp_path):
    path = tmp_path / "Mapping_File.xlsx"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("_rels/.rels", "<Relationships/>")
        z.writestr("xl/workbook.xml", "<workbook/>")
        z.writestr("xl/_rels/workbook.xml.rels", "<Relationships/>")
        z.writestr("xl/worksheets/sheet1.xml", "<worksheet/>")
    result = mod.inspect_mapping_workbook(path)
    assert result["crc_integrity"] == "PASS"
    assert result["worksheet_count"] == 1
    assert result["cell_values_read"] is False
    assert result["label_values_read"] is False


def test_mapping_xlsx_requires_worksheet(tmp_path):
    path = tmp_path / "Mapping_File.xlsx"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("_rels/.rels", "<Relationships/>")
        z.writestr("xl/workbook.xml", "<workbook/>")
        z.writestr("xl/_rels/workbook.xml.rels", "<Relationships/>")
    with pytest.raises(StageCFinalHoldoutLocalSealError, match="no worksheet"):
        mod.inspect_mapping_workbook(path)


def test_task28_does_not_score_or_extract_features():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "predict_proba" not in src
    assert ".fit(" not in src
    assert '"final_holdout_feature_extraction_authorized": False' in src
    assert '"final_holdout_model_scoring_authorized": False' in src


def test_task28_marks_integrity_only_byte_access():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"final_holdout_bytes_accessed_for_integrity": True' in src
    assert '"final_holdout_touch_scope": "BYTE_AND_CONTAINER_INTEGRITY_ONLY"' in src
    assert '"html_capture_contents_accessed": False' in src
    assert '"mapping_labels_accessed": False' in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "seal.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCFinalHoldoutLocalSealError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_mapping_schema_and_identity_index():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "INSPECT_COMPPHISH_MAPPING_SCHEMA_AND_BUILD_FINAL_HOLDOUT_"
        in src
    )
