
from __future__ import annotations
from io import BytesIO
import hashlib
from pathlib import Path
import zipfile
import pytest

import ml.data.stage_c_development_record_index as mod
from ml.data.stage_c_development_record_index import (
    StageCDevelopmentIndexError,
    build_development_record_index,
    frozen_write_json,
)

def make_nested(files):
    b = BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return b.getvalue()

def make_fixture(tmp_path: Path):
    index = b"""CREATE TABLE `index` (
`rec_id` int NOT NULL,
`url` text NOT NULL,
`website` varchar(50) NOT NULL,
`result` int NOT NULL,
`created_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
INSERT INTO `index` (`rec_id`,`url`,`website`,`result`,`created_date`) VALUES
(1,'https://a.test','1001.html',0,'2021-01-01 00:00:00'),
(2,'https://b.test','1002.html',1,'2021-01-02 00:00:00');
"""
    nested = [make_nested({}) for _ in range(8)]
    nested[0] = make_nested({"1001.html": b"<html>same</html>"})
    nested[1] = make_nested({
        "1002.html": b"<html>same</html>",
        "extra.html": b"archive-only",
    })
    outer = tmp_path / "n96ncsr5g4-1.zip"
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("n96ncsr5g4-1/index.sql", index)
        for i, payload in enumerate(nested, 1):
            z.writestr(f"n96ncsr5g4-1/dataset/dataset_part_{i}.zip", payload)

    members = []
    with zipfile.ZipFile(outer) as z:
        for info in z.infolist():
            payload = z.read(info)
            members.append({
                "name": info.filename,
                "sha256": hashlib.sha256(payload).hexdigest(),
            })

    seal = {
        "schema_version": "stage-c-public-download-local-seal-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "verification_mode": "PUBLIC_DOWNLOAD_LOCAL_SEAL",
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
        "source": {"doi": "10.17632/n96ncsr5g4.1", "version": 1},
        "archive": {
            "filename": outer.name,
            "size_bytes": outer.stat().st_size,
            "sha256": hashlib.sha256(outer.read_bytes()).hexdigest(),
        },
        "members": members,
        "member_set_sha256": "a" * 64,
    }
    inspection = {
        "schema_version": "stage-c-development-corpus-inspection-2",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "inspection_mode": "READ_ONLY_IN_MEMORY_NO_EXTRACTION",
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
        "next_gate": "BUILD_DETERMINISTIC_DEVELOPMENT_RECORD_INDEX",
        "inspection_evidence_sha256": "b" * 64,
        "reconciliation": {
            "metadata_rows": 2,
            "metadata_unique_rec_ids": 2,
            "metadata_duplicate_rec_ids": 0,
            "metadata_unique_website_filenames": 2,
            "metadata_duplicate_website_references": 0,
            "metadata_missing_html_count": 0,
            "published_expected_records": 2,
            "metadata_rows_equal_published_expected": True,
            "class_counts": {"0": 1, "1": 1},
            "archive_extra_html_count": 1,
        },
    }
    return outer, seal, inspection

def patch_tiny_task5_guard(monkeypatch):
    def guard(report):
        required = {
            "schema_version": "stage-c-development-corpus-inspection-2",
            "status": "PASS",
            "stage": "C",
            "role": "DEVELOPMENT",
            "inspection_mode": "READ_ONLY_IN_MEMORY_NO_EXTRACTION",
            "model_training_authorized": False,
            "extraction_authorized": False,
            "final_holdout_touched": False,
            "next_gate": "BUILD_DETERMINISTIC_DEVELOPMENT_RECORD_INDEX",
        }
        for key, expected in required.items():
            if report.get(key) != expected:
                raise StageCDevelopmentIndexError(f"Task-5 inspection guard mismatch: {key}")
    monkeypatch.setattr(mod, "_require_task5_report", guard)

def test_frozen_write_is_idempotent(tmp_path):
    p = tmp_path / "x.json"
    assert frozen_write_json(p, {"x": 1}) == "CREATED"
    assert frozen_write_json(p, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCDevelopmentIndexError, match="non-identical"):
        frozen_write_json(p, {"x": 2})

def test_real_task5_contract_rejects_non_80k():
    _, _, inspection = make_fixture(Path.cwd())
    with pytest.raises(StageCDevelopmentIndexError):
        mod._require_task5_report(inspection)

def test_sample_ids_are_stable():
    assert mod._sample_id(1) == "mendeley-n96ncsr5g4-v1:000001"
    assert mod._sample_id(80000) == "mendeley-n96ncsr5g4-v1:080000"

def test_archive_hash_is_enforced(tmp_path):
    path, seal, _ = make_fixture(tmp_path)
    seal["archive"]["sha256"] = "0" * 64
    with pytest.raises(StageCDevelopmentIndexError, match="SHA256 mismatch"):
        mod._validate_archive_identity(path, seal)

def test_full_tiny_build_maps_hashes_and_quarantines_extra(tmp_path, monkeypatch):
    path, seal, inspection = make_fixture(tmp_path)
    patch_tiny_task5_guard(monkeypatch)
    index, quarantine, report = build_development_record_index(
        archive_path=path,
        seal=seal,
        inspection=inspection,
    )
    assert index["record_count"] == 2
    assert index["class_counts"] == {"legitimate": 1, "phishing": 1}
    assert [x["sample_id"] for x in index["records"]] == [
        "mendeley-n96ncsr5g4-v1:000001",
        "mendeley-n96ncsr5g4-v1:000002",
    ]
    assert index["records"][0]["html_sha256"] == index["records"][1]["html_sha256"]
    assert quarantine["count"] == 1
    assert quarantine["entries"][0]["supervised_label_assigned"] is False
    assert report["duplicate_artifact_groups"] == 1
    assert report["duplicate_artifact_samples"] == 2
    assert report["cross_label_duplicate_artifact_groups"] == 1
    assert report["cross_label_duplicate_artifact_samples"] == 2
    assert report["rec_id_contiguous_1_to_expected"] is True

def test_changed_nested_hash_is_rejected(tmp_path, monkeypatch):
    path, seal, inspection = make_fixture(tmp_path)
    patch_tiny_task5_guard(monkeypatch)
    seal["members"] = [dict(x) for x in seal["members"]]
    next(x for x in seal["members"] if x["name"].endswith("dataset_part_1.zip"))["sha256"] = "0"*64
    with pytest.raises(StageCDevelopmentIndexError, match="hash differs"):
        build_development_record_index(archive_path=path, seal=seal, inspection=inspection)

def test_final_holdout_is_not_accessed():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src
    assert "mendeley-fmbs4kp9wz" not in src

def test_no_training_or_scoring_codepath():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src
