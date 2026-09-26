
from __future__ import annotations
from copy import deepcopy
import hashlib
from pathlib import Path
import zipfile
import pytest
from ml.data.stage_c_local_download_seal import (
    StageCLocalSealError,
    seal_public_download,
    validate_public_download_spec,
)

def make_archive(tmp_path: Path):
    path = tmp_path / "n96ncsr5g4-1.zip"
    members = {
        "n96ncsr5g4-1/index.sql": b"create table x();",
        "n96ncsr5g4-1/dataset/dataset_part_1.zip": b"PK\x03\x04fake-one",
        "n96ncsr5g4-1/dataset/dataset_part_2.zip": b"PK\x03\x04fake-two",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in members.items():
            z.writestr(name, content)
    spec = {
        "schema_version": "stage-c-public-download-spec-1",
        "stage": "C",
        "role": "DEVELOPMENT",
        "source_id": "mendeley-n96ncsr5g4-v1",
        "doi": "10.17632/n96ncsr5g4.1",
        "version": 1,
        "license": "CC BY 4.0",
        "landing_page": "https://example.test",
        "expected_archive": {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "expected_member_count": len(members),
        },
        "expected_members": [
            {
                "name": name,
                "size_bytes": len(content),
                "kind": "INDEX_SQL" if name.endswith(".sql") else "NESTED_ZIP",
            }
            for name, content in members.items()
        ],
        "guards": {
            "research_only": True,
            "deployment_authorized": False,
            "model_training_authorized": False,
            "extraction_authorized": False,
            "final_holdout_touched": False,
        },
    }
    return path, spec, members

def test_valid_local_public_download_seals(tmp_path):
    path, spec, members = make_archive(tmp_path)
    result = seal_public_download(archive_path=path, spec=spec)
    assert result["status"] == "PASS"
    assert result["verification_mode"] == "PUBLIC_DOWNLOAD_LOCAL_SEAL"
    assert result["archive"]["member_count"] == len(members)
    assert result["archive"]["crc_integrity"] == "PASS"

def test_member_hashes_are_frozen(tmp_path):
    path, spec, members = make_archive(tmp_path)
    result = seal_public_download(archive_path=path, spec=spec)
    by_name = {x["name"]: x for x in result["members"]}
    for name, content in members.items():
        assert by_name[name]["sha256"] == hashlib.sha256(content).hexdigest()

def test_archive_sha_mismatch_is_rejected(tmp_path):
    path, spec, _ = make_archive(tmp_path)
    bad = deepcopy(spec)
    bad["expected_archive"]["sha256"] = "0" * 64
    with pytest.raises(StageCLocalSealError, match="SHA-256 mismatch"):
        seal_public_download(archive_path=path, spec=bad)

def test_member_size_mismatch_is_rejected(tmp_path):
    path, spec, _ = make_archive(tmp_path)
    bad = deepcopy(spec)
    bad["expected_members"][0]["size_bytes"] += 1
    with pytest.raises(StageCLocalSealError, match="member size mismatch"):
        seal_public_download(archive_path=path, spec=bad)

def test_extra_member_is_rejected(tmp_path):
    path, spec, _ = make_archive(tmp_path)
    with zipfile.ZipFile(path, "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr("n96ncsr5g4-1/extra.txt", b"extra")
    spec["expected_archive"]["size_bytes"] = path.stat().st_size
    spec["expected_archive"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(StageCLocalSealError, match="member-count mismatch"):
        seal_public_download(archive_path=path, spec=spec)

def test_spec_requires_all_safety_guards(tmp_path):
    _, spec, _ = make_archive(tmp_path)
    bad = deepcopy(spec)
    bad["guards"]["model_training_authorized"] = True
    with pytest.raises(StageCLocalSealError, match="guard mismatch"):
        validate_public_download_spec(bad)

def test_success_never_authorizes_training_extraction_or_holdout_touch(tmp_path):
    path, spec, _ = make_archive(tmp_path)
    result = seal_public_download(archive_path=path, spec=spec)
    assert result["model_training_authorized"] is False
    assert result["extraction_authorized"] is False
    assert result["final_holdout_touched"] is False
