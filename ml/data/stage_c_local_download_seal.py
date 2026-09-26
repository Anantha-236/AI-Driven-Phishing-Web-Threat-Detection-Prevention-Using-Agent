
from __future__ import annotations
import hashlib, json, zipfile
from pathlib import Path
from typing import Any, Mapping

SPEC_SCHEMA = "stage-c-public-download-spec-1"
SEAL_SCHEMA = "stage-c-public-download-local-seal-1"

class StageCLocalSealError(ValueError):
    pass

def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def sha256_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info, "r") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCLocalSealError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCLocalSealError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCLocalSealError(f"JSON root must be an object: {path}")
    return value

def validate_public_download_spec(spec: Mapping[str, Any]) -> dict[str, Any]:
    if spec.get("schema_version") != SPEC_SCHEMA:
        raise StageCLocalSealError("unsupported public-download specification")
    if spec.get("stage") != "C" or spec.get("role") != "DEVELOPMENT":
        raise StageCLocalSealError("public-download spec must be Stage-C DEVELOPMENT")
    if spec.get("doi") != "10.17632/n96ncsr5g4.1" or spec.get("version") != 1:
        raise StageCLocalSealError("development DOI/version drift detected")

    expected = spec.get("expected_archive")
    if not isinstance(expected, Mapping):
        raise StageCLocalSealError("expected_archive is required")
    if expected.get("filename") != "n96ncsr5g4-1.zip":
        raise StageCLocalSealError("unexpected public archive filename")
    if type(expected.get("size_bytes")) is not int or expected["size_bytes"] <= 0:
        raise StageCLocalSealError("expected archive size is invalid")
    digest = expected.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
        raise StageCLocalSealError("expected archive SHA-256 is invalid")

    members = spec.get("expected_members")
    if not isinstance(members, list) or not members:
        raise StageCLocalSealError("expected_members is required")
    seen = set()
    for member in members:
        if not isinstance(member, Mapping):
            raise StageCLocalSealError("invalid expected-member entry")
        name = member.get("name")
        if not isinstance(name, str) or not name or name in seen:
            raise StageCLocalSealError("expected member name missing or duplicated")
        seen.add(name)
        if type(member.get("size_bytes")) is not int or member["size_bytes"] < 0:
            raise StageCLocalSealError(f"invalid expected size for {name}")
        if member.get("kind") not in {"INDEX_SQL", "NESTED_ZIP"}:
            raise StageCLocalSealError(f"invalid expected kind for {name}")
    if expected.get("expected_member_count") != len(members):
        raise StageCLocalSealError("expected_member_count does not match expected_members")

    guards = spec.get("guards")
    required = {
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
    }
    if not isinstance(guards, Mapping):
        raise StageCLocalSealError("public-download guards are required")
    for key, value in required.items():
        if guards.get(key) != value:
            raise StageCLocalSealError(f"public-download guard mismatch: {key}")
    return json.loads(json.dumps(spec))

def seal_public_download(*, archive_path: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    active = validate_public_download_spec(spec)
    expected = active["expected_archive"]
    if not archive_path.is_file():
        raise StageCLocalSealError(f"public download not found: {archive_path}")
    if archive_path.name != expected["filename"]:
        raise StageCLocalSealError(f"archive filename mismatch: expected {expected['filename']}, got {archive_path.name}")
    actual_size = archive_path.stat().st_size
    if actual_size != expected["size_bytes"]:
        raise StageCLocalSealError(f"archive size mismatch: expected={expected['size_bytes']}, actual={actual_size}")
    actual_sha = sha256_file(archive_path)
    if actual_sha.lower() != expected["sha256"].lower():
        raise StageCLocalSealError(f"archive SHA-256 mismatch: expected={expected['sha256']}, actual={actual_sha}")

    expected_by_name = {member["name"]: member for member in active["expected_members"]}
    try:
        with zipfile.ZipFile(archive_path, "r", allowZip64=True) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            if len(infos) != expected["expected_member_count"]:
                raise StageCLocalSealError(
                    f"archive member-count mismatch: expected={expected['expected_member_count']}, actual={len(infos)}"
                )
            actual_names = {info.filename for info in infos}
            expected_names = set(expected_by_name)
            missing = sorted(expected_names - actual_names)
            extras = sorted(actual_names - expected_names)
            if missing or extras:
                raise StageCLocalSealError(f"archive member identity mismatch: missing={missing}, extras={extras}")
            bad = archive.testzip()
            if bad is not None:
                raise StageCLocalSealError(f"archive CRC/decompression integrity failure at member: {bad}")

            member_records = []
            for info in sorted(infos, key=lambda x: x.filename):
                expected_member = expected_by_name[info.filename]
                if info.file_size != expected_member["size_bytes"]:
                    raise StageCLocalSealError(
                        f"member size mismatch for {info.filename}: expected={expected_member['size_bytes']}, actual={info.file_size}"
                    )
                member_records.append({
                    "name": info.filename,
                    "kind": expected_member["kind"],
                    "size_bytes": info.file_size,
                    "compressed_size_bytes": info.compress_size,
                    "crc32": f"{info.CRC:08x}",
                    "sha256": sha256_zip_member(archive, info),
                    "compression_method": info.compress_type,
                })
    except zipfile.BadZipFile as exc:
        raise StageCLocalSealError(f"invalid ZIP archive: {exc}") from exc

    return {
        "schema_version": SEAL_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "verification_mode": "PUBLIC_DOWNLOAD_LOCAL_SEAL",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
        "source": {
            "source_id": active["source_id"],
            "doi": active["doi"],
            "version": active["version"],
            "license": active["license"],
            "landing_page": active["landing_page"],
        },
        "archive": {
            "filename": archive_path.name,
            "size_bytes": actual_size,
            "sha256": actual_sha,
            "member_count": len(member_records),
            "crc_integrity": "PASS",
        },
        "members": member_records,
        "member_set_sha256": canonical_hash(member_records),
        "next_gate": "INSPECT_INDEX_AND_NESTED_ARCHIVES_WITHOUT_TRAINING",
    }
