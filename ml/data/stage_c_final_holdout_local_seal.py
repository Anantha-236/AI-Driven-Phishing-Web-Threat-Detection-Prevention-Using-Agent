"""Stage C Task 28 — local integrity seal for CompPhish v3.

Consumes the frozen Task-27 public-availability evidence and verifies the exact
locally downloaded CompPhish v3 files:

  - All_HTML.zip
  - Mapping_File.xlsx

This task performs byte-level integrity work only. It hashes both files,
verifies ZIP/XLSX container integrity, validates safe archive member paths, and
checks that All_HTML.zip contains exactly the expected 15,358 captured .txt
files.

It does not extract Stage-C features, read labels for evaluation, load a model,
score samples, compute metrics, change the threshold, or deploy anything.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any, Mapping
import zipfile

SEAL_SCHEMA = "stage-c-final-holdout-local-integrity-seal-1"

EXPECTED_TASK27_AVAILABILITY_REPORT_SHA256 = (
    "c130c28f3d3678abe2df6e1d56fcb3bd64b3915b8f8ccefaf80b0d4b223ec61c"
)
EXPECTED_TASK27_PUBLIC_EVIDENCE_SHA256 = (
    "d553af085a5bd256b3624b7cdf7ca7e3a9ab128d98a4e158a679cd9d020d488d"
)

EXPECTED_CANDIDATE_ID = "compphish-v3-2026"
EXPECTED_SOURCE_ID = "mendeley-fmbs4kp9wz-v3"
EXPECTED_DOI = "10.17632/fmbs4kp9wz.3"
EXPECTED_LICENSE = "CC BY 4.0"

EXPECTED_HTML_ARCHIVE_NAME = "All_HTML.zip"
EXPECTED_MAPPING_NAME = "Mapping_File.xlsx"
EXPECTED_CAPTURE_COUNT = 15358
EXPECTED_CLASS_COUNTS = {"legitimate": 8154, "phishing": 7204}

XLSX_REQUIRED_MEMBERS = {
    "[Content_Types].xml",
    "_rels/.rels",
    "xl/workbook.xml",
    "xl/_rels/workbook.xml.rels",
}


class StageCFinalHoldoutLocalSealError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_without(value: Mapping[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return canonical_hash(copy)


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFinalHoldoutLocalSealError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFinalHoldoutLocalSealError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCFinalHoldoutLocalSealError(
            f"JSON root must be object: {path}"
        )
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCFinalHoldoutLocalSealError(
                f"refusing to replace non-identical frozen Task-28 output: {path}"
            )
        return "EXISTING_MATCH"
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with tmp.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return "CREATED"


def validate_task27_report(report: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": "stage-c-primary-holdout-availability-evidence-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "primary_candidate_id": EXPECTED_CANDIDATE_ID,
        "primary_source_id": EXPECTED_SOURCE_ID,
        "primary_still_active": True,
        "fallback_activated": False,
        "availability_decision": (
            "PRIMARY_PUBLICLY_AVAILABLE_FOR_MANUAL_ACQUISITION"
        ),
        "public_evidence_sha256": EXPECTED_TASK27_PUBLIC_EVIDENCE_SHA256,
        "remote_inventory_cryptographically_frozen": False,
        "download_manifest_cryptographically_frozen": False,
        "manual_download_required": True,
        "local_integrity_seal_required_before_feature_extraction": True,
        "local_schema_verification_required_before_feature_extraction": True,
        "final_holdout_touched": False,
        "final_holdout_feature_extraction_authorized": False,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_metrics_authorized": False,
        "availability_report_sha256": EXPECTED_TASK27_AVAILABILITY_REPORT_SHA256,
        "next_gate": (
            "MANUALLY_DOWNLOAD_COMPPHISH_V3_AND_FREEZE_LOCAL_INTEGRITY_SEAL"
        ),
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise StageCFinalHoldoutLocalSealError(
                f"Task-27 report guard mismatch: {key}"
            )
    if (
        hash_without(report, "availability_report_sha256")
        != EXPECTED_TASK27_AVAILABILITY_REPORT_SHA256
    ):
        raise StageCFinalHoldoutLocalSealError(
            "Task-27 canonical availability-report hash mismatch"
        )

    evidence = report.get("public_availability_evidence")
    if not isinstance(evidence, Mapping):
        raise StageCFinalHoldoutLocalSealError(
            "Task-27 public evidence missing"
        )
    checks = [
        (evidence.get("doi") == EXPECTED_DOI, "DOI"),
        (evidence.get("license") == EXPECTED_LICENSE, "license"),
        (evidence.get("sample_count") == EXPECTED_CAPTURE_COUNT, "sample count"),
        (
            evidence.get("class_counts") == EXPECTED_CLASS_COUNTS,
            "class counts",
        ),
        (
            evidence.get("raw_html_archive_name")
            == EXPECTED_HTML_ARCHIVE_NAME,
            "HTML archive name",
        ),
        (
            evidence.get("mapping_file_name") == EXPECTED_MAPPING_NAME,
            "mapping file name",
        ),
        (
            evidence.get("download_all_control_visible") is True,
            "download control",
        ),
    ]
    for ok, name in checks:
        if not ok:
            raise StageCFinalHoldoutLocalSealError(
                f"Task-27 evidence changed: {name}"
            )


def _safe_archive_member_name(name: str) -> bool:
    if not name or "\\" in name:
        return False
    p = PurePosixPath(name)
    if p.is_absolute():
        return False
    if any(part in {"", ".", ".."} for part in p.parts):
        return False
    if ":" in p.parts[0]:
        return False
    return True


def _zip_member_inventory(
    archive: zipfile.ZipFile,
    *,
    require_all_txt: bool,
) -> tuple[list[dict[str, Any]], int]:
    infos = [info for info in archive.infolist() if not info.is_dir()]
    records: list[dict[str, Any]] = []
    txt_count = 0
    seen: set[str] = set()

    for info in sorted(infos, key=lambda item: item.filename):
        name = info.filename
        if name in seen:
            raise StageCFinalHoldoutLocalSealError(
                f"duplicate ZIP member name: {name}"
            )
        seen.add(name)
        if not _safe_archive_member_name(name):
            raise StageCFinalHoldoutLocalSealError(
                f"unsafe ZIP member path: {name!r}"
            )
        suffix = PurePosixPath(name).suffix.casefold()
        if suffix == ".txt":
            txt_count += 1
        elif require_all_txt:
            raise StageCFinalHoldoutLocalSealError(
                f"unexpected non-.txt file in HTML archive: {name}"
            )
        records.append({
            "name": name,
            "size_bytes": info.file_size,
            "compressed_size_bytes": info.compress_size,
            "crc32": f"{info.CRC:08x}",
            "compression_method": info.compress_type,
        })
    return records, txt_count


def inspect_html_archive(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFinalHoldoutLocalSealError(
            f"HTML archive not found: {path}"
        )
    if path.name != EXPECTED_HTML_ARCHIVE_NAME:
        raise StageCFinalHoldoutLocalSealError(
            f"HTML archive filename mismatch: expected "
            f"{EXPECTED_HTML_ARCHIVE_NAME}, got {path.name}"
        )

    try:
        with zipfile.ZipFile(path, "r", allowZip64=True) as archive:
            bad = archive.testzip()
            if bad is not None:
                raise StageCFinalHoldoutLocalSealError(
                    f"HTML archive CRC/decompression failure: {bad}"
                )
            members, txt_count = _zip_member_inventory(
                archive,
                require_all_txt=True,
            )
    except zipfile.BadZipFile as exc:
        raise StageCFinalHoldoutLocalSealError(
            f"invalid HTML ZIP archive: {exc}"
        ) from exc

    if txt_count != EXPECTED_CAPTURE_COUNT:
        raise StageCFinalHoldoutLocalSealError(
            f"HTML capture count mismatch: "
            f"expected={EXPECTED_CAPTURE_COUNT}, actual={txt_count}"
        )
    if len(members) != EXPECTED_CAPTURE_COUNT:
        raise StageCFinalHoldoutLocalSealError(
            f"HTML archive file-count mismatch: "
            f"expected={EXPECTED_CAPTURE_COUNT}, actual={len(members)}"
        )

    basenames = [PurePosixPath(row["name"]).name for row in members]
    if len(set(basenames)) != EXPECTED_CAPTURE_COUNT:
        raise StageCFinalHoldoutLocalSealError(
            "HTML capture basenames are not unique"
        )

    return {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "container": "ZIP",
        "crc_integrity": "PASS",
        "file_count": len(members),
        "txt_capture_count": txt_count,
        "capture_basename_unique_count": len(set(basenames)),
        "member_inventory_sha256": canonical_hash(members),
    }


def inspect_mapping_workbook(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFinalHoldoutLocalSealError(
            f"mapping workbook not found: {path}"
        )
    if path.name != EXPECTED_MAPPING_NAME:
        raise StageCFinalHoldoutLocalSealError(
            f"mapping filename mismatch: expected {EXPECTED_MAPPING_NAME}, "
            f"got {path.name}"
        )

    try:
        with zipfile.ZipFile(path, "r", allowZip64=True) as workbook:
            bad = workbook.testzip()
            if bad is not None:
                raise StageCFinalHoldoutLocalSealError(
                    f"XLSX CRC/decompression failure: {bad}"
                )
            members, _ = _zip_member_inventory(
                workbook,
                require_all_txt=False,
            )
            names = {row["name"] for row in members}
    except zipfile.BadZipFile as exc:
        raise StageCFinalHoldoutLocalSealError(
            f"invalid XLSX container: {exc}"
        ) from exc

    missing = sorted(XLSX_REQUIRED_MEMBERS - names)
    if missing:
        raise StageCFinalHoldoutLocalSealError(
            f"XLSX required members missing: {missing}"
        )

    worksheet_members = sorted(
        name
        for name in names
        if name.startswith("xl/worksheets/") and name.endswith(".xml")
    )
    if not worksheet_members:
        raise StageCFinalHoldoutLocalSealError(
            "XLSX contains no worksheet XML"
        )

    return {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "container": "XLSX_ZIP",
        "crc_integrity": "PASS",
        "internal_member_count": len(members),
        "worksheet_count": len(worksheet_members),
        "worksheet_members": worksheet_members,
        "internal_member_inventory_sha256": canonical_hash(members),
        "cell_values_read": False,
        "label_values_read": False,
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_final_holdout_local_seal.py",
        "ml/data/seal_stage_c_final_holdout_download.py",
        "ml/data/stage_c_primary_holdout_availability.py",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCFinalHoldoutLocalSealError(
                "invalid Git HEAD identity"
            )
        for relative in paths:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"],
                cwd=repo_root,
                capture_output=True,
                check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *paths],
            cwd=repo_root,
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCFinalHoldoutLocalSealError(
            "Task-28 and bound files must be committed before local sealing"
        ) from exc
    if dirty != 0:
        raise StageCFinalHoldoutLocalSealError(
            "Task-28/bound files differ from committed HEAD"
        )

    return {
        "git_head": head,
        "task28_module_sha256": sha256_file(repo_root / paths[0]),
        "task28_cli_sha256": sha256_file(repo_root / paths[1]),
        "task27_module_sha256": sha256_file(repo_root / paths[2]),
    }


def seal_final_holdout_download(
    *,
    repo_root: Path,
    task27_report_path: Path,
    html_archive_path: Path,
    mapping_workbook_path: Path,
) -> dict[str, Any]:
    report = load_json(task27_report_path)
    validate_task27_report(report)

    html = inspect_html_archive(html_archive_path)
    mapping = inspect_mapping_workbook(mapping_workbook_path)
    git = _git_provenance(repo_root)

    artifact_identity = {
        "candidate_id": EXPECTED_CANDIDATE_ID,
        "source_id": EXPECTED_SOURCE_ID,
        "doi": EXPECTED_DOI,
        "html_archive": {
            "filename": html["filename"],
            "size_bytes": html["size_bytes"],
            "sha256": html["sha256"],
            "file_count": html["file_count"],
            "member_inventory_sha256": html[
                "member_inventory_sha256"
            ],
        },
        "mapping_workbook": {
            "filename": mapping["filename"],
            "size_bytes": mapping["size_bytes"],
            "sha256": mapping["sha256"],
            "internal_member_inventory_sha256": mapping[
                "internal_member_inventory_sha256"
            ],
        },
    }

    seal = {
        "schema_version": SEAL_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_id": EXPECTED_CANDIDATE_ID,
        "source_id": EXPECTED_SOURCE_ID,
        "doi": EXPECTED_DOI,
        "license": EXPECTED_LICENSE,
        "expected_sample_count": EXPECTED_CAPTURE_COUNT,
        "expected_class_counts": EXPECTED_CLASS_COUNTS,
        "local_artifacts": {
            "html_archive": html,
            "mapping_workbook": mapping,
        },
        "local_artifact_set_sha256": canonical_hash(artifact_identity),
        "local_integrity_seal_complete": True,
        "html_archive_integrity_passed": True,
        "mapping_container_integrity_passed": True,
        "mapping_schema_inspected": False,
        "mapping_labels_accessed": False,
        "html_capture_contents_accessed": False,
        "final_holdout_bytes_accessed_for_integrity": True,
        "final_holdout_touch_scope": "BYTE_AND_CONTAINER_INTEGRITY_ONLY",
        "final_holdout_feature_extraction_authorized": False,
        "final_holdout_model_scoring_authorized": False,
        "final_holdout_metrics_authorized": False,
        "final_holdout_error_analysis_authorized": False,
        "identity_bindings": {
            "task27_availability_report_sha256": (
                EXPECTED_TASK27_AVAILABILITY_REPORT_SHA256
            ),
            "task27_public_evidence_sha256": (
                EXPECTED_TASK27_PUBLIC_EVIDENCE_SHA256
            ),
            **git,
        },
        "prohibitions": {
            "mapping_label_use_before_schema_gate": True,
            "html_content_feature_extraction": True,
            "model_scoring": True,
            "metric_computation": True,
            "error_analysis": True,
            "threshold_change": True,
            "model_refit": True,
            "deployment": True,
        },
        "next_gate": (
            "INSPECT_COMPPHISH_MAPPING_SCHEMA_AND_BUILD_FINAL_HOLDOUT_"
            "IDENTITY_INDEX_WITHOUT_MODEL_SCORING"
        ),
    }
    seal["local_integrity_seal_sha256"] = canonical_hash(seal)
    return seal
