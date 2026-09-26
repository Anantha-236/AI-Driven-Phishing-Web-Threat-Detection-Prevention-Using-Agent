
"""Stage C Task 6 — deterministic development record index.

Builds a frozen, research-only mapping from the authoritative 80k metadata rows
to their exact HTML members inside the sealed Mendeley development archive.

Safety / protocol properties:
- development corpus only
- no extraction to disk
- no feature selection, training, calibration, thresholding, or scoring
- no final-holdout access
- archive-only HTML extras are quarantined and never labeled
- canonical HTML SHA-256 is computed for artifact grouping in later split tasks
"""
from __future__ import annotations

from collections import Counter, defaultdict
from io import BytesIO
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
import zipfile

from .stage_c_corpus_inspection import (
    StageCCorpusInspectionError,
    _canonical_index_rows,
    inspect_index_sql,
    load_json,
)

INDEX_SCHEMA = "stage-c-development-record-index-1"
REPORT_SCHEMA = "stage-c-development-record-index-report-1"
QUARANTINE_SCHEMA = "stage-c-development-extra-html-quarantine-1"
MAX_NESTED_ZIP_BYTES = 512 * 1024 * 1024

class StageCDevelopmentIndexError(ValueError):
    pass

def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

def file_sha256(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def frozen_write_json(path: Path, value: Any) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageCDevelopmentIndexError(
                f"existing frozen output is unreadable: {path}: {exc}"
            ) from exc
        if current != value:
            raise StageCDevelopmentIndexError(
                f"refusing to replace non-identical frozen output: {path}"
            )
        return "EXISTING_MATCH"
    path.write_text(rendered, encoding="utf-8")
    return "CREATED"

def _require_task4_seal(seal: Mapping[str, Any]) -> None:
    required = {
        "schema_version": "stage-c-public-download-local-seal-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "verification_mode": "PUBLIC_DOWNLOAD_LOCAL_SEAL",
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
    }
    for key, expected in required.items():
        if seal.get(key) != expected:
            raise StageCDevelopmentIndexError(f"Task-4 seal guard mismatch: {key}")

def _require_task5_report(report: Mapping[str, Any]) -> None:
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

    reconciliation = report.get("reconciliation")
    if not isinstance(reconciliation, Mapping):
        raise StageCDevelopmentIndexError("Task-5 reconciliation missing")

    exact = {
        "metadata_rows": 80000,
        "metadata_unique_rec_ids": 80000,
        "metadata_duplicate_rec_ids": 0,
        "metadata_unique_website_filenames": 80000,
        "metadata_duplicate_website_references": 0,
        "metadata_missing_html_count": 0,
        "published_expected_records": 80000,
        "metadata_rows_equal_published_expected": True,
    }
    for key, expected in exact.items():
        if reconciliation.get(key) != expected:
            raise StageCDevelopmentIndexError(
                f"Task-5 reconciliation not authoritative for Task 6: {key}"
            )

    if reconciliation.get("class_counts") != {"0": 50000, "1": 30000}:
        raise StageCDevelopmentIndexError("Task-5 class counts differ from 50k/30k contract")

def _sealed_member_hashes(seal: Mapping[str, Any]) -> dict[str, str]:
    values = {}
    for row in seal.get("members", []):
        if not isinstance(row, Mapping):
            continue
        name = row.get("name")
        digest = row.get("sha256")
        if isinstance(name, str) and isinstance(digest, str):
            values[name] = digest.lower()
    return values

def _validate_archive_identity(archive_path: Path, seal: Mapping[str, Any]) -> None:
    if not archive_path.is_file():
        raise StageCDevelopmentIndexError(f"development archive not found: {archive_path}")
    archive = seal.get("archive")
    if not isinstance(archive, Mapping):
        raise StageCDevelopmentIndexError("Task-4 archive identity missing")
    if archive_path.name != archive.get("filename"):
        raise StageCDevelopmentIndexError("development archive filename differs from Task-4 seal")
    if archive_path.stat().st_size != archive.get("size_bytes"):
        raise StageCDevelopmentIndexError("development archive size differs from Task-4 seal")
    expected = str(archive.get("sha256", "")).lower()
    actual = file_sha256(archive_path)
    if actual != expected:
        raise StageCDevelopmentIndexError(
            f"development archive SHA256 mismatch: expected={expected} actual={actual}"
        )

def _sample_id(rec_id: int) -> str:
    return f"mendeley-n96ncsr5g4-v1:{rec_id:06d}"

def _read_metadata_rows(
    outer: zipfile.ZipFile,
    *,
    expected_member_hashes: Mapping[str, str],
    expected_count: int,
) -> tuple[str, list[dict[str, Any]], str]:
    infos = [
        info for info in outer.infolist()
        if not info.is_dir() and PurePosixPath(info.filename).name == "index.sql"
    ]
    if len(infos) != 1:
        raise StageCDevelopmentIndexError(
            f"expected exactly one index.sql, found {len(infos)}"
        )
    info = infos[0]
    payload = outer.read(info)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_member_hashes.get(info.filename):
        raise StageCDevelopmentIndexError("index.sql hash differs from Task-4 seal")

    parsed = inspect_index_sql(payload)
    rows = _canonical_index_rows(parsed)
    if len(rows) != expected_count:
        raise StageCDevelopmentIndexError(
            f"canonical metadata row count differs from frozen Task-5 count "
            f"{expected_count}: {len(rows)}"
        )
    return info.filename, rows, digest

def _build_html_locator(
    outer: zipfile.ZipFile,
    *,
    expected_member_hashes: Mapping[str, str],
) -> tuple[
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    locators: dict[str, dict[str, Any]] = {}
    all_html: dict[str, tuple[str, str]] = {}
    nested_summaries: list[dict[str, Any]] = []

    nested_infos = sorted(
        [
            info for info in outer.infolist()
            if not info.is_dir()
            and PurePosixPath(info.filename).suffix.casefold() == ".zip"
        ],
        key=lambda x: x.filename,
    )
    if len(nested_infos) != 8:
        raise StageCDevelopmentIndexError(
            f"expected 8 nested development archives, found {len(nested_infos)}"
        )

    for outer_info in nested_infos:
        if outer_info.file_size > MAX_NESTED_ZIP_BYTES:
            raise StageCDevelopmentIndexError(
                f"nested archive exceeds Task-6 memory bound: {outer_info.filename}"
            )
        payload = outer.read(outer_info)
        nested_sha = hashlib.sha256(payload).hexdigest()
        expected = expected_member_hashes.get(outer_info.filename)
        if nested_sha != expected:
            raise StageCDevelopmentIndexError(
                f"nested ZIP hash differs from Task-4 seal: {outer_info.filename}"
            )

        with zipfile.ZipFile(BytesIO(payload), "r", allowZip64=True) as nested:
            bad = nested.testzip()
            if bad is not None:
                raise StageCDevelopmentIndexError(
                    f"nested ZIP CRC/decompression failure: {outer_info.filename}: {bad}"
                )
            html_infos = [
                info for info in nested.infolist()
                if not info.is_dir()
                and PurePosixPath(info.filename).suffix.casefold() in {".html", ".htm"}
            ]

            per_archive_seen = set()
            oversized = 0
            for info in html_infos:
                basename = PurePosixPath(info.filename).name
                if basename in per_archive_seen:
                    raise StageCDevelopmentIndexError(
                        f"duplicate HTML basename inside nested archive: "
                        f"{outer_info.filename}: {basename}"
                    )
                per_archive_seen.add(basename)

                if basename in all_html:
                    first_archive, first_member = all_html[basename]
                    raise StageCDevelopmentIndexError(
                        "duplicate HTML basename across nested archives: "
                        f"{basename}: {first_archive}/{first_member} vs "
                        f"{outer_info.filename}/{info.filename}"
                    )
                all_html[basename] = (outer_info.filename, info.filename)
                if info.file_size > 12 * 1024 * 1024:
                    oversized += 1

            nested_summaries.append({
                "nested_archive": outer_info.filename,
                "nested_archive_sha256": nested_sha,
                "html_members": len(html_infos),
                "oversized_html_members_over_12_mib": oversized,
            })

    summary = {
        "nested_archive_count": len(nested_summaries),
        "html_basename_count": len(all_html),
        "nested_archives": nested_summaries,
    }
    return locators, [
        {"basename": name, "nested_archive": a, "member_name": m}
        for name, (a, m) in all_html.items()
    ], summary

def build_development_record_index(
    *,
    archive_path: Path,
    seal: Mapping[str, Any],
    inspection: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _require_task4_seal(seal)
    _require_task5_report(inspection)
    _validate_archive_identity(archive_path, seal)

    expected_hashes = _sealed_member_hashes(seal)

    try:
        with zipfile.ZipFile(archive_path, "r", allowZip64=True) as outer:
            expected_count = int(inspection["reconciliation"]["metadata_rows"])
            index_member, metadata_rows, index_sha = _read_metadata_rows(
                outer,
                expected_member_hashes=expected_hashes,
                expected_count=expected_count,
            )

            # Build a basename -> nested member locator without extracting anything.
            nested_infos = sorted(
                [
                    info for info in outer.infolist()
                    if not info.is_dir()
                    and PurePosixPath(info.filename).suffix.casefold() == ".zip"
                ],
                key=lambda x: x.filename,
            )
            if len(nested_infos) != 8:
                raise StageCDevelopmentIndexError(
                    f"expected 8 nested development archives, found {len(nested_infos)}"
                )

            html_locator: dict[str, tuple[str, str, int, int]] = {}
            nested_summary = []

            for outer_info in nested_infos:
                payload = outer.read(outer_info)
                digest = hashlib.sha256(payload).hexdigest()
                if digest != expected_hashes.get(outer_info.filename):
                    raise StageCDevelopmentIndexError(
                        f"nested ZIP hash differs from Task-4 seal: {outer_info.filename}"
                    )
                with zipfile.ZipFile(BytesIO(payload), "r", allowZip64=True) as nested:
                    bad = nested.testzip()
                    if bad is not None:
                        raise StageCDevelopmentIndexError(
                            f"nested ZIP CRC/decompression failure: {outer_info.filename}: {bad}"
                        )
                    html_infos = [
                        x for x in nested.infolist()
                        if not x.is_dir()
                        and PurePosixPath(x.filename).suffix.casefold() in {".html", ".htm"}
                    ]
                    oversized = 0
                    for info in html_infos:
                        basename = PurePosixPath(info.filename).name
                        if basename in html_locator:
                            raise StageCDevelopmentIndexError(
                                f"duplicate HTML basename across nested archives: {basename}"
                            )
                        html_locator[basename] = (
                            outer_info.filename,
                            info.filename,
                            info.file_size,
                            info.CRC,
                        )
                        if info.file_size > 12 * 1024 * 1024:
                            oversized += 1
                    nested_summary.append({
                        "nested_archive": outer_info.filename,
                        "nested_archive_sha256": digest,
                        "html_members": len(html_infos),
                        "oversized_html_members_over_12_mib": oversized,
                    })

            canonical_websites = {str(row["website"]) for row in metadata_rows}
            if len(canonical_websites) != expected_count:
                raise StageCDevelopmentIndexError(
                    f"canonical website identity count differs from frozen Task-5 count "
                    f"{expected_count}: {len(canonical_websites)}"
                )
            missing = canonical_websites - set(html_locator)
            if missing:
                raise StageCDevelopmentIndexError(
                    f"Task-6 mapping has missing HTML despite Task-5 PASS: {len(missing)}"
                )

            extras = sorted(set(html_locator) - canonical_websites)
            if len(extras) != inspection["reconciliation"]["archive_extra_html_count"]:
                raise StageCDevelopmentIndexError(
                    "archive-only HTML count differs from frozen Task-5 report"
                )

            # Hash canonical HTML. Open each nested ZIP once and resolve all rows assigned to it.
            metadata_by_archive: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in metadata_rows:
                website = str(row["website"])
                nested_archive, member_name, file_size, crc = html_locator[website]
                metadata_by_archive[nested_archive].append({
                    "metadata": row,
                    "member_name": member_name,
                    "file_size": file_size,
                    "crc32": crc,
                })

            records: list[dict[str, Any]] = []
            artifact_hash_to_samples: dict[str, list[tuple[str, int]]] = defaultdict(list)
            oversized_canonical = 0

            nested_outer_by_name = {
                info.filename: info
                for info in nested_infos
            }
            for nested_archive in sorted(metadata_by_archive):
                outer_info = nested_outer_by_name[nested_archive]
                payload = outer.read(outer_info)
                digest = hashlib.sha256(payload).hexdigest()
                if digest != expected_hashes.get(nested_archive):
                    raise StageCDevelopmentIndexError(
                        f"nested ZIP hash changed between Task-6 passes: {nested_archive}"
                    )
                with zipfile.ZipFile(BytesIO(payload), "r", allowZip64=True) as nested:
                    for item in metadata_by_archive[nested_archive]:
                        row = item["metadata"]
                        member_name = item["member_name"]
                        with nested.open(member_name, "r") as fh:
                            h = hashlib.sha256()
                            while True:
                                chunk = fh.read(1024 * 1024)
                                if not chunk:
                                    break
                                h.update(chunk)
                        html_sha = h.hexdigest()

                        rec_id = int(row["rec_id"])
                        label = int(row["result"])
                        if label not in {0, 1}:
                            raise StageCDevelopmentIndexError(
                                f"unsupported class label for rec_id {rec_id}: {label}"
                            )
                        sample_id = _sample_id(rec_id)
                        record = {
                            "sample_id": sample_id,
                            "rec_id": rec_id,
                            "url": str(row["url"]),
                            "website": str(row["website"]),
                            "label": label,
                            "created_date": str(row["created_date"]),
                            "nested_archive": nested_archive,
                            "member_name": member_name,
                            "html_size_bytes": int(item["file_size"]),
                            "html_crc32": f"{int(item['crc32']) & 0xffffffff:08x}",
                            "html_sha256": html_sha,
                            "oversized_over_12_mib": int(item["file_size"]) > 12 * 1024 * 1024,
                        }
                        if record["oversized_over_12_mib"]:
                            oversized_canonical += 1
                        records.append(record)
                        artifact_hash_to_samples[html_sha].append((sample_id, label))
                del payload

            records.sort(key=lambda x: x["rec_id"])

            rec_ids = [x["rec_id"] for x in records]
            expected_rec_ids = list(range(1, expected_count + 1))
            rec_id_contiguous_1_to_expected = rec_ids == expected_rec_ids

            duplicate_groups = {
                digest: members
                for digest, members in artifact_hash_to_samples.items()
                if len(members) > 1
            }
            duplicate_samples = sum(len(x) for x in duplicate_groups.values())
            cross_label_groups = [
                (digest, members)
                for digest, members in duplicate_groups.items()
                if len({label for _, label in members}) > 1
            ]
            cross_label_samples = sum(len(members) for _, members in cross_label_groups)

            labels = Counter(x["label"] for x in records)
            times = sorted(x["created_date"] for x in records)

            index_payload = {
                "schema_version": INDEX_SCHEMA,
                "status": "PASS",
                "stage": "C",
                "role": "DEVELOPMENT",
                "research_only": True,
                "deployment_authorized": False,
                "model_training_authorized": False,
                "feature_extraction_authorized": False,
                "final_holdout_touched": False,
                "source": {
                    "doi": seal["source"]["doi"],
                    "version": seal["source"]["version"],
                    "archive_sha256": seal["archive"]["sha256"],
                    "task4_member_set_sha256": seal["member_set_sha256"],
                    "task5_inspection_evidence_sha256": inspection["inspection_evidence_sha256"],
                    "index_sql_member": index_member,
                    "index_sql_sha256": index_sha,
                },
                "record_count": len(records),
                "class_counts": {
                    "legitimate": labels[0],
                    "phishing": labels[1],
                },
                "records": records,
            }
            index_payload["record_set_sha256"] = canonical_hash(records)

            extra_entries = []
            for basename in extras:
                nested_archive, member_name, file_size, crc = html_locator[basename]
                extra_entries.append({
                    "nested_archive": nested_archive,
                    "member_name": member_name,
                    "basename_sha256": hashlib.sha256(basename.encode("utf-8")).hexdigest(),
                    "html_size_bytes": int(file_size),
                    "html_crc32": f"{int(crc) & 0xffffffff:08x}",
                    "reason": "ARCHIVE_HTML_WITHOUT_METADATA_ROW",
                    "supervised_label_assigned": False,
                })
            extra_entries.sort(key=lambda x: (x["nested_archive"], x["member_name"]))
            quarantine = {
                "schema_version": QUARANTINE_SCHEMA,
                "status": "PASS",
                "stage": "C",
                "role": "DEVELOPMENT",
                "reason": "ARCHIVE_ONLY_HTML_NOT_IN_CANONICAL_METADATA",
                "supervised_use_authorized": False,
                "count": len(extra_entries),
                "entries": extra_entries,
            }
            quarantine["entry_set_sha256"] = canonical_hash(extra_entries)

            duplicate_group_count = len(duplicate_groups)
            report = {
                "schema_version": REPORT_SCHEMA,
                "status": "PASS",
                "stage": "C",
                "role": "DEVELOPMENT",
                "research_only": True,
                "deployment_authorized": False,
                "model_training_authorized": False,
                "feature_extraction_authorized": False,
                "final_holdout_touched": False,
                "record_count": len(records),
                "class_counts": {
                    "legitimate": labels[0],
                    "phishing": labels[1],
                },
                "created_date_min": times[0] if times else None,
                "created_date_max": times[-1] if times else None,
                "rec_id_contiguous_1_to_expected": rec_id_contiguous_1_to_expected,
                "unique_website_count": len({x["website"] for x in records}),
                "unique_artifact_sha256_count": len(artifact_hash_to_samples),
                "duplicate_artifact_groups": duplicate_group_count,
                "duplicate_artifact_samples": duplicate_samples,
                "cross_label_duplicate_artifact_groups": len(cross_label_groups),
                "cross_label_duplicate_artifact_samples": cross_label_samples,
                "canonical_oversized_html_over_12_mib": oversized_canonical,
                "archive_extra_html_quarantine_count": len(extra_entries),
                "archive_extra_html_expected_from_task5": inspection["reconciliation"]["archive_extra_html_count"],
                "nested_archives": nested_summary,
                "record_set_sha256": index_payload["record_set_sha256"],
                "extra_quarantine_set_sha256": quarantine["entry_set_sha256"],
                "next_gate": "AUDIT_DEVELOPMENT_DUPLICATES_AND_SPLIT_FEASIBILITY",
            }
            report["index_evidence_sha256"] = canonical_hash(report)

            return index_payload, quarantine, report

    except zipfile.BadZipFile as exc:
        raise StageCDevelopmentIndexError(f"invalid development archive: {exc}") from exc
