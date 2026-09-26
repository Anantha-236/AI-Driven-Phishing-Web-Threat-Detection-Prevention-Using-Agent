"""Stage B Task 20: selected-shard extraction and scaled candidate assembly.

Consumes a PASS Task-19 temporal coverage plan plus the exact remote ZIP
central-directory shard index. This task never downloads network content.

Pipeline:
1. locate only finalized ZIPs selected by Task 19;
2. verify every ZIP against its plan-pinned MD5;
3. extract HTML/HTM members only, restricted to IDs assigned to that exact
   shard by the verified central-directory index;
4. require exact per-shard record-ID reconciliation;
5. adapt extracted records against the original metadata CSVs;
6. quarantine duplicate HTML artifacts before supervised splitting;
7. build + validate a normalized archive replay candidate;
8. run the existing strict-forward, artifact/domain/brand-isolated research splitter;
9. require resulting partition class counts to meet checked-in readiness minima;
10. copy only supervised records to a compact replay archive and create a
    normalized supervised replay plan.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Iterable, Mapping
import zipfile

from .stage_b_archive_replay import MAX_HTML_BYTES, validate_archive_replay_plan
from .stage_b_research_splitting import PARTITIONS, construct_research_archive_splits
from .stage_b_zenodo8041387 import (
    ARCHIVE_PLAN_SCHEMA,
    DATASET_ID,
    PROVIDER,
    SOURCE_GROUP,
    SOURCE_REFERENCE,
    AdaptedRecord,
    Zenodo8041387AdapterError,
    adapt_class,
    canonical_json_hash,
    load_brand_aliases,
    sha256_file,
)

COVERAGE_PLAN_SCHEMA = "stage-b-temporal-coverage-plan-1"
SHARD_INDEX_SCHEMA = "stage-b-zenodo-shard-index-1"
READINESS_POLICY_SCHEMA = "stage-b-readiness-policy-1"
ASSEMBLY_REPORT_SCHEMA = "stage-b-scaled-candidate-assembly-1"
OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
HTML_SUFFIXES = {".html", ".htm"}


class ScaledAssemblyError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ScaledAssemblyError(f"required JSON file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScaledAssemblyError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ScaledAssemblyError(f"JSON root must be an object: {path}")
    return data


def _atomic_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def safe_member_path(name: str) -> PurePosixPath | None:
    if not isinstance(name, str):
        return None
    cleaned = name.replace("\\", "/").strip()
    if not cleaned or cleaned.endswith("/"):
        return None
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        return None
    path = PurePosixPath(cleaned)
    if any(part in ("", ".", "..") for part in path.parts):
        return None
    return path


def _record_id_from_member(path: PurePosixPath) -> str | None:
    ids = [part.lower() for part in path.parts if OBJECT_ID_RE.fullmatch(part)]
    return ids[0] if len(ids) == 1 else None


def validate_inputs(
    coverage_plan: Mapping[str, Any],
    shard_index: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if coverage_plan.get("schema_version") != COVERAGE_PLAN_SCHEMA:
        raise ScaledAssemblyError("unsupported Task 19 coverage-plan schema")
    if coverage_plan.get("status") != "PASS":
        raise ScaledAssemblyError("Task 19 coverage plan is not PASS")
    if coverage_plan.get("deployment_authorized") is not False:
        raise ScaledAssemblyError("Task 19 plan must remain non-deployable research evidence")

    selected = coverage_plan.get("selected_shards")
    if not isinstance(selected, list) or not selected:
        raise ScaledAssemblyError("coverage plan selected_shards must be a non-empty list")

    if shard_index.get("schema_version") != SHARD_INDEX_SCHEMA:
        raise ScaledAssemblyError("unsupported Task 19 shard-index schema")
    if shard_index.get("status") != "PASS":
        raise ScaledAssemblyError("Task 19 shard index is not PASS")
    if shard_index.get("archive_body_downloaded") is not False:
        raise ScaledAssemblyError("shard index must declare archive_body_downloaded=false")

    by_name: dict[str, dict[str, Any]] = {}
    for entry in shard_index.get("shards", []):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("name"), str):
            raise ScaledAssemblyError("invalid shard-index entry")
        by_name[str(entry["name"])] = dict(entry)

    seen = set()
    normalized_selected = []
    for row in selected:
        if not isinstance(row, Mapping):
            raise ScaledAssemblyError("invalid selected-shard entry")
        name = row.get("name")
        klass = row.get("class")
        md5 = row.get("md5")
        if not isinstance(name, str) or not name.endswith(".zip"):
            raise ScaledAssemblyError("selected shard requires .zip name")
        if name in seen:
            raise ScaledAssemblyError(f"duplicate selected shard: {name}")
        seen.add(name)
        if klass not in ("phishing", "legitimate"):
            raise ScaledAssemblyError(f"invalid selected shard class for {name}")
        if not isinstance(md5, str) or not re.fullmatch(r"[0-9a-f]{32}", md5):
            raise ScaledAssemblyError(f"invalid selected shard MD5 for {name}")
        indexed = by_name.get(name)
        if indexed is None:
            raise ScaledAssemblyError(f"selected shard absent from exact index: {name}")
        if indexed.get("class") != klass or indexed.get("md5") != md5:
            raise ScaledAssemblyError(f"Task19 plan/index identity mismatch for {name}")
        ids = indexed.get("record_ids")
        if not isinstance(ids, list) or not ids:
            raise ScaledAssemblyError(f"indexed record IDs missing for {name}")
        normalized_selected.append(dict(row))

    return normalized_selected, by_name


def locate_finalized_shards(
    selected: Iterable[Mapping[str, Any]],
    download_roots: Iterable[Path],
) -> dict[str, Path]:
    roots = [Path(root) for root in download_roots]
    if not roots:
        raise ScaledAssemblyError("at least one download root is required")
    result: dict[str, Path] = {}
    for row in selected:
        name = str(row["name"])
        matches = [root / name for root in roots if (root / name).is_file()]
        if len(matches) > 1:
            matches.sort(key=lambda p: str(p.resolve()))
        if not matches:
            partials = [root / f"{name}.part" for root in roots if (root / f"{name}.part").is_file()]
            detail = f"; partial={partials[0]}" if partials else ""
            raise ScaledAssemblyError(f"selected shard is not finalized: {name}{detail}")
        result[name] = matches[0]
    return result


def input_preflight(
    selected: Iterable[Mapping[str, Any]],
    download_roots: Iterable[Path],
) -> dict[str, Any]:
    roots = [Path(root) for root in download_roots]
    rows = []
    ready = 0
    for row in selected:
        name = str(row["name"])
        final = next((root / name for root in roots if (root / name).is_file()), None)
        part = next((root / f"{name}.part" for root in roots if (root / f"{name}.part").is_file()), None)
        state = "READY" if final else ("DOWNLOADING" if part else "MISSING")
        if final:
            ready += 1
        rows.append({
            "name": name,
            "class": row["class"],
            "state": state,
            "final_path": str(final) if final else None,
            "partial_path": str(part) if part else None,
            "partial_bytes": part.stat().st_size if part else 0,
        })
    return {
        "status": "PASS" if ready == len(rows) else "WAITING",
        "selected_shards": len(rows),
        "ready_shards": ready,
        "pending_shards": len(rows) - ready,
        "shards": rows,
    }


def _verify_archive(path: Path, expected_md5: str) -> dict[str, Any]:
    actual = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            actual.update(chunk)
    digest = actual.hexdigest()
    if digest != expected_md5:
        raise ScaledAssemblyError(
            f"MD5 mismatch for {path.name}: expected={expected_md5}, actual={digest}"
        )
    return {"path": str(path), "bytes": path.stat().st_size, "md5": digest}


def _expected_ids(index_entry: Mapping[str, Any]) -> set[str]:
    raw = index_entry.get("record_ids")
    if not isinstance(raw, list) or not raw:
        raise ScaledAssemblyError("shard-index record_ids are required")
    values = {str(value).lower() for value in raw}
    if len(values) != len(raw) or any(not OBJECT_ID_RE.fullmatch(value) for value in values):
        raise ScaledAssemblyError("invalid/duplicate record IDs in shard index")
    return values


def _discovered_record_ids(destination: Path) -> set[str]:
    result = set()
    if not destination.is_dir():
        return result
    for path in destination.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in HTML_SUFFIXES:
            continue
        try:
            relative = PurePosixPath(path.relative_to(destination).as_posix())
        except ValueError:
            continue
        record_id = _record_id_from_member(relative)
        if record_id:
            result.add(record_id)
    return result


def extract_shard_html_exact(
    zip_path: Path,
    destination: Path,
    *,
    expected_ids: set[str],
    expected_md5: str,
) -> dict[str, Any]:
    verified = _verify_archive(zip_path, expected_md5)
    marker = destination / ".stage-b-task20-extraction.json"
    identity = {
        "archive_name": zip_path.name,
        "archive_md5": expected_md5,
        "expected_record_ids_sha256": _canonical_hash(sorted(expected_ids)),
    }

    if marker.is_file():
        try:
            prior = json.loads(marker.read_text(encoding="utf-8"))
        except Exception:
            prior = {}
        actual_ids = _discovered_record_ids(destination)
        prior_quarantined = {
            str(value).lower()
            for value in prior.get("missing_html_capture_record_ids", [])
            if isinstance(value, str)
        }
        if (
            prior.get("status") == "PASS"
            and prior.get("identity") == identity
            and actual_ids.isdisjoint(prior_quarantined)
            and actual_ids | prior_quarantined == expected_ids
        ):
            return {**prior, "status": "PASS", "reused": True, "archive": verified}

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    html_extracted = 0
    skipped_bad_path = 0
    skipped_non_html = 0
    skipped_unindexed_record = 0
    skipped_duplicate_path = 0
    skipped_read_error = 0
    seen_targets: set[str] = set()
    archive_html_expected_ids: set[str] = set()

    try:
        archive = zipfile.ZipFile(zip_path, "r", allowZip64=True)
    except Exception as exc:
        raise ScaledAssemblyError(f"cannot open ZIP {zip_path.name}: {exc}") from exc

    with archive:
        try:
            members = archive.infolist()
        except Exception as exc:
            raise ScaledAssemblyError(f"cannot enumerate ZIP {zip_path.name}: {exc}") from exc

        for info in members:
            raw_name = getattr(info, "filename", "")
            raw_cleaned = raw_name.replace("\\", "/") if isinstance(raw_name, str) else ""
            raw_path = PurePosixPath(raw_cleaned) if raw_cleaned else None
            raw_ids = (
                [
                    part.lower()
                    for part in raw_path.parts
                    if OBJECT_ID_RE.fullmatch(part)
                ]
                if raw_path is not None
                else []
            )
            if (
                raw_path is not None
                and raw_path.suffix.lower() in HTML_SUFFIXES
                and len(raw_ids) == 1
                and raw_ids[0] in expected_ids
            ):
                archive_html_expected_ids.add(raw_ids[0])

            safe = safe_member_path(raw_name)
            if safe is None:
                skipped_bad_path += 1
                continue
            if safe.suffix.lower() not in HTML_SUFFIXES:
                skipped_non_html += 1
                continue
            record_id = _record_id_from_member(safe)
            if record_id is None or record_id not in expected_ids:
                skipped_unindexed_record += 1
                continue

            relative = Path(*safe.parts)
            key = relative.as_posix().lower()
            if key in seen_targets:
                skipped_duplicate_path += 1
                continue
            target = destination / relative
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)
            except Exception:
                skipped_read_error += 1
                try:
                    target.unlink(missing_ok=True)
                except Exception:
                    pass
                continue
            seen_targets.add(key)
            html_extracted += 1

    actual_ids = _discovered_record_ids(destination)
    missing_all = expected_ids - actual_ids
    missing_with_html = sorted(missing_all & archive_html_expected_ids)
    missing_no_html = sorted(missing_all - archive_html_expected_ids)
    extras = sorted(actual_ids - expected_ids)

    # Indexed source records can legitimately contain assets/screenshots/metadata
    # without an archived HTML capture. Those records are unusable for browser
    # replay, so quarantine them explicitly instead of failing the whole shard.
    #
    # Fail closed if HTML DID exist but safe extraction did not produce it,
    # when an unexpected record appears, or on an expected HTML read error.
    if extras or missing_with_html or skipped_read_error:
        raise ScaledAssemblyError(
            f"HTML extraction/record-ID reconciliation failed for {zip_path.name}: "
            f"expected={len(expected_ids)}, actual={len(actual_ids)}, "
            f"missing_with_html={len(missing_with_html)}, "
            f"missing_without_html={len(missing_no_html)}, "
            f"extras={len(extras)}, read_errors={skipped_read_error}"
        )

    report = {
        "status": "PASS",
        "reused": False,
        "identity": identity,
        "archive": verified,
        "archive_member_count": len(members),
        "expected_record_ids": len(expected_ids),
        "reconciled_record_ids": len(actual_ids),
        "html_extracted": html_extracted,
        "missing_html_capture_count": len(missing_no_html),
        "missing_html_capture_record_ids": missing_no_html,
        "source_record_quarantine": [
            {
                "record_id": record_id,
                "reason": "MISSING_HTML_CAPTURE",
            }
            for record_id in missing_no_html
        ],
        "skipped_bad_name_or_path": skipped_bad_path,
        "skipped_non_html": skipped_non_html,
        "skipped_unindexed_record": skipped_unindexed_record,
        "skipped_duplicate_html_path": skipped_duplicate_path,
        "skipped_html_read_error": skipped_read_error,
    }
    _atomic_json(marker, report)
    return report


def extract_selected_shards(
    selected: list[Mapping[str, Any]],
    index_by_name: Mapping[str, Mapping[str, Any]],
    zip_paths: Mapping[str, Path],
    extraction_root: Path,
) -> list[dict[str, Any]]:
    reports = []
    for row in sorted(selected, key=lambda x: (str(x["class"]), str(x["name"]))):
        name = str(row["name"])
        klass = str(row["class"])
        destination = extraction_root / klass / name[:-4]
        report = extract_shard_html_exact(
            zip_paths[name],
            destination,
            expected_ids=_expected_ids(index_by_name[name]),
            expected_md5=str(row["md5"]),
        )
        reports.append({
            "name": name,
            "class": klass,
            "destination": str(destination),
            **report,
        })
    return reports


def quarantine_oversized_artifacts(
    phishing: list[AdaptedRecord],
    legitimate: list[AdaptedRecord],
    *,
    max_html_bytes: int = MAX_HTML_BYTES,
) -> tuple[list[AdaptedRecord], list[AdaptedRecord], list[dict[str, Any]]]:
    if type(max_html_bytes) is not int or max_html_bytes < 1:
        raise ScaledAssemblyError("max_html_bytes must be a positive integer")

    retained_phishing: list[AdaptedRecord] = []
    retained_legitimate: list[AdaptedRecord] = []
    quarantined: list[dict[str, Any]] = []

    for klass, records, retained in (
        ("phishing", phishing, retained_phishing),
        ("legitimate", legitimate, retained_legitimate),
    ):
        for record in records:
            try:
                size = record.source_path.stat().st_size
            except OSError as exc:
                raise ScaledAssemblyError(
                    f"cannot stat adapted HTML for {klass}:{record.sample_number}: {exc}"
                ) from exc

            # Preserve the global archive-replay validator's empty-file and
            # other integrity checks. Task 20 only quarantines positive-size
            # captures that exceed the existing hard replay ceiling.
            if size > max_html_bytes:
                quarantined.append({
                    "class": klass,
                    "record_id": str(record.sample_number),
                    "sample_id": f"{DATASET_ID}:{klass}:{record.sample_number}",
                    "artifact_sha256": record.artifact_sha256,
                    "html_bytes": size,
                    "max_html_bytes": max_html_bytes,
                    "reason": "OVERSIZED_HTML_CAPTURE",
                })
                continue

            retained.append(record)

    quarantined.sort(key=lambda row: row["sample_id"])
    return retained_phishing, retained_legitimate, quarantined


def quarantine_duplicate_artifacts(
    phishing: list[AdaptedRecord],
    legitimate: list[AdaptedRecord],
) -> tuple[list[AdaptedRecord], list[AdaptedRecord], list[dict[str, Any]]]:
    grouped: dict[str, list[tuple[str, AdaptedRecord]]] = defaultdict(list)
    for klass, records in (("phishing", phishing), ("legitimate", legitimate)):
        for record in records:
            grouped[record.artifact_sha256].append((klass, record))

    blocked_hashes = {digest for digest, rows in grouped.items() if len(rows) > 1}
    quarantined = []
    for digest in sorted(blocked_hashes):
        rows = grouped[digest]
        quarantined.append({
            "artifact_sha256": digest,
            "sample_ids": sorted(
                f"{DATASET_ID}:{klass}:{record.sample_number}"
                for klass, record in rows
            ),
            "labels": sorted({record.ground_truth for _, record in rows}),
            "reason": "DUPLICATE_HTML_ARTIFACT",
        })

    return (
        [record for record in phishing if record.artifact_sha256 not in blocked_hashes],
        [record for record in legitimate if record.artifact_sha256 not in blocked_hashes],
        quarantined,
    )


def build_candidate_raw_plan(
    phishing: list[AdaptedRecord],
    legitimate: list[AdaptedRecord],
    *,
    extraction_root: Path,
    metadata_hashes: Mapping[str, str],
    coverage_plan_sha256: str,
    shard_index_sha256: str,
    wait_ms: int,
    license_reference: str,
    created_at: str,
) -> dict[str, Any]:
    if not 250 <= wait_ms <= 10_000:
        raise ScaledAssemblyError("wait_ms must be between 250 and 10000")

    rows = [("phishing", r) for r in phishing] + [("legitimate", r) for r in legitimate]
    rows.sort(key=lambda pair: (pair[0], str(pair[1].sample_number)))

    items = []
    artifact_identity = []
    extraction_resolved = extraction_root.resolve(strict=True)
    for klass, record in rows:
        try:
            relative = record.source_path.resolve(strict=True).relative_to(extraction_resolved)
        except ValueError as exc:
            raise ScaledAssemblyError("adapted HTML path escapes extraction root") from exc
        sample_id = f"{DATASET_ID}:{klass}:{record.sample_number}"
        items.append({
            "sample_id": sample_id,
            "html_path": relative.as_posix(),
            "ground_truth": record.ground_truth,
            "observed_at": record.observed_at,
            "artifact_sha256": record.artifact_sha256,
            "domain_group": record.domain_group,
            "brand_group": record.brand_group,
            "source_group": SOURCE_GROUP,
            "wait_ms": wait_ms,
        })
        artifact_identity.append({"sample_id": sample_id, "artifact_sha256": record.artifact_sha256})

    if not items:
        raise ScaledAssemblyError("scaled candidate has no records")

    snapshot = canonical_json_hash({
        "coverage_plan_sha256": coverage_plan_sha256,
        "shard_index_sha256": shard_index_sha256,
        "metadata_hashes": dict(sorted(metadata_hashes.items())),
        "artifacts": artifact_identity,
        "source_reference": SOURCE_REFERENCE,
    })
    return {
        "schema_version": ARCHIVE_PLAN_SCHEMA,
        "plan_id": f"{DATASET_ID}-scale-{snapshot[:12]}",
        "created_at": created_at,
        "dataset": {
            "dataset_id": DATASET_ID,
            "provider": PROVIDER,
            "source_reference": SOURCE_REFERENCE,
            "source_snapshot_sha256": snapshot,
            "independence_group": SOURCE_GROUP,
            "license_reference": license_reference,
            "research_use_allowed": True,
        },
        "items": items,
    }


def split_count_readiness(
    splits: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    if policy.get("schema_version") != READINESS_POLICY_SCHEMA:
        raise ScaledAssemblyError("unsupported readiness policy schema")
    minima = policy.get("min_samples_per_class")
    if not isinstance(minima, Mapping) or set(minima) != set(PARTITIONS):
        raise ScaledAssemblyError("readiness policy requires minima for all four partitions")

    issues = []
    counts = {}
    partitions = splits.get("partitions")
    if not isinstance(partitions, Mapping):
        raise ScaledAssemblyError("research split artifact requires partitions")
    for name in PARTITIONS:
        payload = partitions.get(name)
        if not isinstance(payload, Mapping):
            raise ScaledAssemblyError(f"missing split partition: {name}")
        legit = int(payload.get("legitimate", 0))
        phish = int(payload.get("phishing", 0))
        minimum = minima.get(name)
        if type(minimum) is not int or minimum < 1:
            raise ScaledAssemblyError(f"invalid readiness minimum for {name}")
        counts[name] = {"legitimate": legit, "phishing": phish, "required_per_class": minimum}
        for klass, observed in (("legitimate", legit), ("phishing", phish)):
            if observed < minimum:
                issues.append({
                    "partition": name,
                    "class": klass,
                    "observed": observed,
                    "required": minimum,
                })
    return {"status": "PASS" if not issues else "FAIL", "counts": counts, "issues": issues}


def build_supervised_replay_plan(
    normalized_candidate: Mapping[str, Any],
    splits: Mapping[str, Any],
    *,
    extraction_root: Path,
    supervised_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    supervised_ids = {
        str(row["sample_id"])
        for name in PARTITIONS
        for row in splits["partitions"][name]["records"]
    }
    item_by_id = {str(item["sample_id"]): dict(item) for item in normalized_candidate["items"]}
    missing = sorted(supervised_ids - set(item_by_id))
    if missing:
        raise ScaledAssemblyError(f"split references missing candidate samples: {missing[:3]}")

    if supervised_root.exists():
        shutil.rmtree(supervised_root)
    supervised_root.mkdir(parents=True, exist_ok=True)

    items = []
    copied_bytes = 0
    for sample_id in sorted(supervised_ids):
        item = item_by_id[sample_id]
        source = extraction_root / Path(*PurePosixPath(item["html_path"]).parts)
        if not source.is_file():
            raise ScaledAssemblyError(f"supervised source HTML missing: {sample_id}")
        klass = "phishing" if item["ground_truth"] == 1 else "legitimate"
        record_token = sample_id.rsplit(":", 1)[-1]
        relative = Path(klass) / f"{record_token}.html"
        destination = supervised_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        actual = sha256_file(destination)
        if actual != item["artifact_sha256"]:
            raise ScaledAssemblyError(f"supervised copy hash mismatch: {sample_id}")
        copied_bytes += destination.stat().st_size
        items.append({
            "sample_id": sample_id,
            "html_path": relative.as_posix(),
            "ground_truth": item["ground_truth"],
            "observed_at": item["observed_at"],
            "artifact_sha256": item["artifact_sha256"],
            "domain_group": item["domain_group"],
            "brand_group": item["brand_group"],
            "source_group": item["source_group"],
            "wait_ms": item["wait_ms"],
        })

    raw = {
        "schema_version": ARCHIVE_PLAN_SCHEMA,
        "plan_id": f"{normalized_candidate['plan_id']}-supervised",
        "created_at": normalized_candidate["created_at"],
        "dataset": dict(normalized_candidate["dataset"]),
        "items": items,
    }
    return raw, {
        "supervised_samples": len(items),
        "copied_bytes": copied_bytes,
        "excluded_candidate_samples": len(normalized_candidate["items"]) - len(items),
    }


def assemble_scaled_candidate(
    *,
    coverage_plan_path: Path,
    shard_index_path: Path,
    phishing_csv: Path,
    legitimate_csv: Path,
    brands_csv: Path | None,
    download_roots: list[Path],
    extraction_root: Path,
    output_root: Path,
    split_contract_path: Path,
    readiness_policy_path: Path,
    wait_ms: int,
    license_reference: str,
) -> dict[str, Any]:
    coverage_plan = _load(coverage_plan_path)
    shard_index = _load(shard_index_path)
    selected, index_by_name = validate_inputs(coverage_plan, shard_index)
    zip_paths = locate_finalized_shards(selected, download_roots)

    if output_root.exists() and (output_root / "scaled-assembly-report.json").exists():
        raise ScaledAssemblyError(
            "output-root already contains a frozen Task 20 report; choose a new output-root"
        )
    output_root.mkdir(parents=True, exist_ok=True)

    extraction_reports = extract_selected_shards(selected, index_by_name, zip_paths, extraction_root)

    brands = load_brand_aliases(brands_csv)
    try:
        phishing, phishing_report = adapt_class(
            extraction_root / "phishing", phishing_csv, label=1, brand_aliases=brands
        )
        legitimate, legitimate_report = adapt_class(
            extraction_root / "legitimate", legitimate_csv, label=0, brand_aliases=brands
        )
    except Zenodo8041387AdapterError as exc:
        raise ScaledAssemblyError(str(exc)) from exc

    phishing, legitimate, oversized_quarantine = quarantine_oversized_artifacts(
        phishing, legitimate
    )

    phishing, legitimate, duplicate_quarantine = quarantine_duplicate_artifacts(
        phishing, legitimate
    )

    metadata_hashes = {
        "phishing.csv": sha256_file(phishing_csv),
        "not-phishing.csv": sha256_file(legitimate_csv),
    }
    if brands_csv:
        metadata_hashes["brands.csv"] = sha256_file(brands_csv)

    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw_candidate = build_candidate_raw_plan(
        phishing,
        legitimate,
        extraction_root=extraction_root,
        metadata_hashes=metadata_hashes,
        coverage_plan_sha256=sha256_file(coverage_plan_path),
        shard_index_sha256=sha256_file(shard_index_path),
        wait_ms=wait_ms,
        license_reference=license_reference,
        created_at=created_at,
    )
    candidate_raw_path = output_root / "scaled-candidate-plan.json"
    candidate_normalized_path = output_root / "scaled-candidate-plan.normalized.json"
    _atomic_json(candidate_raw_path, raw_candidate)
    normalized_candidate = validate_archive_replay_plan(raw_candidate, extraction_root)
    _atomic_json(candidate_normalized_path, normalized_candidate)

    splits = construct_research_archive_splits(
        normalized_candidate, _load(split_contract_path)
    )
    splits_path = output_root / "research-splits.json"
    _atomic_json(splits_path, splits)

    count_readiness = split_count_readiness(splits, _load(readiness_policy_path))
    count_readiness_path = output_root / "split-count-readiness.json"
    _atomic_json(count_readiness_path, count_readiness)

    missing_html_quarantine = [
        {
            "class": row["class"],
            "shard": row["name"],
            "record_id": record_id,
            "reason": "MISSING_HTML_CAPTURE",
        }
        for row in extraction_reports
        for record_id in row.get("missing_html_capture_record_ids", [])
    ]

    source_quarantine_records = [
        *missing_html_quarantine,
        *oversized_quarantine,
    ]

    report = {
        "schema_version": ASSEMBLY_REPORT_SCHEMA,
        "status": "PASS" if count_readiness["status"] == "PASS" else "INSUFFICIENT_SCALE",
        "research_only": True,
        "deployment_authorized": False,
        "selected_shards": len(selected),
        "extraction": extraction_reports,
        "adaptation": {
            "phishing": phishing_report,
            "legitimate": legitimate_report,
            "post_duplicate_quarantine": {
                "phishing": len(phishing),
                "legitimate": len(legitimate),
            },
        },
        "source_record_quarantine": {
            "missing_html_capture_samples": len(missing_html_quarantine),
            "oversized_html_capture_samples": len(oversized_quarantine),
            "total_samples": len(source_quarantine_records),
            "max_html_bytes": MAX_HTML_BYTES,
            "records": source_quarantine_records,
        },
        "duplicate_artifact_quarantine": {
            "groups": len(duplicate_quarantine),
            "samples": sum(len(row["sample_ids"]) for row in duplicate_quarantine),
            "records": duplicate_quarantine,
        },
        "candidate_samples": len(normalized_candidate["items"]),
        "split_partitions": {
            name: {
                "total": splits["partitions"][name]["sample_count"],
                "legitimate": splits["partitions"][name]["legitimate"],
                "phishing": splits["partitions"][name]["phishing"],
            }
            for name in PARTITIONS
        },
        "chronology_bridge_quarantine_samples": splits["audit"]["chronology_bridge_sample_count"],
        "split_count_readiness": count_readiness,
        "outputs": {
            "candidate_raw_plan": str(candidate_raw_path),
            "candidate_normalized_plan": str(candidate_normalized_path),
            "research_splits": str(splits_path),
            "split_count_readiness": str(count_readiness_path),
        },
        "limitations": [
            "Task 20 uses one archived source dataset and remains research-only.",
            "Passing count minima does not establish statistical adequacy or deployment readiness.",
            "Only exact HTML artifacts from Task-19-selected shards are assembled; live network/server context is not reproduced.",
        ],
    }

    if count_readiness["status"] == "PASS":
        supervised_root = output_root / "supervised-archive"
        supervised_raw, supervised_copy = build_supervised_replay_plan(
            normalized_candidate,
            splits,
            extraction_root=extraction_root,
            supervised_root=supervised_root,
        )
        supervised_raw_path = output_root / "supervised-replay-plan.json"
        supervised_normalized_path = output_root / "supervised-replay-plan.normalized.json"
        _atomic_json(supervised_raw_path, supervised_raw)
        supervised_normalized = validate_archive_replay_plan(supervised_raw, supervised_root)
        _atomic_json(supervised_normalized_path, supervised_normalized)
        report["supervised"] = supervised_copy
        report["outputs"].update({
            "supervised_archive_root": str(supervised_root),
            "supervised_raw_plan": str(supervised_raw_path),
            "supervised_normalized_plan": str(supervised_normalized_path),
        })

    report_path = output_root / "scaled-assembly-report.json"
    report["outputs"]["report"] = str(report_path)
    _atomic_json(report_path, report)
    return report
