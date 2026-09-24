"""Stage B local snapshot ingestion with provenance and privacy-safe URL metadata.

The ingester operates on files already downloaded by the researcher. It does not
fetch remote feeds, execute websites, or promote popularity rankings to benign
ground truth. Raw URL identity is used transiently to compute fingerprints; the
persisted records contain a redacted URL and hashes rather than query values.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import csv
import hashlib
from pathlib import Path
import posixpath
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .stage_b_manifest import ManifestValidationError, validate_source_manifest


BATCH_SCHEMA = "stage-b-ingestion-batch-1"
RECORD_SCHEMA = "stage-b-ingested-url-1"
SUPPORTED_ADAPTERS = {"phishtank_csv", "openphish_text", "tranco_csv"}


class IngestionError(ValueError):
    """Raised when a local source snapshot cannot be safely ingested."""


@dataclass(frozen=True)
class CanonicalUrl:
    canonical_url: str
    redacted_url: str
    origin: str
    hostname: str
    url_sha256: str
    origin_path_sha256: str


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    had_trailing_slash = path.endswith("/")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if normalized == "//":
        normalized = "/"
    if had_trailing_slash and normalized != "/":
        normalized += "/"
    return normalized


def canonicalize_url(raw_url: str) -> CanonicalUrl:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise IngestionError("URL is empty")
    if any(ord(ch) < 32 for ch in raw_url):
        raise IngestionError("URL contains control characters")

    parsed = urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise IngestionError("Only http(s) URLs are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise IngestionError("Credential-bearing URLs are rejected")
    if not parsed.hostname:
        raise IngestionError("URL hostname is required")

    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise IngestionError("URL hostname is not valid IDNA") from exc
    if not hostname:
        raise IngestionError("URL hostname is required")

    try:
        port = parsed.port
    except ValueError as exc:
        raise IngestionError("URL port is invalid") from exc

    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    origin = f"{scheme}://{netloc}"
    path = _normalize_path(parsed.path)

    canonical_url = urlunsplit((scheme, netloc, path, parsed.query, ""))
    redacted_query = ""
    if parsed.query:
        try:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
            redacted_query = urlencode([(key, "*") for key, _value in pairs], doseq=True)
        except ValueError:
            redacted_query = "query=%2A"
    redacted_url = urlunsplit((scheme, netloc, path, redacted_query, ""))

    return CanonicalUrl(
        canonical_url=canonical_url,
        redacted_url=redacted_url,
        origin=origin,
        hostname=hostname,
        url_sha256=_sha256_text(canonical_url),
        origin_path_sha256=_sha256_text(urlunsplit((scheme, netloc, path, "", ""))),
    )


def _normalized_brand(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.strip().lower().split())
    return text or None


def _base_record(
    manifest: Mapping[str, Any],
    canonical: CanonicalUrl,
    *,
    source_record_id: str,
    observed_at: str,
    ground_truth: int | None,
    label_status: str,
    brand_group: str | None = None,
    rank: int | None = None,
) -> dict[str, Any]:
    source = manifest["source"]
    record = {
        "schema_version": RECORD_SCHEMA,
        "sample_id": f"{manifest['dataset_id']}:{source_record_id}",
        "dataset_id": manifest["dataset_id"],
        "source_record_id": source_record_id,
        "source_group": source["independence_group"],
        "source_artifact_sha256": source["content_sha256"],
        "ground_truth": ground_truth,
        "label_status": label_status,
        "label_source": manifest["labeling"]["label_source"] if ground_truth is not None else None,
        "observed_at": observed_at,
        "hostname": canonical.hostname,
        "origin": canonical.origin,
        "domain_group": canonical.hostname,
        "brand_group": brand_group,
        "url_sha256": canonical.url_sha256,
        "origin_path_sha256": canonical.origin_path_sha256,
        "redacted_url": canonical.redacted_url,
        "redistribution_allowed": bool(source["license"]["redistributable"]),
        "local_only": not bool(source["license"]["redistributable"]),
    }
    if rank is not None:
        record["rank"] = rank
    return record


def _new_stats() -> dict[str, Any]:
    return {
        "input_records": 0,
        "accepted_records": 0,
        "duplicate_records": 0,
        "rejected_records": 0,
        "rejection_reasons": {},
    }


def _finalize_stats(stats: dict[str, Any], rejection_counter: Counter[str]) -> None:
    stats["rejection_reasons"] = dict(sorted(rejection_counter.items()))


def _dedupe_append(records: list[dict[str, Any]], seen: set[str], record: dict[str, Any], stats: dict[str, Any]) -> None:
    fingerprint = record["url_sha256"]
    if fingerprint in seen:
        stats["duplicate_records"] += 1
        return
    seen.add(fingerprint)
    records.append(record)
    stats["accepted_records"] += 1


def _ingest_phishtank(manifest: Mapping[str, Any], source_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    stats = _new_stats()
    rejected: Counter[str] = Counter()

    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"phish_id", "url", "verified", "verification_time", "online", "target"}
        if not reader.fieldnames or required - set(reader.fieldnames):
            raise IngestionError("PhishTank CSV columns are incomplete")
        for row in reader:
            stats["input_records"] += 1
            if row.get("verified", "").strip().lower() not in {"yes", "true", "y", "1"} or row.get("online", "").strip().lower() not in {"yes", "true", "y", "1"}:
                stats["rejected_records"] += 1
                rejected["not_verified_online"] += 1
                continue
            try:
                canonical = canonicalize_url(row.get("url", ""))
            except IngestionError:
                stats["rejected_records"] += 1
                rejected["invalid_url"] += 1
                continue
            observed_at = row.get("verification_time", "").strip() or manifest["source"]["retrieved_at"]
            record = _base_record(
                manifest,
                canonical,
                source_record_id=row.get("phish_id", "").strip() or canonical.url_sha256,
                observed_at=observed_at,
                ground_truth=1,
                label_status="VERIFIED_SOURCE_LABEL",
                brand_group=_normalized_brand(row.get("target")),
            )
            _dedupe_append(records, seen, record, stats)
    _finalize_stats(stats, rejected)
    return records, stats


def _ingest_openphish(manifest: Mapping[str, Any], source_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    stats = _new_stats()
    rejected: Counter[str] = Counter()

    for raw in source_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line:
            continue
        stats["input_records"] += 1
        try:
            canonical = canonicalize_url(line)
        except IngestionError:
            stats["rejected_records"] += 1
            rejected["invalid_url"] += 1
            continue
        record = _base_record(
            manifest,
            canonical,
            source_record_id=canonical.url_sha256,
            observed_at=manifest["source"]["retrieved_at"],
            ground_truth=1,
            label_status="VERIFIED_SOURCE_LABEL",
        )
        _dedupe_append(records, seen, record, stats)
    _finalize_stats(stats, rejected)
    return records, stats


def _ingest_tranco(manifest: Mapping[str, Any], source_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    stats = _new_stats()
    rejected: Counter[str] = Counter()

    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row:
                continue
            stats["input_records"] += 1
            if len(row) < 2:
                stats["rejected_records"] += 1
                rejected["invalid_row"] += 1
                continue
            try:
                rank = int(row[0])
                canonical = canonicalize_url(f"https://{row[1].strip()}/")
            except (ValueError, IngestionError):
                stats["rejected_records"] += 1
                rejected["invalid_row"] += 1
                continue
            record = _base_record(
                manifest,
                canonical,
                source_record_id=f"rank-{rank}",
                observed_at=manifest["source"]["retrieved_at"],
                ground_truth=None,
                label_status="UNLABELED_CANDIDATE",
                rank=rank,
            )
            _dedupe_append(records, seen, record, stats)
    _finalize_stats(stats, rejected)
    return records, stats


def ingest_source(
    source_manifest: Mapping[str, Any],
    source_path: str | Path,
    *,
    adapter: str,
) -> dict[str, Any]:
    try:
        manifest = validate_source_manifest(source_manifest)
    except ManifestValidationError as exc:
        raise IngestionError(str(exc)) from exc

    if adapter not in SUPPORTED_ADAPTERS:
        raise IngestionError(f"Unsupported Stage B adapter: {adapter}")

    path = Path(source_path)
    if not path.is_file():
        raise IngestionError(f"Source snapshot not found: {path}")
    actual_hash = sha256_file(path)
    if actual_hash != manifest["source"]["content_sha256"]:
        raise IngestionError("Source content SHA-256 does not match manifest")

    provider = manifest["source"]["provider"].lower()
    if adapter == "phishtank_csv":
        if "phishtank" not in provider:
            raise IngestionError("phishtank_csv adapter requires a PhishTank source manifest")
        records, stats = _ingest_phishtank(manifest, path)
    elif adapter == "openphish_text":
        if "openphish" not in provider:
            raise IngestionError("openphish_text adapter requires an OpenPhish source manifest")
        records, stats = _ingest_openphish(manifest, path)
    else:
        if "tranco" not in provider:
            raise IngestionError("tranco_csv adapter requires a Tranco source manifest")
        records, stats = _ingest_tranco(manifest, path)

    return {
        "schema_version": BATCH_SCHEMA,
        "dataset_id": manifest["dataset_id"],
        "adapter": adapter,
        "source_artifact": {
            "path_name": path.name,
            "sha256": actual_hash,
            "provider": manifest["source"]["provider"],
            "retrieved_at": manifest["source"]["retrieved_at"],
            "independence_group": manifest["source"]["independence_group"],
        },
        "stats": stats,
        "records": records,
        "limitations": [
            "URL labels come only from the declared source authority; model predictions never become labels.",
            "Persisted URLs redact query values; exact URL identity is represented by SHA-256.",
            "domain_group is host-level at ingestion and must be upgraded to registrable-domain grouping before final split construction.",
            "Tranco records are candidate legitimate sites, not legitimate ground truth.",
        ],
    }


def merge_ingestion_batches(batches: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    all_records: list[dict[str, Any]] = []
    by_url: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_origin_path: dict[str, set[str]] = defaultdict(set)

    for batch in batches:
        if batch.get("schema_version") != BATCH_SCHEMA:
            raise IngestionError("Unsupported ingestion batch schema")
        for raw in batch.get("records", []):
            record = dict(raw)
            all_records.append(record)
            by_url[record["url_sha256"]].append(record)
            by_origin_path[record["origin_path_sha256"]].add(record["url_sha256"])

    conflicts = []
    for url_hash, rows in by_url.items():
        verified_labels = {
            row.get("ground_truth")
            for row in rows
            if row.get("label_status") == "VERIFIED_SOURCE_LABEL" and row.get("ground_truth") in (0, 1)
        }
        if verified_labels == {0, 1}:
            conflicts.append({
                "url_sha256": url_hash,
                "datasets": sorted({row["dataset_id"] for row in rows}),
                "labels": [0, 1],
            })

    unique_records = []
    for url_hash in sorted(by_url):
        rows = by_url[url_hash]
        # Keep all provenance for conflicts; otherwise retain one representative
        # while recording source membership in the merged view.
        representative = dict(rows[0])
        representative["source_datasets"] = sorted({row["dataset_id"] for row in rows})
        unique_records.append(representative)

    origin_path_collisions = sum(1 for hashes in by_origin_path.values() if len(hashes) > 1)
    return {
        "schema_version": "stage-b-ingestion-merge-1",
        "stats": {
            "input_records": len(all_records),
            "unique_exact_urls": len(by_url),
            "origin_path_collisions": origin_path_collisions,
            "label_conflicts": len(conflicts),
        },
        "conflicts": conflicts,
        "records": unique_records,
    }
