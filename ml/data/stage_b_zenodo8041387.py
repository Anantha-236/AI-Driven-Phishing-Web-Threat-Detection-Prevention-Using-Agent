"""Adapter for the Putra Phishing Website Dataset (Zenodo 8041387).

The adapter operates only on files already downloaded and extracted by the user.
It never visits an archived source URL. Raw source URLs are used transiently
only to derive a conservative domain group and are not persisted to Task-16
replay-plan artifacts.

CSV columns are resolved from a closed alias set or explicit CLI overrides.
Missing or ambiguous required metadata fails closed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
import sys
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

DATASET_ID = "zenodo-8041387"
SOURCE_REFERENCE = "https://doi.org/10.5281/zenodo.8041387"
SOURCE_GROUP = "zenodo-8041387-putra-2023"
PROVIDER = "Putra, I Kadek Agus Ariesta / Zenodo"
ARCHIVE_PLAN_SCHEMA = "stage-b-archive-replay-plan-1"

ID_ALIASES = (
    "_id", "id", "record_id", "sample_id", "website_id", "site_id",
    "index", "idx", "no", "number", "websiteid", "siteid",
)
URL_ALIASES = (
    "domain", "url", "website", "website_url", "site_url", "host",
    "hostname", "source_url", "websiteurl",
)
DATE_ALIASES = (
    "scan_date", "discovered_at", "discovery_date", "date", "discovered",
    "created_at", "created", "timestamp", "datetime", "first_seen",
    "firstseen", "collected_at",
)
BRAND_ALIASES = (
    "brands", "target_brand", "brand", "target", "brand_id", "brand_identifier",
    "targetbrand", "identifier",
)
OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
HTML_SUFFIXES = {".html", ".htm"}
HTML_PRIORITY = (
    "index.html", "index.htm", "page.html", "page.htm",
    "source.html", "source.htm", "website.html", "website.htm",
)
COMMON_CC_SECOND_LEVEL = {
    "ac", "co", "com", "edu", "gov", "net", "org", "ne", "or",
}
MAX_BRAND_SHARE_DEFAULT = 0.25


class Zenodo8041387AdapterError(ValueError):
    """Raised when real archive metadata cannot be adapted without guessing."""


@dataclass(frozen=True)
class ColumnMap:
    id: str
    url: str
    date: str
    brand: str | None


@dataclass(frozen=True)
class HtmlCandidate:
    source_path: Path
    source_relative: str
    sample_number: int | str
    sha256: str
    size: int


@dataclass(frozen=True)
class AdaptedRecord:
    sample_number: int | str
    source_path: Path
    ground_truth: int
    observed_at: str
    domain_group: str
    brand_group: str
    artifact_sha256: str


def canonical_json_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def _column_lookup(headers: Iterable[str]) -> dict[str, list[str]]:
    lookup: dict[str, list[str]] = defaultdict(list)
    for header in headers:
        lookup[normalize_column(header)].append(header)
    return lookup


def _resolve_one(
    headers: list[str],
    aliases: Iterable[str],
    *,
    explicit: str | None,
    field: str,
    required: bool,
) -> str | None:
    if explicit:
        if explicit not in headers:
            raise Zenodo8041387AdapterError(
                f"explicit {field} column {explicit!r} is absent; available columns: {headers}"
            )
        return explicit
    lookup = _column_lookup(headers)
    # Alias order expresses source-specific preference. This matters for the
    # real CSV, which contains both `domain` and `url`.
    for alias in aliases:
        matches = list(dict.fromkeys(lookup.get(normalize_column(alias), [])))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise Zenodo8041387AdapterError(
                f"multiple equivalent {field} columns {matches}; pass an explicit override"
            )
    if required:
        raise Zenodo8041387AdapterError(
            f"could not resolve required {field} column; available columns: {headers}"
        )
    return None


def _configure_csv_field_limit() -> int:
    """Raise csv parser per-field limit safely across platforms."""
    limit = sys.maxsize
    while limit > 131072:
        try:
            csv.field_size_limit(limit)
            return limit
        except OverflowError:
            limit //= 10
    csv.field_size_limit(131072)
    return 131072


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        raise Zenodo8041387AdapterError(f"metadata CSV not found: {path}")
    _configure_csv_field_limit()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise Zenodo8041387AdapterError(f"metadata CSV has no header: {path}")
        headers = [str(value) for value in reader.fieldnames]
        rows = [
            {str(key): ("" if value is None else str(value).strip()) for key, value in row.items()}
            for row in reader
        ]
    if not rows:
        raise Zenodo8041387AdapterError(f"metadata CSV has no rows: {path}")
    return headers, rows


def resolve_columns(
    headers: list[str],
    *,
    label: int,
    id_column: str | None = None,
    url_column: str | None = None,
    date_column: str | None = None,
    brand_column: str | None = None,
) -> ColumnMap:
    return ColumnMap(
        id=_resolve_one(headers, ID_ALIASES, explicit=id_column, field="ID", required=True),
        url=_resolve_one(headers, URL_ALIASES, explicit=url_column, field="URL/domain", required=True),
        date=_resolve_one(headers, DATE_ALIASES, explicit=date_column, field="date", required=True),
        brand=_resolve_one(
            headers,
            BRAND_ALIASES,
            explicit=brand_column,
            field="target brand",
            required=(label == 1),
        ),
    )


def normalize_record_key(value: str) -> int | str:
    text = value.strip().strip("\"'")
    if OBJECT_ID_RE.fullmatch(text):
        return text.lower()
    return parse_sample_number(text)


def _record_key_from_html_path(root: Path, path: Path) -> int | str:
    relative = path.relative_to(root)
    object_ids = [part.lower() for part in relative.parts if OBJECT_ID_RE.fullmatch(part)]
    if len(object_ids) == 1:
        return object_ids[0]
    if len(object_ids) > 1:
        raise Zenodo8041387AdapterError(
            f"multiple 24-hex record IDs in archived HTML path: {relative.as_posix()}"
        )
    # Backwards-compatible fallback for synthetic numeric layouts.
    return infer_html_sample_number(root, path)


def _record_token(value: int | str) -> str:
    return f"{value:06d}" if isinstance(value, int) else str(value)


def parse_sample_number(value: str) -> int:
    text = value.strip()
    if re.fullmatch(r"\d+", text):
        number = int(text)
        if number > 0:
            return number
    match = re.search(r"(?<!\d)(\d{1,7})(?!\d)", text)
    if not match or int(match.group(1)) <= 0:
        raise Zenodo8041387AdapterError(f"cannot parse positive sample number from {value!r}")
    return int(match.group(1))


def parse_observed_at(value: str) -> str:
    text = value.strip()
    if not text:
        raise Zenodo8041387AdapterError("empty discovery/observation date")
    if re.fullmatch(r"\d{10}(?:\.\d+)?", text):
        dt = datetime.fromtimestamp(float(text), tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    attempts = (
        None,
        "%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y",
        "%m/%d/%Y", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S",
    )
    for fmt in attempts:
        try:
            if fmt is None:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise Zenodo8041387AdapterError(f"unsupported discovery date {value!r}")


def hostname_from_source(value: str) -> str:
    text = value.strip()
    if not text:
        raise Zenodo8041387AdapterError("empty URL/domain metadata")
    parsed = urlsplit(text if "://" in text else f"//{text}", scheme="https")
    host = (parsed.hostname or "").strip(".").lower()
    if not host:
        raise Zenodo8041387AdapterError(f"cannot derive hostname from metadata {value!r}")
    return host


def conservative_domain_group(value: str) -> str:
    host = hostname_from_source(value)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in COMMON_CC_SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        raise Zenodo8041387AdapterError("target brand is empty")
    return slug


def load_brand_aliases(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    headers, rows = read_csv(path)
    norm = {normalize_column(header): header for header in headers}
    identifier_col = norm.get("identifier")
    name_col = norm.get("name")
    if not identifier_col or not name_col:
        raise Zenodo8041387AdapterError("brands.csv must contain identifier and name columns")
    aliases: dict[str, str] = {}
    for row in rows:
        identifier = row.get(identifier_col, "").strip()
        name = row.get(name_col, "").strip()
        if not identifier:
            continue
        canonical = brand_slug(identifier)
        aliases[brand_slug(identifier)] = canonical
        if name:
            aliases[brand_slug(name)] = canonical
    return aliases


def canonical_brand(value: str, aliases: Mapping[str, str]) -> str:
    key = brand_slug(value)
    return aliases.get(key, key)


def _infer_range_start(root: Path) -> tuple[int | None, int | None]:
    for part in reversed(root.parts):
        match = re.search(r"(\d{4})-(\d{4})", part)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return start, end
    return None, None


def _numeric_tokens(relative: Path) -> list[int]:
    tokens: list[int] = []
    for part in relative.parts:
        for match in re.finditer(r"(?<!\d)(\d{1,7})(?!\d)", part):
            value = int(match.group(1))
            if value > 0:
                tokens.append(value)
    return tokens


def infer_html_sample_number(root: Path, path: Path) -> int:
    relative = path.relative_to(root)
    tokens = _numeric_tokens(relative)
    if not tokens:
        raise Zenodo8041387AdapterError(
            f"cannot infer sample number from archived HTML path: {relative.as_posix()}"
        )
    number = tokens[0]
    start, end = _infer_range_start(root)
    if start is not None and end is not None:
        width = end - start + 1
        if 1 <= number <= width and not (start <= number <= end):
            number = start + number - 1
    return number


def _html_score(path: Path) -> tuple[int, int, str]:
    name = path.name.lower()
    try:
        priority = HTML_PRIORITY.index(name)
    except ValueError:
        priority = len(HTML_PRIORITY)
    return priority, -path.stat().st_size, path.as_posix().lower()


def discover_html(root: Path) -> dict[int | str, HtmlCandidate]:
    if not root.is_dir():
        raise Zenodo8041387AdapterError(f"extracted archive root not found: {root}")
    grouped: dict[int | str, list[Path]] = defaultdict(list)
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink() and path.suffix.lower() in HTML_SUFFIXES:
            try:
                record_key = _record_key_from_html_path(root, path)
            except Zenodo8041387AdapterError:
                continue
            grouped[record_key].append(path)
    if not grouped:
        raise Zenodo8041387AdapterError(f"no .html/.htm captures found below {root}")

    result: dict[int | str, HtmlCandidate] = {}
    for record_key, candidates in grouped.items():
        ordered = sorted(candidates, key=_html_score)
        best = ordered[0]
        # Multiple HTML documents may exist inside one website capture. The
        # 24-hex archive directory is the record identity, so collapse them.
        result[record_key] = HtmlCandidate(
            source_path=best,
            source_relative=best.relative_to(root).as_posix(),
            sample_number=record_key,
            sha256=sha256_file(best),
            size=best.stat().st_size,
        )
    return result


def metadata_index(
    csv_path: Path,
    *,
    label: int,
    id_column: str | None = None,
    url_column: str | None = None,
    date_column: str | None = None,
    brand_column: str | None = None,
) -> tuple[ColumnMap, dict[int, dict[str, str]], list[str]]:
    headers, rows = read_csv(csv_path)
    columns = resolve_columns(
        headers,
        label=label,
        id_column=id_column,
        url_column=url_column,
        date_column=date_column,
        brand_column=brand_column,
    )
    index: dict[int | str, dict[str, str]] = {}
    duplicates: list[int | str] = []
    for row in rows:
        raw_id = row.get(columns.id, "")
        if not raw_id:
            continue
        try:
            record_key = normalize_record_key(raw_id)
        except Zenodo8041387AdapterError:
            continue
        if record_key in index:
            duplicates.append(record_key)
            continue
        index[record_key] = row
    if duplicates:
        raise Zenodo8041387AdapterError(
            f"metadata contains duplicate sample IDs; first duplicate: {duplicates[0]}"
        )
    if not index:
        raise Zenodo8041387AdapterError(
            f"no sample IDs could be indexed from column {columns.id!r}"
        )
    return columns, index, headers


def adapt_class(
    archive_root: Path,
    metadata_csv: Path,
    *,
    label: int,
    brand_aliases: Mapping[str, str],
    id_column: str | None = None,
    url_column: str | None = None,
    date_column: str | None = None,
    brand_column: str | None = None,
) -> tuple[list[AdaptedRecord], dict[str, Any]]:
    html = discover_html(archive_root)
    columns, meta, headers = metadata_index(
        metadata_csv,
        label=label,
        id_column=id_column,
        url_column=url_column,
        date_column=date_column,
        brand_column=brand_column,
    )
    records: list[AdaptedRecord] = []
    rejected: Counter[str] = Counter()
    for record_key, candidate in sorted(html.items(), key=lambda item: str(item[0])):
        row = meta.get(record_key)
        if row is None:
            rejected["metadata_missing"] += 1
            continue
        try:
            observed_at = parse_observed_at(row.get(columns.date, ""))
            domain_group = conservative_domain_group(row.get(columns.url, ""))
            if label == 1:
                if not columns.brand:
                    raise Zenodo8041387AdapterError("phishing target-brand column is required")
                brand_group = canonical_brand(row.get(columns.brand, ""), brand_aliases)
            else:
                brand_group = domain_group
        except Zenodo8041387AdapterError:
            rejected["invalid_required_metadata"] += 1
            continue
        records.append(AdaptedRecord(
            sample_number=record_key,
            source_path=candidate.source_path,
            ground_truth=label,
            observed_at=observed_at,
            domain_group=domain_group,
            brand_group=brand_group,
            artifact_sha256=candidate.sha256,
        ))
    if not records:
        raise Zenodo8041387AdapterError(
            f"no usable {'phishing' if label else 'legitimate'} archive records"
        )
    return records, {
        "archive_html_candidates": len(html),
        "archive_record_ids_detected": len(html),
        "matched_metadata_records": len(records),
        "unmatched_archive_record_ids": len(set(html) - set(meta)),
        "metadata_rows_indexed": len(meta),
        "usable_records": len(records),
        "rejected": dict(sorted(rejected.items())),
        "resolved_columns": {
            "id": columns.id,
            "url": columns.url,
            "date": columns.date,
            "brand": columns.brand,
        },
        "available_columns": headers,
    }


def _dt(record: AdaptedRecord) -> datetime:
    return datetime.fromisoformat(record.observed_at.replace("Z", "+00:00"))


def common_time_window(
    phishing: list[AdaptedRecord],
    legitimate: list[AdaptedRecord],
) -> tuple[datetime, datetime]:
    start = max(min(map(_dt, phishing)), min(map(_dt, legitimate)))
    end = min(max(map(_dt, phishing)), max(map(_dt, legitimate)))
    if start >= end:
        raise Zenodo8041387AdapterError(
            "phishing and legitimate metadata do not have an overlapping discovery-date window"
        )
    return start, end


def _spread_indices(length: int, count: int) -> list[int]:
    if count > length:
        raise Zenodo8041387AdapterError(
            f"requested {count} samples but only {length} are eligible"
        )
    if count == 1:
        return [length // 2]
    raw = [round(i * (length - 1) / (count - 1)) for i in range(count)]
    result: list[int] = []
    used: set[int] = set()
    for value in raw:
        candidate = value
        while candidate in used and candidate + 1 < length:
            candidate += 1
        while candidate in used and candidate - 1 >= 0:
            candidate -= 1
        if candidate in used:
            raise Zenodo8041387AdapterError("unable to construct deterministic spread sample")
        used.add(candidate)
        result.append(candidate)
    return sorted(result)


def select_pilot(
    records: list[AdaptedRecord],
    *,
    count: int,
    start: datetime,
    end: datetime,
    max_brand_share: float = MAX_BRAND_SHARE_DEFAULT,
) -> list[AdaptedRecord]:
    eligible = [record for record in records if start <= _dt(record) <= end]
    eligible.sort(key=lambda record: (_dt(record), str(record.sample_number)))
    if len(eligible) < count:
        raise Zenodo8041387AdapterError(
            f"only {len(eligible)} records fall in the shared time window; requested {count}"
        )

    brand_limit = max(1, int(count * max_brand_share))
    diversified: list[AdaptedRecord] = []
    brand_counts: Counter[str] = Counter()
    for record in eligible:
        if brand_counts[record.brand_group] >= brand_limit:
            continue
        diversified.append(record)
        brand_counts[record.brand_group] += 1
    if len(diversified) < count:
        raise Zenodo8041387AdapterError(
            "brand-diversity cap leaves too few records; lower --per-class or increase --max-brand-share"
        )

    chosen = [diversified[index] for index in _spread_indices(len(diversified), count)]
    if len({record.domain_group for record in chosen}) < 4:
        raise Zenodo8041387AdapterError("pilot requires at least four domain groups per class")
    if len({record.brand_group for record in chosen}) < 4:
        raise Zenodo8041387AdapterError("pilot requires at least four brand groups per class")
    return chosen


def build_raw_plan(
    phishing: list[AdaptedRecord],
    legitimate: list[AdaptedRecord],
    *,
    output_archive_root: Path,
    metadata_hashes: Mapping[str, str],
    wait_ms: int,
    license_reference: str,
    created_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not 250 <= wait_ms <= 10_000:
        raise Zenodo8041387AdapterError("wait_ms must be between 250 and 10000")
    output_archive_root.mkdir(parents=True, exist_ok=True)

    selected = [("phishing", record) for record in phishing] + [
        ("legitimate", record) for record in legitimate
    ]
    selected.sort(key=lambda pair: (pair[0], str(pair[1].sample_number)))

    items: list[dict[str, Any]] = []
    copied: list[dict[str, Any]] = []
    for kind, record in selected:
        token = _record_token(record.sample_number)
        sample_id = f"{DATASET_ID}:{kind}:{token}"
        relative = Path(kind) / f"{token}.html"
        destination = output_archive_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(record.source_path, destination)
        copied_hash = sha256_file(destination)
        if copied_hash != record.artifact_sha256:
            raise Zenodo8041387AdapterError(f"copied artifact hash mismatch for {sample_id}")
        items.append({
            "sample_id": sample_id,
            "html_path": relative.as_posix(),
            "ground_truth": record.ground_truth,
            "observed_at": record.observed_at,
            "artifact_sha256": copied_hash,
            "domain_group": record.domain_group,
            "brand_group": record.brand_group,
            "source_group": SOURCE_GROUP,
            "wait_ms": wait_ms,
        })
        copied.append({
            "sample_id": sample_id,
            "artifact_sha256": copied_hash,
            "size": destination.stat().st_size,
        })

    snapshot = canonical_json_hash({
        "metadata_hashes": dict(sorted(metadata_hashes.items())),
        "selected_artifacts": copied,
        "source_reference": SOURCE_REFERENCE,
    })
    plan = {
        "schema_version": ARCHIVE_PLAN_SCHEMA,
        "plan_id": f"{DATASET_ID}-pilot-{snapshot[:12]}",
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
    return plan, {
        "snapshot_sha256": snapshot,
        "selected": {
            "phishing": len(phishing),
            "legitimate": len(legitimate),
            "total": len(items),
        },
        "artifact_bytes": sum(entry["size"] for entry in copied),
    }
