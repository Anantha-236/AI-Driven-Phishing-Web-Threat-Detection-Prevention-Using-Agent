"""Validate local archived-webpage replay plans for Stage B research acquisition.

This module never downloads remote content and never executes HTML. It verifies
that every planned HTML artifact is an ordinary local file below an explicitly
provided archive root, that the caller supplied the exact SHA-256, and that the
metadata needed for later leakage analysis is present.

Absolute local paths and raw source URLs are deliberately absent from normalized
output so plans can be shared without disclosing workstation layout or URL data.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

ARCHIVE_REPLAY_PLAN_SCHEMA = "stage-b-archive-replay-plan-1"
NORMALIZED_REPLAY_PLAN_SCHEMA = "stage-b-archive-replay-normalized-1"
ARCHIVED_BROWSER_REPLAY = "ARCHIVED_BROWSER_REPLAY"

PLAN_FIELDS = {"schema_version", "plan_id", "created_at", "dataset", "items"}
DATASET_FIELDS = {
    "dataset_id", "provider", "source_reference", "source_snapshot_sha256",
    "independence_group", "license_reference", "research_use_allowed",
}
ITEM_FIELDS = {
    "sample_id", "html_path", "ground_truth", "observed_at", "artifact_sha256",
    "domain_group", "brand_group", "source_group", "wait_ms",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_WAIT_MS = 250
MAX_WAIT_MS = 10_000
MAX_HTML_BYTES = 12 * 1024 * 1024
ALLOWED_SUFFIXES = {".html", ".htm"}


class ArchiveReplayValidationError(ValueError):
    """Raised when archived replay metadata or local files are unsafe/invalid."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ArchiveReplayValidationError(f"{name} must be an object")
    return value


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], name: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise ArchiveReplayValidationError(f"unexpected {name} fields: {', '.join(extras)}")


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ArchiveReplayValidationError(f"{name} is required")
    return value.strip()


def _sha256(value: Any, name: str) -> str:
    text = _string(value, name).lower()
    if not SHA256_RE.fullmatch(text):
        raise ArchiveReplayValidationError(f"{name} must be lowercase SHA-256")
    return text


def _time(value: Any, name: str) -> str:
    text = _string(value, name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArchiveReplayValidationError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ArchiveReplayValidationError(f"{name} must include a timezone")
    return text


def _relative_html_path(value: Any) -> str:
    text = _string(value, "html_path").replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts:
        raise ArchiveReplayValidationError("html_path must be relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveReplayValidationError("html_path cannot contain traversal segments")
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ArchiveReplayValidationError("html_path must reference .html or .htm")
    return path.as_posix()


def _resolve_under_root(root: Path, relative: str) -> Path:
    root_resolved = root.resolve(strict=True)
    candidate = (root_resolved / Path(*PurePosixPath(relative).parts)).resolve(strict=True)
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ArchiveReplayValidationError("html_path escapes archive_root") from exc
    if candidate.is_symlink() or not candidate.is_file():
        raise ArchiveReplayValidationError("html_path must resolve to an ordinary file")
    return candidate


def validate_archive_replay_plan(
    data: Mapping[str, Any],
    archive_root: str | Path,
) -> dict[str, Any]:
    plan = deepcopy(dict(_require_mapping(data, "archive replay plan")))
    _reject_unknown(plan, PLAN_FIELDS, "archive replay plan")
    if plan.get("schema_version") != ARCHIVE_REPLAY_PLAN_SCHEMA:
        raise ArchiveReplayValidationError("unsupported archive replay plan schema")

    plan_id = _string(plan.get("plan_id"), "plan_id")
    created_at = _time(plan.get("created_at"), "created_at")

    dataset = dict(_require_mapping(plan.get("dataset"), "dataset"))
    _reject_unknown(dataset, DATASET_FIELDS, "dataset")
    dataset_id = _string(dataset.get("dataset_id"), "dataset.dataset_id")
    provider = _string(dataset.get("provider"), "dataset.provider")
    source_reference = _string(dataset.get("source_reference"), "dataset.source_reference")
    source_snapshot_sha256 = _sha256(
        dataset.get("source_snapshot_sha256"), "dataset.source_snapshot_sha256"
    )
    independence_group = _string(dataset.get("independence_group"), "dataset.independence_group")
    license_reference = _string(dataset.get("license_reference"), "dataset.license_reference")
    if dataset.get("research_use_allowed") is not True:
        raise ArchiveReplayValidationError("dataset must explicitly allow research use")

    root = Path(archive_root)
    if not root.is_dir():
        raise ArchiveReplayValidationError("archive_root must be an existing directory")

    raw_items = plan.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ArchiveReplayValidationError("archive replay plan must contain items")

    normalized_items: list[dict[str, Any]] = []
    sample_ids: set[str] = set()
    artifact_hashes: set[str] = set()
    for raw in raw_items:
        item = dict(_require_mapping(raw, "archive replay item"))
        _reject_unknown(item, ITEM_FIELDS, "archive replay item")
        sample_id = _string(item.get("sample_id"), "sample_id")
        if sample_id in sample_ids:
            raise ArchiveReplayValidationError(f"duplicate sample_id: {sample_id}")
        sample_ids.add(sample_id)

        relative = _relative_html_path(item.get("html_path"))
        local_path = _resolve_under_root(root, relative)
        size = local_path.stat().st_size
        if size <= 0:
            raise ArchiveReplayValidationError(f"empty archived HTML: {sample_id}")
        if size > MAX_HTML_BYTES:
            raise ArchiveReplayValidationError(
                f"archived HTML exceeds {MAX_HTML_BYTES} bytes: {sample_id}"
            )

        expected_hash = _sha256(item.get("artifact_sha256"), "artifact_sha256")
        actual_hash = sha256_file(local_path)
        if actual_hash != expected_hash:
            raise ArchiveReplayValidationError(f"artifact SHA-256 mismatch: {sample_id}")
        if actual_hash in artifact_hashes:
            raise ArchiveReplayValidationError("duplicate archived HTML artifact detected")
        artifact_hashes.add(actual_hash)

        label = item.get("ground_truth")
        if type(label) is not int or label not in (0, 1):
            raise ArchiveReplayValidationError("ground_truth must be integer 0 or 1")

        observed_at = _time(item.get("observed_at"), "observed_at")
        domain_group = _string(item.get("domain_group"), "domain_group")
        brand_group = item.get("brand_group")
        if brand_group is not None:
            brand_group = _string(brand_group, "brand_group")
        source_group = _string(item.get("source_group"), "source_group")
        if source_group != independence_group:
            raise ArchiveReplayValidationError(
                "source_group must equal the dataset independence_group; "
                "archive shards must not be presented as independent sources"
            )

        wait_ms = item.get("wait_ms")
        if type(wait_ms) is not int or not MIN_WAIT_MS <= wait_ms <= MAX_WAIT_MS:
            raise ArchiveReplayValidationError(
                f"wait_ms must be between {MIN_WAIT_MS} and {MAX_WAIT_MS}"
            )

        normalized_items.append({
            "sample_id": sample_id,
            "html_path": relative,
            "ground_truth": label,
            "observed_at": observed_at,
            "artifact_sha256": actual_hash,
            "domain_group": domain_group,
            "brand_group": brand_group,
            "source_group": source_group,
            "wait_ms": wait_ms,
        })

    normalized_items.sort(key=lambda item: item["sample_id"])
    return {
        "schema_version": NORMALIZED_REPLAY_PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": created_at,
        "dataset": {
            "dataset_id": dataset_id,
            "provider": provider,
            "source_reference": source_reference,
            "source_snapshot_sha256": source_snapshot_sha256,
            "independence_group": independence_group,
            "license_reference": license_reference,
            "research_use_allowed": True,
        },
        "collection_provenance": ARCHIVED_BROWSER_REPLAY,
        "items": normalized_items,
        "safety_contract": {
            "local_files_only": True,
            "absolute_paths_persisted": False,
            "raw_source_urls_persisted": False,
            "archive_shards_treated_as_independent_sources": False,
            "max_html_bytes": MAX_HTML_BYTES,
        },
        "limitations": [
            "Archive replay preserves structural browser evidence but cannot reproduce original network, TLS, server, timing, or JavaScript execution context.",
            "Archived source shards are not treated as independent datasets.",
            "Labels and observed_at values remain only as trustworthy as the declared archive metadata.",
        ],
    }
