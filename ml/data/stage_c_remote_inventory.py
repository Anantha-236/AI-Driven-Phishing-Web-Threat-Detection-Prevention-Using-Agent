"""Stage C Task 4: verify pinned Mendeley public dataset inventories.

No dataset bodies are downloaded here. The task resolves public metadata only,
normalizes stable file identities, and freezes immutable download manifests.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

MANIFEST_SCHEMA = "stage-c-remote-download-manifest-1"
REPORT_SCHEMA = "stage-c-remote-inventory-report-1"
DEFAULT_API_BASE = "https://api.data.mendeley.com"

_DOI_RE = re.compile(r"^10\.17632/([A-Za-z0-9]+)\.(\d+)$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class StageCRemoteInventoryError(ValueError):
    pass


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_mendeley_doi(doi: str) -> tuple[str, int]:
    if not isinstance(doi, str):
        raise StageCRemoteInventoryError("DOI must be a string")
    match = _DOI_RE.fullmatch(doi.strip())
    if not match:
        raise StageCRemoteInventoryError(f"unsupported Mendeley DOI: {doi}")
    return match.group(1), int(match.group(2))


def _json_get(
    url: str,
    *,
    token: str | None = None,
    timeout: float = 30.0,
) -> Any:
    headers = {
        "Accept": "application/json, application/vnd.mendeley-public-dataset.1+json",
        "User-Agent": "stage-c-dataset-inventory/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise StageCRemoteInventoryError(
                f"Mendeley API authorization required or rejected for {url}; "
                "set MENDELEY_DATA_TOKEN if your API access requires a token"
            ) from exc
        raise StageCRemoteInventoryError(
            f"Mendeley API HTTP {exc.code} for {url}"
        ) from exc
    except URLError as exc:
        raise StageCRemoteInventoryError(
            f"Mendeley API network error for {url}: {exc.reason}"
        ) from exc
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StageCRemoteInventoryError(
            f"Mendeley API returned non-JSON content for {url}"
        ) from exc


def _dataset_url(api_base: str, dataset_id: str, version: int) -> str:
    return (
        f"{api_base.rstrip('/')}/datasets/{quote(dataset_id)}?"
        + urlencode({"version": version})
    )


def _files_url(
    api_base: str,
    dataset_id: str,
    version: int,
    *,
    start: int,
    limit: int,
) -> str:
    query = urlencode(
        {"version": version, "$start": start, "$limit": limit}
    )
    return (
        f"{api_base.rstrip('/')}/datasets/{quote(dataset_id)}/files?{query}"
    )


def _extract_version(dataset: Mapping[str, Any]) -> int | None:
    value = dataset.get("version")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _extract_doi(dataset: Mapping[str, Any]) -> str | None:
    value = dataset.get("doi")
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("id", "doi"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    return None


def _coerce_files_page(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, Mapping)]
    if isinstance(value, Mapping):
        for key in ("files", "items", "results", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return [x for x in candidate if isinstance(x, Mapping)]
    raise StageCRemoteInventoryError(
        "Mendeley file-list response has an unsupported shape"
    )


def _normalise_file(raw: Mapping[str, Any]) -> dict[str, Any]:
    file_id = raw.get("id")
    filename = raw.get("filename") or raw.get("name")
    details = raw.get("content_details")
    if not isinstance(details, Mapping):
        details = {}

    size = raw.get("size")
    if not isinstance(size, int):
        size = details.get("size")
    digest = (
        details.get("sha256_hash")
        or raw.get("sha256_hash")
        or raw.get("sha256")
    )

    if not isinstance(file_id, str) or not file_id:
        raise StageCRemoteInventoryError("remote file is missing stable file UUID")
    if not isinstance(filename, str) or not filename:
        raise StageCRemoteInventoryError(
            f"remote file {file_id} is missing filename"
        )
    if type(size) is not int or size < 0:
        raise StageCRemoteInventoryError(
            f"remote file {filename} is missing valid size"
        )
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise StageCRemoteInventoryError(
            f"remote file {filename} is missing valid SHA-256"
        )

    media_type = (
        details.get("content_type")
        or raw.get("media_type")
        or raw.get("content_type")
    )
    folder_id = raw.get("folder_id")
    last_modified = raw.get("last_modified_date") or details.get("created_date")

    return {
        "file_id": file_id,
        "filename": filename,
        "size_bytes": size,
        "sha256": digest.lower(),
        "media_type": media_type if isinstance(media_type, str) else None,
        "folder_id": folder_id if isinstance(folder_id, str) else None,
        "last_modified": last_modified if isinstance(last_modified, str) else None,
    }


def _deduplicate_files(files: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for raw in files:
        current = _normalise_file(raw)
        existing = by_id.get(current["file_id"])
        if existing is not None and existing != current:
            raise StageCRemoteInventoryError(
                f"conflicting metadata for remote file {current['file_id']}"
            )
        by_id[current["file_id"]] = current
    result = list(by_id.values())
    result.sort(key=lambda x: (x["filename"].casefold(), x["file_id"]))
    return result


def fetch_public_dataset_inventory(
    *,
    doi: str,
    api_base: str = DEFAULT_API_BASE,
    token: str | None = None,
    page_limit: int = 100,
    http_get: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    dataset_id, version = parse_mendeley_doi(doi)

    if http_get is None:
        def get(url: str) -> Any:
            return _json_get(url, token=token)
    else:
        get = http_get

    dataset_url = _dataset_url(api_base, dataset_id, version)
    dataset = get(dataset_url)
    if not isinstance(dataset, Mapping):
        raise StageCRemoteInventoryError(
            "Mendeley dataset metadata response must be an object"
        )

    observed_version = _extract_version(dataset)
    if observed_version is not None and observed_version != version:
        raise StageCRemoteInventoryError(
            f"version drift: requested {version}, API returned {observed_version}"
        )

    observed_doi = _extract_doi(dataset)
    if observed_doi:
        observed_doi = observed_doi.removeprefix("https://doi.org/").strip()
        if observed_doi != doi:
            raise StageCRemoteInventoryError(
                f"DOI drift: requested {doi}, API returned {observed_doi}"
            )

    embedded = dataset.get("files")
    raw_files: list[Mapping[str, Any]] = []
    inventory_method: str

    if isinstance(embedded, list) and embedded:
        raw_files.extend(x for x in embedded if isinstance(x, Mapping))
        inventory_method = "DATASET_EMBEDDED_FILES"
    else:
        inventory_method = "PAGINATED_PUBLIC_FILES_ENDPOINT"
        start = 0
        while True:
            page_url = _files_url(
                api_base,
                dataset_id,
                version,
                start=start,
                limit=page_limit,
            )
            page = _coerce_files_page(get(page_url))
            raw_files.extend(page)
            if len(page) < page_limit:
                break
            start += len(page)
            if start > 1_000_000:
                raise StageCRemoteInventoryError(
                    "remote file pagination exceeded safety limit"
                )

    files = _deduplicate_files(raw_files)
    if not files:
        raise StageCRemoteInventoryError(
            f"pinned dataset {doi} returned no downloadable files"
        )

    return {
        "dataset_id": dataset_id,
        "version": version,
        "doi": doi,
        "title": dataset.get("name") or dataset.get("title"),
        "inventory_method": inventory_method,
        "metadata_endpoint": dataset_url,
        "file_count": len(files),
        "total_size_bytes": sum(x["size_bytes"] for x in files),
        "files": files,
        "remote_inventory_sha256": canonical_hash(files),
    }


def build_download_manifest(
    *,
    role: str,
    source_id: str,
    expected_doi: str,
    inventory: Mapping[str, Any],
) -> dict[str, Any]:
    if role not in {"DEVELOPMENT", "FINAL_HOLDOUT"}:
        raise StageCRemoteInventoryError("unsupported manifest role")
    if inventory.get("doi") != expected_doi:
        raise StageCRemoteInventoryError("inventory DOI does not match frozen plan")

    dataset_id, version = parse_mendeley_doi(expected_doi)
    if inventory.get("dataset_id") != dataset_id:
        raise StageCRemoteInventoryError("inventory dataset id mismatch")
    if inventory.get("version") != version:
        raise StageCRemoteInventoryError("inventory version mismatch")

    files = inventory.get("files")
    if not isinstance(files, list) or not files:
        raise StageCRemoteInventoryError("inventory contains no files")

    entries = []
    for file in files:
        if not isinstance(file, Mapping):
            raise StageCRemoteInventoryError("invalid inventory file entry")
        file_id = file.get("file_id")
        filename = file.get("filename")
        size = file.get("size_bytes")
        digest = file.get("sha256")
        if not isinstance(file_id, str) or not file_id:
            raise StageCRemoteInventoryError("manifest file UUID missing")
        if not isinstance(filename, str) or not filename:
            raise StageCRemoteInventoryError("manifest filename missing")
        if type(size) is not int or size < 0:
            raise StageCRemoteInventoryError("manifest file size invalid")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise StageCRemoteInventoryError("manifest file SHA-256 invalid")

        entries.append({
            "file_id": file_id,
            "filename": filename,
            "size_bytes": size,
            "sha256": digest.lower(),
            "download_endpoint": (
                f"{DEFAULT_API_BASE}/datasets/{dataset_id}/files/"
                f"{file_id}/file_downloaded?version={version}"
            ),
        })

    entries.sort(key=lambda x: (x["filename"].casefold(), x["file_id"]))
    return {
        "schema_version": MANIFEST_SCHEMA,
        "stage": "C",
        "role": role,
        "research_only": True,
        "deployment_authorized": False,
        "source_id": source_id,
        "provider": "Mendeley Data",
        "dataset_id": dataset_id,
        "version": version,
        "doi": expected_doi,
        "file_count": len(entries),
        "total_size_bytes": sum(x["size_bytes"] for x in entries),
        "files": entries,
        "file_set_sha256": canonical_hash(entries),
        "download_state": (
            "LOCKED_METADATA_ONLY"
            if role == "FINAL_HOLDOUT"
            else "VERIFIED_MANIFEST_NOT_DOWNLOADED"
        ),
    }


def verify_acquisition_plan(plan: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if plan.get("schema_version") != "stage-c-dataset-acquisition-plan-1":
        raise StageCRemoteInventoryError("unsupported acquisition-plan schema")
    if plan.get("status") != "PASS":
        raise StageCRemoteInventoryError("acquisition plan is not PASS")
    if plan.get("downloads_authorized") is not False:
        raise StageCRemoteInventoryError(
            "Task 4 expects Task 3 downloads_authorized=false"
        )
    development = plan.get("development")
    final = plan.get("final_holdout")
    if not isinstance(development, Mapping) or not isinstance(final, Mapping):
        raise StageCRemoteInventoryError("acquisition plan roles are missing")
    return development, final


def freeze_remote_inventories(
    *,
    acquisition_plan: Mapping[str, Any],
    fetch_inventory: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    development, final = verify_acquisition_plan(acquisition_plan)

    dev_inv = fetch_inventory(str(development["doi"]))
    final_inv = fetch_inventory(str(final["doi"]))

    dev_manifest = build_download_manifest(
        role="DEVELOPMENT",
        source_id=str(development["source_id"]),
        expected_doi=str(development["doi"]),
        inventory=dev_inv,
    )
    final_manifest = build_download_manifest(
        role="FINAL_HOLDOUT",
        source_id=str(final["source_id"]),
        expected_doi=str(final["doi"]),
        inventory=final_inv,
    )

    if dev_manifest["source_id"] == final_manifest["source_id"]:
        raise StageCRemoteInventoryError(
            "development and final-holdout sources are not independent"
        )
    if (
        dev_manifest["dataset_id"] == final_manifest["dataset_id"]
        and dev_manifest["version"] == final_manifest["version"]
    ):
        raise StageCRemoteInventoryError(
            "development and final holdout resolve to same remote dataset"
        )

    return {
        "schema_version": REPORT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "dataset_downloads_performed": False,
        "development_download_authorized": False,
        "final_holdout_download_authorized": False,
        "development": {
            "doi": dev_manifest["doi"],
            "file_count": dev_manifest["file_count"],
            "total_size_bytes": dev_manifest["total_size_bytes"],
            "remote_inventory_sha256": dev_inv["remote_inventory_sha256"],
            "file_set_sha256": dev_manifest["file_set_sha256"],
        },
        "final_holdout": {
            "doi": final_manifest["doi"],
            "file_count": final_manifest["file_count"],
            "total_size_bytes": final_manifest["total_size_bytes"],
            "remote_inventory_sha256": final_inv["remote_inventory_sha256"],
            "file_set_sha256": final_manifest["file_set_sha256"],
            "state": "LOCKED_METADATA_ONLY",
        },
        "next_gate": "REVIEW_FROZEN_REMOTE_INVENTORIES_AND_DOWNLOAD_SIZES",
        "_development_manifest": dev_manifest,
        "_final_manifest": final_manifest,
    }


def load_optional_token(env_name: str = "MENDELEY_DATA_TOKEN") -> str | None:
    value = os.environ.get(env_name)
    return value.strip() if isinstance(value, str) and value.strip() else None
