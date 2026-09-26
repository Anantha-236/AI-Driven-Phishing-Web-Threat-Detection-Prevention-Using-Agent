from __future__ import annotations

from copy import deepcopy
import pytest

from ml.data.stage_c_remote_inventory import (
    StageCRemoteInventoryError,
    build_download_manifest,
    fetch_public_dataset_inventory,
    freeze_remote_inventories,
    parse_mendeley_doi,
)


def file(file_id: str, name: str, size: int, digest: str):
    return {
        "id": file_id,
        "filename": name,
        "size": size,
        "content_details": {
            "sha256_hash": digest,
            "content_type": "application/octet-stream",
        },
    }


def test_parse_pinned_mendeley_doi():
    assert parse_mendeley_doi("10.17632/n96ncsr5g4.1") == ("n96ncsr5g4", 1)
    assert parse_mendeley_doi("10.17632/fmbs4kp9wz.3") == ("fmbs4kp9wz", 3)


def test_embedded_file_inventory_is_normalized_and_hashed():
    digest = "a" * 64
    def get(url: str):
        return {
            "version": 1,
            "doi": {"id": "10.17632/n96ncsr5g4.1"},
            "files": [file("uuid-1", "index.sql", 42, digest)],
        }

    result = fetch_public_dataset_inventory(
        doi="10.17632/n96ncsr5g4.1",
        http_get=get,
    )
    assert result["file_count"] == 1
    assert result["files"][0]["filename"] == "index.sql"
    assert len(result["remote_inventory_sha256"]) == 64


def test_paginated_file_inventory_is_supported():
    digest_a = "a" * 64
    digest_b = "b" * 64

    def get(url: str):
        if "/files?" not in url:
            return {
                "version": 3,
                "doi": {"id": "10.17632/fmbs4kp9wz.3"},
                "files": [],
            }
        if "%24start=0" in url or "$start=0" in url:
            return [
                file("uuid-1", "a.zip", 10, digest_a),
                file("uuid-2", "b.zip", 20, digest_b),
            ]
        return []

    result = fetch_public_dataset_inventory(
        doi="10.17632/fmbs4kp9wz.3",
        page_limit=2,
        http_get=get,
    )
    assert result["file_count"] == 2
    assert result["total_size_bytes"] == 30


def test_version_drift_is_rejected():
    def get(url: str):
        return {
            "version": 4,
            "doi": {"id": "10.17632/fmbs4kp9wz.4"},
            "files": [file("uuid-1", "x.zip", 10, "a" * 64)],
        }

    with pytest.raises(StageCRemoteInventoryError, match="version drift"):
        fetch_public_dataset_inventory(
            doi="10.17632/fmbs4kp9wz.3",
            http_get=get,
        )


def test_missing_sha256_is_rejected():
    def get(url: str):
        return {
            "version": 1,
            "doi": {"id": "10.17632/n96ncsr5g4.1"},
            "files": [{
                "id": "uuid-1",
                "filename": "x.zip",
                "size": 10,
                "content_details": {},
            }],
        }

    with pytest.raises(StageCRemoteInventoryError, match="SHA-256"):
        fetch_public_dataset_inventory(
            doi="10.17632/n96ncsr5g4.1",
            http_get=get,
        )


def test_manifest_uses_pinned_version_download_endpoint():
    inventory = {
        "dataset_id": "fmbs4kp9wz",
        "version": 3,
        "doi": "10.17632/fmbs4kp9wz.3",
        "files": [{
            "file_id": "uuid-1",
            "filename": "raw.zip",
            "size_bytes": 100,
            "sha256": "a" * 64,
        }],
    }
    result = build_download_manifest(
        role="FINAL_HOLDOUT",
        source_id="mendeley-fmbs4kp9wz-v3",
        expected_doi="10.17632/fmbs4kp9wz.3",
        inventory=inventory,
    )
    assert result["version"] == 3
    assert "version=3" in result["files"][0]["download_endpoint"]
    assert result["download_state"] == "LOCKED_METADATA_ONLY"


def plan():
    return {
        "schema_version": "stage-c-dataset-acquisition-plan-1",
        "status": "PASS",
        "downloads_authorized": False,
        "development": {
            "source_id": "mendeley-n96ncsr5g4-v1",
            "doi": "10.17632/n96ncsr5g4.1",
        },
        "final_holdout": {
            "source_id": "mendeley-fmbs4kp9wz-v3",
            "doi": "10.17632/fmbs4kp9wz.3",
        },
    }


def inventory(dataset_id: str, version: int, doi: str, tag: str):
    files = [{
        "file_id": f"{tag}-uuid",
        "filename": f"{tag}.zip",
        "size_bytes": 100,
        "sha256": (tag[0] * 64) if tag[0] in "abcdef" else "a" * 64,
    }]
    return {
        "dataset_id": dataset_id,
        "version": version,
        "doi": doi,
        "files": files,
        "remote_inventory_sha256": "f" * 64,
    }


def test_freeze_keeps_both_downloads_unauthorized():
    def fetch(doi: str):
        if doi.endswith(".1"):
            return inventory(
                "n96ncsr5g4", 1, "10.17632/n96ncsr5g4.1", "a"
            )
        return inventory(
            "fmbs4kp9wz", 3, "10.17632/fmbs4kp9wz.3", "b"
        )

    result = freeze_remote_inventories(
        acquisition_plan=plan(),
        fetch_inventory=fetch,
    )
    assert result["status"] == "PASS"
    assert result["dataset_downloads_performed"] is False
    assert result["development_download_authorized"] is False
    assert result["final_holdout_download_authorized"] is False
    assert result["next_gate"] == "REVIEW_FROZEN_REMOTE_INVENTORIES_AND_DOWNLOAD_SIZES"


def test_same_remote_dataset_for_both_roles_is_rejected():
    bad = deepcopy(plan())
    bad["final_holdout"]["source_id"] = "other-source"
    bad["final_holdout"]["doi"] = "10.17632/n96ncsr5g4.1"

    def fetch(doi: str):
        return inventory(
            "n96ncsr5g4", 1, "10.17632/n96ncsr5g4.1", "a"
        )

    with pytest.raises(StageCRemoteInventoryError, match="same remote dataset"):
        freeze_remote_inventories(
            acquisition_plan=bad,
            fetch_inventory=fetch,
        )
