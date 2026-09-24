from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from ml.data.stage_b_archive_replay import (
    ARCHIVED_BROWSER_REPLAY,
    ArchiveReplayValidationError,
    validate_archive_replay_plan,
)


def write_html(root: Path, name: str, body: str = "<form><input type=password></form>") -> tuple[str, str]:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return name.replace("\\", "/"), sha256(path.read_bytes()).hexdigest()


def plan(path: str, digest: str):
    return {
        "schema_version": "stage-b-archive-replay-plan-1",
        "plan_id": "archive-replay-test",
        "created_at": "2026-09-25T00:00:00Z",
        "dataset": {
            "dataset_id": "archive-test",
            "provider": "Research Archive",
            "source_reference": "doi:example",
            "source_snapshot_sha256": "a" * 64,
            "independence_group": "archive-test-source",
            "license_reference": "research-license",
            "research_use_allowed": True,
        },
        "items": [{
            "sample_id": "archive-test:1",
            "html_path": path,
            "ground_truth": 1,
            "observed_at": "2026-01-01T00:00:00Z",
            "artifact_sha256": digest,
            "domain_group": "example.test",
            "brand_group": "example-brand",
            "source_group": "archive-test-source",
            "wait_ms": 500,
        }],
    }


def test_validates_local_hashed_archive_without_persisting_absolute_root(tmp_path: Path):
    rel, digest = write_html(tmp_path, "sample/index.html")
    result = validate_archive_replay_plan(plan(rel, digest), tmp_path)
    assert result["collection_provenance"] == ARCHIVED_BROWSER_REPLAY
    assert result["items"][0]["html_path"] == "sample/index.html"
    assert str(tmp_path) not in str(result)
    assert result["safety_contract"]["raw_source_urls_persisted"] is False


def test_rejects_path_traversal(tmp_path: Path):
    rel, digest = write_html(tmp_path, "sample.html")
    data = plan(rel, digest)
    data["items"][0]["html_path"] = "../sample.html"
    with pytest.raises(ArchiveReplayValidationError, match="traversal"):
        validate_archive_replay_plan(data, tmp_path)


def test_rejects_artifact_hash_mismatch(tmp_path: Path):
    rel, digest = write_html(tmp_path, "sample.html")
    data = plan(rel, digest)
    data["items"][0]["artifact_sha256"] = "0" * 64
    with pytest.raises(ArchiveReplayValidationError, match="SHA-256 mismatch"):
        validate_archive_replay_plan(data, tmp_path)


def test_rejects_archive_shard_as_fake_independent_source(tmp_path: Path):
    rel, digest = write_html(tmp_path, "sample.html")
    data = plan(rel, digest)
    data["items"][0]["source_group"] = "archive-test-shard-0001"
    with pytest.raises(ArchiveReplayValidationError, match="independence_group"):
        validate_archive_replay_plan(data, tmp_path)


def test_rejects_duplicate_artifacts(tmp_path: Path):
    rel, digest = write_html(tmp_path, "sample.html")
    data = plan(rel, digest)
    duplicate = dict(data["items"][0])
    duplicate["sample_id"] = "archive-test:2"
    data["items"].append(duplicate)
    with pytest.raises(ArchiveReplayValidationError, match="duplicate archived HTML"):
        validate_archive_replay_plan(data, tmp_path)


def test_rejects_non_research_source(tmp_path: Path):
    rel, digest = write_html(tmp_path, "sample.html")
    data = plan(rel, digest)
    data["dataset"]["research_use_allowed"] = False
    with pytest.raises(ArchiveReplayValidationError, match="research use"):
        validate_archive_replay_plan(data, tmp_path)
