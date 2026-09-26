from __future__ import annotations

import hashlib
from pathlib import Path
import zipfile

import pytest

from ml.data.stage_b_scaled_assembly import (
    ScaledAssemblyError,
    extract_shard_html_exact,
    input_preflight,
    quarantine_duplicate_artifacts,
    quarantine_oversized_artifacts,
    split_count_readiness,
)
from ml.data.stage_b_zenodo8041387 import AdaptedRecord


def make_zip(path: Path, record_ids: list[str]):
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        for record_id in record_ids:
            z.writestr(f"{record_id}/index.html", f"<html>{record_id}</html>")
            z.writestr(f"{record_id}/assets/app.js", "ignored")
        z.writestr("../escape.html", "bad")
    return hashlib.md5(path.read_bytes()).hexdigest()


def test_exact_extraction_uses_only_indexed_record_ids(tmp_path: Path):
    ids = ["64042704845bed3cfa5ef610", "64042939845bed3cfa5ef619"]
    archive = tmp_path / "sample.zip"
    md5 = make_zip(archive, ids)
    destination = tmp_path / "out"
    result = extract_shard_html_exact(
        archive, destination, expected_ids=set(ids), expected_md5=md5
    )
    assert result["status"] == "PASS"
    assert result["reconciled_record_ids"] == 2
    assert result["html_extracted"] == 2
    assert not (tmp_path / "escape.html").exists()


def test_exact_extraction_quarantines_indexed_record_with_no_html(tmp_path: Path):
    present = "64042704845bed3cfa5ef610"
    no_html = "64042939845bed3cfa5ef619"
    archive = tmp_path / "sample.zip"
    md5 = make_zip(archive, [present])

    result = extract_shard_html_exact(
        archive,
        tmp_path / "out",
        expected_ids={present, no_html},
        expected_md5=md5,
    )
    assert result["status"] == "PASS"
    assert result["reconciled_record_ids"] == 1
    assert result["missing_html_capture_count"] == 1
    assert result["missing_html_capture_record_ids"] == [no_html]
    assert result["source_record_quarantine"] == [
        {"record_id": no_html, "reason": "MISSING_HTML_CAPTURE"}
    ]


def test_exact_extraction_still_fails_when_html_exists_but_path_is_unsafe(tmp_path: Path):
    record_id = "64042704845bed3cfa5ef610"
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w", allowZip64=True) as z:
        z.writestr(f"../{record_id}/index.html", "<html>unsafe path</html>")
    md5 = hashlib.md5(archive.read_bytes()).hexdigest()

    with pytest.raises(ScaledAssemblyError, match="missing_with_html=1"):
        extract_shard_html_exact(
            archive,
            tmp_path / "out",
            expected_ids={record_id},
            expected_md5=md5,
        )


def test_preflight_distinguishes_final_and_partial_files(tmp_path: Path):
    (tmp_path / "ready.zip").write_bytes(b"x")
    (tmp_path / "pending.zip.part").write_bytes(b"123")
    selected = [
        {"name": "ready.zip", "class": "phishing"},
        {"name": "pending.zip", "class": "legitimate"},
    ]
    result = input_preflight(selected, [tmp_path])
    assert result["status"] == "WAITING"
    assert result["ready_shards"] == 1
    assert {row["name"]: row["state"] for row in result["shards"]} == {
        "ready.zip": "READY",
        "pending.zip": "DOWNLOADING",
    }


def adapted(sample: str, digest: str, label: int) -> AdaptedRecord:
    return AdaptedRecord(
        sample_number=sample,
        source_path=Path(f"{sample}.html"),
        ground_truth=label,
        observed_at="2023-01-01T00:00:00Z",
        domain_group=f"{sample}.example",
        brand_group=f"brand-{sample}",
        artifact_sha256=digest,
    )


def test_oversized_html_is_quarantined_before_archive_replay_validation(tmp_path: Path):
    safe_path = tmp_path / "safe.html"
    large_path = tmp_path / "large.html"
    safe_path.write_bytes(b"x" * 16)
    large_path.write_bytes(b"x" * 33)

    safe = AdaptedRecord(
        sample_number="safe",
        source_path=safe_path,
        ground_truth=1,
        observed_at="2023-01-01T00:00:00Z",
        domain_group="safe.example",
        brand_group="safe-brand",
        artifact_sha256="a" * 64,
    )
    large = AdaptedRecord(
        sample_number="large",
        source_path=large_path,
        ground_truth=1,
        observed_at="2023-01-01T00:00:00Z",
        domain_group="large.example",
        brand_group="large-brand",
        artifact_sha256="b" * 64,
    )

    phishing, legitimate, quarantine = quarantine_oversized_artifacts(
        [safe, large],
        [],
        max_html_bytes=32,
    )

    assert [row.sample_number for row in phishing] == ["safe"]
    assert legitimate == []
    assert quarantine == [{
        "class": "phishing",
        "record_id": "large",
        "sample_id": "zenodo-8041387:phishing:large",
        "artifact_sha256": "b" * 64,
        "html_bytes": 33,
        "max_html_bytes": 32,
        "reason": "OVERSIZED_HTML_CAPTURE",
    }]


def test_empty_html_is_not_hidden_by_oversized_quarantine(tmp_path: Path):
    empty_path = tmp_path / "empty.html"
    empty_path.write_bytes(b"")
    empty = AdaptedRecord(
        sample_number="empty",
        source_path=empty_path,
        ground_truth=0,
        observed_at="2023-01-01T00:00:00Z",
        domain_group="empty.example",
        brand_group=None,
        artifact_sha256="c" * 64,
    )

    phishing, legitimate, quarantine = quarantine_oversized_artifacts(
        [],
        [empty],
        max_html_bytes=32,
    )

    assert phishing == []
    assert [row.sample_number for row in legitimate] == ["empty"]
    assert quarantine == []


def test_duplicate_artifacts_are_quarantined_instead_of_entering_split():
    duplicate = "a" * 64
    unique = "b" * 64
    p, l, quarantine = quarantine_duplicate_artifacts(
        [adapted("p1", duplicate, 1), adapted("p2", unique, 1)],
        [adapted("l1", duplicate, 0)],
    )
    assert [x.sample_number for x in p] == ["p2"]
    assert l == []
    assert len(quarantine) == 1
    assert quarantine[0]["labels"] == [0, 1]


def test_split_count_readiness_enforces_each_class_not_only_total():
    splits = {
        "partitions": {
            "train": {"legitimate": 100, "phishing": 100},
            "selection": {"legitimate": 50, "phishing": 49},
            "calibration": {"legitimate": 50, "phishing": 50},
            "test": {"legitimate": 100, "phishing": 100},
        }
    }
    policy = {
        "schema_version": "stage-b-readiness-policy-1",
        "min_samples_per_class": {
            "train": 100, "selection": 50, "calibration": 50, "test": 100,
        },
    }
    result = split_count_readiness(splits, policy)
    assert result["status"] == "FAIL"
    assert result["issues"] == [{
        "partition": "selection",
        "class": "phishing",
        "observed": 49,
        "required": 50,
    }]
