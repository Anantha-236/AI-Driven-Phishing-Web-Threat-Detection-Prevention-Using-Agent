from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from ml.data.stage_b_ingestion import (
    IngestionError,
    canonicalize_url,
    ingest_source,
    merge_ingestion_batches,
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_for(path: Path, *, provider: str, dataset_id: str = "test-source-2026-09-24") -> dict:
    return {
        "schema_version": "stage-b-source-manifest-1",
        "dataset_id": dataset_id,
        "display_name": provider,
        "source": {
            "provider": provider,
            "homepage": "https://example.test/",
            "retrieval_url": "https://example.test/snapshot",
            "retrieved_at": "2026-09-24T12:00:00Z",
            "content_sha256": sha256_file(path),
            "provenance": "REAL",
            "collection_method": "PUBLIC_DATASET",
            "independence_group": provider.lower().replace(" ", "-"),
            "license": {
                "name": "Test terms",
                "url": "https://example.test/terms",
                "redistributable": False,
                "research_use_allowed": True,
            },
        },
        "labeling": {
            "positive_class": "PHISHING",
            "negative_class": "LEGITIMATE",
            "label_source": "VERIFIED_SOURCE_REVIEW",
            "validation_reference": "test-fixture",
            "model_predictions_used_as_ground_truth": False,
        },
        "privacy": {
            "contains_raw_page_content": False,
            "contains_secrets": False,
            "pii_review_status": "REVIEWED",
        },
        "grouping": {
            "domain_group": "AVAILABLE",
            "brand_group": "PARTIAL",
            "time_group": "AVAILABLE",
            "source_group": "AVAILABLE",
        },
        "intended_use": ["TRAIN", "SELECTION", "CALIBRATION", "TEST"],
        "limitations": ["Fixture only"],
    }


def test_canonicalize_url_normalizes_identity_without_losing_path_or_query():
    item = canonicalize_url("HTTPS://ExAmPle.COM:443/a/../login?b=2&a=1#frag")
    assert item.canonical_url == "https://example.com/login?b=2&a=1"
    assert item.origin == "https://example.com"
    assert item.hostname == "example.com"
    assert item.redacted_url == "https://example.com/login?b=%2A&a=%2A"
    assert len(item.url_sha256) == 64
    assert len(item.origin_path_sha256) == 64


def test_ingest_rejects_source_hash_mismatch(tmp_path: Path):
    source = tmp_path / "feed.txt"
    source.write_text("https://phish.test/login\n", encoding="utf-8")
    manifest = manifest_for(source, provider="OpenPhish")
    manifest["source"]["content_sha256"] = "0" * 64

    with pytest.raises(IngestionError, match="content SHA-256"):
        ingest_source(manifest, source, adapter="openphish_text")


def test_phishtank_csv_keeps_only_verified_online_rows_and_never_uses_model_labels(tmp_path: Path):
    source = tmp_path / "phishtank.csv"
    with source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "phish_id", "url", "phish_detail_url", "submission_time",
            "verified", "verification_time", "online", "target",
        ])
        writer.writeheader()
        writer.writerow({
            "phish_id": "101",
            "url": "https://PHISH.test/login?victim=abc",
            "phish_detail_url": "https://phishtank.example/101",
            "submission_time": "2026-09-23T10:00:00+00:00",
            "verified": "yes",
            "verification_time": "2026-09-23T11:00:00+00:00",
            "online": "yes",
            "target": "Example Bank",
        })
        writer.writerow({
            "phish_id": "102",
            "url": "https://unverified.test/",
            "phish_detail_url": "https://phishtank.example/102",
            "submission_time": "2026-09-23T10:00:00+00:00",
            "verified": "no",
            "verification_time": "",
            "online": "yes",
            "target": "",
        })
        writer.writerow({
            "phish_id": "103",
            "url": "https://offline.test/",
            "phish_detail_url": "https://phishtank.example/103",
            "submission_time": "2026-09-23T10:00:00+00:00",
            "verified": "yes",
            "verification_time": "2026-09-23T11:00:00+00:00",
            "online": "no",
            "target": "",
        })

    batch = ingest_source(manifest_for(source, provider="PhishTank"), source, adapter="phishtank_csv")
    assert batch["stats"] == {
        "input_records": 3,
        "accepted_records": 1,
        "duplicate_records": 0,
        "rejected_records": 2,
        "rejection_reasons": {"not_verified_online": 2},
    }
    record = batch["records"][0]
    assert record["ground_truth"] == 1
    assert record["label_status"] == "VERIFIED_SOURCE_LABEL"
    assert record["source_record_id"] == "101"
    assert record["brand_group"] == "example bank"
    assert record["observed_at"] == "2026-09-23T11:00:00+00:00"
    assert record["redacted_url"].endswith("?victim=%2A")
    assert "abc" not in json.dumps(record)
    assert "canonical_url" not in record


def test_openphish_text_is_local_research_only_and_deduplicates_exact_urls(tmp_path: Path):
    source = tmp_path / "openphish.txt"
    source.write_text(
        "https://phish.test/login?x=1\nhttps://PHISH.test:443/login?x=1#fragment\n\n",
        encoding="utf-8",
    )
    manifest = manifest_for(source, provider="OpenPhish")
    manifest["source"]["license"]["redistributable"] = False

    batch = ingest_source(manifest, source, adapter="openphish_text")
    assert batch["stats"]["accepted_records"] == 1
    assert batch["stats"]["duplicate_records"] == 1
    assert batch["records"][0]["ground_truth"] == 1
    assert batch["records"][0]["redistribution_allowed"] is False
    assert batch["records"][0]["local_only"] is True


def test_tranco_rows_are_unlabeled_candidates_not_legitimate_ground_truth(tmp_path: Path):
    source = tmp_path / "tranco.csv"
    source.write_text("1,example.com\n2,openai.com\n", encoding="utf-8")
    manifest = manifest_for(source, provider="Tranco")

    batch = ingest_source(manifest, source, adapter="tranco_csv")
    assert batch["stats"]["accepted_records"] == 2
    assert {row["ground_truth"] for row in batch["records"]} == {None}
    assert {row["label_status"] for row in batch["records"]} == {"UNLABELED_CANDIDATE"}
    assert batch["records"][0]["rank"] == 1
    assert batch["records"][0]["redacted_url"] == "https://example.com/"


def test_merge_batches_deduplicates_cross_source_and_reports_label_conflicts(tmp_path: Path):
    phish = tmp_path / "phish.txt"
    phish.write_text("https://same.test/login\n", encoding="utf-8")
    tranco = tmp_path / "tranco.csv"
    tranco.write_text("1,same.test\n", encoding="utf-8")

    a = ingest_source(manifest_for(phish, provider="OpenPhish", dataset_id="phish-a"), phish, adapter="openphish_text")
    b = ingest_source(manifest_for(tranco, provider="Tranco", dataset_id="candidate-b"), tranco, adapter="tranco_csv")

    merged = merge_ingestion_batches([a, b])
    assert merged["stats"]["input_records"] == 2
    assert merged["stats"]["unique_exact_urls"] == 2
    assert merged["stats"]["origin_path_collisions"] == 0
    assert merged["stats"]["label_conflicts"] == 0

    # Exact same URL with opposing *verified* labels must be surfaced, never silently resolved.
    b["records"][0]["url_sha256"] = a["records"][0]["url_sha256"]
    b["records"][0]["ground_truth"] = 0
    b["records"][0]["label_status"] = "VERIFIED_SOURCE_LABEL"
    conflicted = merge_ingestion_batches([a, b])
    assert conflicted["stats"]["label_conflicts"] == 1
    assert conflicted["conflicts"][0]["url_sha256"] == a["records"][0]["url_sha256"]
