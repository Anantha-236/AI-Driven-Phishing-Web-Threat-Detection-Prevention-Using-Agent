from __future__ import annotations

from copy import deepcopy

import pytest

from ml.data.stage_b_reconciliation import ReconciliationError, reconcile_ingestion_batches


def record(*, dataset: str, source_group: str, artifact: str, url: str, origin_path: str,
           label: int | None, status: str, host: str = "example.test") -> dict:
    return {
        "schema_version": "stage-b-ingested-url-1",
        "sample_id": f"{dataset}:{url[:8]}",
        "dataset_id": dataset,
        "source_record_id": url[:12],
        "source_group": source_group,
        "source_artifact_sha256": artifact,
        "ground_truth": label,
        "label_status": status,
        "label_source": "VERIFIED_SOURCE_REVIEW" if label is not None else None,
        "observed_at": "2026-09-24T12:00:00Z",
        "hostname": host,
        "origin": f"https://{host}",
        "domain_group": host,
        "brand_group": None,
        "url_sha256": url,
        "origin_path_sha256": origin_path,
        "redacted_url": f"https://{host}/login?token=%2A",
        "redistribution_allowed": False,
        "local_only": True,
    }


def batch(dataset: str, source_group: str, artifact: str, rows: list[dict]) -> dict:
    return {
        "schema_version": "stage-b-ingestion-batch-1",
        "dataset_id": dataset,
        "adapter": "fixture",
        "source_artifact": {
            "path_name": f"{dataset}.txt",
            "sha256": artifact,
            "provider": dataset,
            "retrieved_at": "2026-09-24T12:00:00Z",
            "independence_group": source_group,
        },
        "stats": {},
        "records": rows,
        "limitations": [],
    }


def test_exact_duplicate_same_verified_label_is_collapsed_with_full_source_lineage():
    url = "a" * 64
    path = "b" * 64
    left = record(dataset="phishtank", source_group="pt", artifact="1" * 64,
                  url=url, origin_path=path, label=1, status="VERIFIED_SOURCE_LABEL")
    right = record(dataset="openphish", source_group="op", artifact="2" * 64,
                   url=url, origin_path=path, label=1, status="VERIFIED_SOURCE_LABEL")

    result = reconcile_ingestion_batches([
        batch("phishtank", "pt", "1" * 64, [left]),
        batch("openphish", "op", "2" * 64, [right]),
    ])

    assert result["stats"]["canonical_records"] == 1
    assert result["stats"]["duplicate_records_removed"] == 1
    assert result["quarantine"] == []
    row = result["records"][0]
    assert row["ground_truth"] == 1
    assert row["source_datasets"] == ["openphish", "phishtank"]
    assert row["source_groups"] == ["op", "pt"]
    assert row["duplicate_count"] == 2
    assert row["artifact_group"].startswith("artifact-")


def test_opposing_verified_labels_quarantine_entire_artifact_cluster():
    url = "c" * 64
    path = "d" * 64
    phish = record(dataset="phish", source_group="p", artifact="3" * 64,
                   url=url, origin_path=path, label=1, status="VERIFIED_SOURCE_LABEL")
    legit = record(dataset="legit", source_group="l", artifact="4" * 64,
                   url=url, origin_path=path, label=0, status="VERIFIED_SOURCE_LABEL")

    result = reconcile_ingestion_batches([
        batch("phish", "p", "3" * 64, [phish]),
        batch("legit", "l", "4" * 64, [legit]),
    ])

    assert result["records"] == []
    assert result["stats"]["verified_label_conflicts"] == 1
    assert result["stats"]["quarantined_records"] == 2
    assert result["quarantine"][0]["reasons"] == ["VERIFIED_LABEL_CONFLICT"]
    assert result["quarantine"][0]["labels"] == [0, 1]


def test_query_variants_share_artifact_group_so_future_split_cannot_separate_them():
    path = "e" * 64
    first = record(dataset="feed", source_group="f", artifact="5" * 64,
                   url="f" * 64, origin_path=path, label=1, status="VERIFIED_SOURCE_LABEL")
    second = record(dataset="feed", source_group="f", artifact="5" * 64,
                    url="0" * 64, origin_path=path, label=1, status="VERIFIED_SOURCE_LABEL")

    result = reconcile_ingestion_batches([batch("feed", "f", "5" * 64, [first, second])])

    assert len(result["records"]) == 2
    assert result["stats"]["origin_path_variant_groups"] == 1
    assert len({row["artifact_group"] for row in result["records"]}) == 1


def test_same_raw_source_artifact_cannot_masquerade_as_two_independent_sources():
    shared_artifact = "6" * 64
    left = record(dataset="mirror-a", source_group="independent-a", artifact=shared_artifact,
                  url="1" * 64, origin_path="2" * 64, label=1, status="VERIFIED_SOURCE_LABEL")
    right = record(dataset="mirror-b", source_group="independent-b", artifact=shared_artifact,
                   url="3" * 64, origin_path="4" * 64, label=1, status="VERIFIED_SOURCE_LABEL")

    result = reconcile_ingestion_batches([
        batch("mirror-a", "independent-a", shared_artifact, [left]),
        batch("mirror-b", "independent-b", shared_artifact, [right]),
    ])

    assert result["records"] == []
    assert result["stats"]["source_independence_conflicts"] == 1
    assert result["stats"]["quarantined_records"] == 2
    assert {tuple(item["reasons"]) for item in result["quarantine"]} == {
        ("SOURCE_INDEPENDENCE_VIOLATION",),
    }


def test_verified_label_wins_over_unlabeled_candidate_only_for_same_exact_url():
    url = "7" * 64
    path = "8" * 64
    verified = record(dataset="verified", source_group="v", artifact="7" * 64,
                      url=url, origin_path=path, label=1, status="VERIFIED_SOURCE_LABEL")
    candidate = record(dataset="candidate", source_group="c", artifact="8" * 64,
                       url=url, origin_path=path, label=None, status="UNLABELED_CANDIDATE")

    result = reconcile_ingestion_batches([
        batch("verified", "v", "7" * 64, [verified]),
        batch("candidate", "c", "8" * 64, [candidate]),
    ])

    assert result["quarantine"] == []
    assert len(result["records"]) == 1
    assert result["records"][0]["ground_truth"] == 1
    assert result["records"][0]["label_status"] == "VERIFIED_SOURCE_LABEL"
    assert result["records"][0]["source_datasets"] == ["candidate", "verified"]


def test_reconciliation_rejects_records_that_reintroduce_raw_url_material():
    row = record(dataset="bad", source_group="b", artifact="9" * 64,
                 url="9" * 64, origin_path="a" * 64, label=1, status="VERIFIED_SOURCE_LABEL")
    row["canonical_url"] = "https://example.test/login?token=secret"

    with pytest.raises(ReconciliationError, match="unexpected record fields"):
        reconcile_ingestion_batches([batch("bad", "b", "9" * 64, [row])])
