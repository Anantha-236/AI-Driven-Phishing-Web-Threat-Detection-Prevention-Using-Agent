from __future__ import annotations

import csv
from pathlib import Path

from ml.data.stage_b_phishing_tenant_host import build_phishing_tenant_host_plan


def normalized_plan():
    return {
        "schema_version": "stage-b-archive-replay-normalized-1",
        "plan_id": "fixture",
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "dataset": {
            "independence_group": "fixture-source",
        },
        "items": [
            {
                "sample_id": "zenodo-8041387:phishing:aaaaaaaaaaaaaaaaaaaaaaaa",
                "ground_truth": 1,
                "domain_group": "workers.dev",
                "brand_group": "microsoft",
                "artifact_sha256": "a" * 64,
                "observed_at": "2023-01-01T00:00:00+00:00",
                "source_group": "fixture-source",
            },
            {
                "sample_id": "zenodo-8041387:phishing:bbbbbbbbbbbbbbbbbbbbbbbb",
                "ground_truth": 1,
                "domain_group": "workers.dev",
                "brand_group": "paypal",
                "artifact_sha256": "b" * 64,
                "observed_at": "2023-01-02T00:00:00+00:00",
                "source_group": "fixture-source",
            },
            {
                "sample_id": "zenodo-8041387:legitimate:cccccccccccccccccccccccc",
                "ground_truth": 0,
                "domain_group": "example.com",
                "brand_group": "example.com",
                "artifact_sha256": "c" * 64,
                "observed_at": "2023-01-03T00:00:00+00:00",
                "source_group": "fixture-source",
            },
        ],
    }


def write_csv(path: Path):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["_id", "url"])
        writer.writeheader()
        writer.writerow({
            "_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
            "url": "https://tenant-one.workers.dev/login",
        })
        writer.writerow({
            "_id": "bbbbbbbbbbbbbbbbbbbbbbbb",
            "url": "https://tenant-two.workers.dev/auth",
        })


def test_rewrites_only_phishing_domain_group(tmp_path: Path):
    csv_path = tmp_path / "phishing.csv"
    write_csv(csv_path)

    plan, report = build_phishing_tenant_host_plan(normalized_plan(), csv_path)

    assert plan["items"][0]["domain_group"] == "tenant-one.workers.dev"
    assert plan["items"][1]["domain_group"] == "tenant-two.workers.dev"
    assert plan["items"][2]["domain_group"] == "example.com"
    assert plan["items"][0]["brand_group"] == "microsoft"
    assert report["changed_domain_groups"] == 2


def test_experiment_remains_research_only(tmp_path: Path):
    csv_path = tmp_path / "phishing.csv"
    write_csv(csv_path)
    _, report = build_phishing_tenant_host_plan(normalized_plan(), csv_path)
    assert report["research_only"] is True
    assert report["deployment_authorized"] is False
