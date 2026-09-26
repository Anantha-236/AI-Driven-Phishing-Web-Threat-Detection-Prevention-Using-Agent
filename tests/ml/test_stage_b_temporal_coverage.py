from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ml.data.stage_b_temporal_coverage import (
    MetaRecord,
    Shard,
    TemporalCoveragePlanError,
    build_temporal_coverage_plan,
    load_inventory,
    validate_readiness_targets,
)


def inventory():
    files = []
    for klass, prefix, total in (
        ("phishing", "phishing", 1500),
        ("legitimate", "not-phishing", 1500),
    ):
        for i, start in enumerate((1, 501, 1001)):
            end = min(start + 499, total)
            files.append({
                "name": f"{prefix}_{start:04d}-{end:04d}.zip",
                "kind": "archive",
                "class": klass,
                "start": start,
                "end": end,
                "size_display": f"{i + 1} GB",
                "size_bytes_estimated": (i + 1) * 1_000_000_000,
                "md5": f"{i + (1 if klass == 'phishing' else 8):032x}"[-32:],
            })
    return {
        "schema_version": "zenodo-8041387-full-file-inventory-1",
        "files": files,
    }


def records(klass: str, shards: list[Shard], count=1500):
    base = datetime(2023, 1, 1, tzinfo=timezone.utc)
    result = []
    for ordinal in range(1, count + 1):
        shard = next(s for s in shards if s.start <= ordinal <= s.end)
        result.append(MetaRecord(
            ordinal=ordinal,
            record_key=f"{ordinal:024x}",
            klass=klass,
            observed_at=base + timedelta(hours=ordinal),
            domain_group=f"d-{klass}-{ordinal}.example",
            brand_group=f"b-{klass}-{ordinal}",
            shard_name=shard.name,
        ))
    return result


def policy():
    return {
        "schema_version": "stage-b-readiness-policy-1",
        "min_samples_per_class": {
            "train": 100,
            "selection": 50,
            "calibration": 50,
            "test": 100,
        },
    }


def test_readiness_target_is_derived_from_policy_and_split_fractions():
    result = validate_readiness_targets(policy(), reserve_fraction=0.20)
    assert result["fraction_implied_supervised_target_per_class"] == 1000
    assert result["candidate_metadata_target_per_class"] == 1250
    assert result["candidate_post_cutoff_target_per_class"] == 125
    assert result["binding_partition"] == "test"


def test_inventory_must_be_contiguous_and_cover_real_dataset_totals():
    realish = {
        "schema_version": "zenodo-8041387-full-file-inventory-1",
        "files": [
            {
                "name": "phishing_0001-5151.zip",
                "kind": "archive", "class": "phishing",
                "start": 1, "end": 5151,
                "size_display": "1 GB", "size_bytes_estimated": 1,
                "md5": "a" * 32,
            },
            {
                "name": "not-phishing_0001-5244.zip",
                "kind": "archive", "class": "legitimate",
                "start": 1, "end": 5244,
                "size_display": "1 GB", "size_bytes_estimated": 1,
                "md5": "b" * 32,
            },
        ],
    }
    loaded = load_inventory(realish)
    assert loaded["phishing"][0].end == 5151
    assert loaded["legitimate"][0].end == 5244


def test_planner_treats_existing_shard_as_zero_marginal_cost(monkeypatch):
    # Adapt synthetic inventory to the real expected totals while making only
    # the first three shards carry records relevant to this unit test.
    inv = {
        "phishing": [
            Shard("p1.zip", "phishing", 1, 500, "", 3_000, "1"*32),
            Shard("p2.zip", "phishing", 501, 1000, "", 2_000, "2"*32),
            Shard("p3.zip", "phishing", 1001, 1500, "", 1_000, "3"*32),
        ],
        "legitimate": [
            Shard("l1.zip", "legitimate", 1, 500, "", 3_000, "4"*32),
            Shard("l2.zip", "legitimate", 501, 1000, "", 2_000, "5"*32),
            Shard("l3.zip", "legitimate", 1001, 1500, "", 1_000, "6"*32),
        ],
    }
    p = records("phishing", inv["phishing"])
    l = records("legitimate", inv["legitimate"])
    targets = {
        "candidate_metadata_target_per_class": 1000,
        "candidate_pre_cutoff_target_per_class": 750,
        "candidate_post_cutoff_target_per_class": 250,
    }
    plan = build_temporal_coverage_plan(
        phishing_records=p,
        legitimate_records=l,
        inventory=inv,
        targets=targets,
        existing_shards={"p1.zip", "l1.zip"},
        max_cutoff_candidates=64,
    )
    assert plan["status"] == "PASS"
    assert "p1.zip" in plan["existing_shards_used"]
    assert "l1.zip" in plan["existing_shards_used"]
    assert all(row["name"] not in {"p1.zip", "l1.zip"} for row in plan["download_recommendations"])


def test_planner_requires_shared_late_class_coverage():
    inv = {
        "phishing": [Shard("p.zip", "phishing", 1, 400, "", 1, "a"*32)],
        "legitimate": [Shard("l.zip", "legitimate", 1, 400, "", 1, "b"*32)],
    }
    base = datetime(2023, 1, 1, tzinfo=timezone.utc)
    p = [
        MetaRecord(i, str(i), "phishing", base + timedelta(days=i),
                   f"p{i}.example", f"p{i}", "p.zip")
        for i in range(1, 401)
    ]
    # Legitimate ends very early; there is no useful shared strict-forward tail.
    l = [
        MetaRecord(i, str(i), "legitimate", base + timedelta(minutes=i),
                   f"l{i}.example", f"l{i}", "l.zip")
        for i in range(1, 401)
    ]
    targets = {
        "candidate_metadata_target_per_class": 300,
        "candidate_pre_cutoff_target_per_class": 200,
        "candidate_post_cutoff_target_per_class": 100,
    }
    with pytest.raises(TemporalCoveragePlanError):
        build_temporal_coverage_plan(
            phishing_records=p,
            legitimate_records=l,
            inventory=inv,
            targets=targets,
            existing_shards=set(),
            max_cutoff_candidates=64,
        )


def test_plan_contains_group_metadata_not_raw_urls():
    inv = {
        "phishing": [Shard("p.zip", "phishing", 1, 300, "", 1, "a"*32)],
        "legitimate": [Shard("l.zip", "legitimate", 1, 300, "", 1, "b"*32)],
    }
    base = datetime(2023, 1, 1, tzinfo=timezone.utc)
    p = [
        MetaRecord(i, str(i), "phishing", base + timedelta(hours=i),
                   f"phish-{i}.example", f"brand-{i}", "p.zip")
        for i in range(1, 301)
    ]
    l = [
        MetaRecord(i, str(i), "legitimate", base + timedelta(hours=i),
                   f"legit-{i}.example", f"legit-{i}.example", "l.zip")
        for i in range(1, 301)
    ]
    targets = {
        "candidate_metadata_target_per_class": 250,
        "candidate_pre_cutoff_target_per_class": 200,
        "candidate_post_cutoff_target_per_class": 50,
    }
    plan = build_temporal_coverage_plan(
        phishing_records=p,
        legitimate_records=l,
        inventory=inv,
        targets=targets,
        existing_shards=set(),
        max_cutoff_candidates=64,
    )
    rendered = str(plan)
    assert "http://" not in rendered
    assert "https://" not in rendered
