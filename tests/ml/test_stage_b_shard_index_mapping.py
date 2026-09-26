from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ml.data.stage_b_temporal_coverage import (
    MetaRecord,
    Shard,
    TemporalCoveragePlanError,
    apply_verified_shard_index,
)


def shard(name, start, end, md5):
    return Shard(name, "phishing", start, end, "", 1, md5)


def record(value):
    return MetaRecord(
        ordinal=value,
        record_key=f"{value:024x}",
        klass="phishing",
        observed_at=datetime(2023, 1, 1, tzinfo=timezone.utc),
        domain_group=f"d{value}.example",
        brand_group=f"b{value}",
        shard_name="unverified",
    )


def test_exact_shard_index_reconciles_csv_ids_and_assigns_real_shards():
    shards = [
        shard("p1.zip", 1, 2, "a" * 32),
        shard("p2.zip", 3, 4, "b" * 32),
    ]
    index = {
        "schema_version": "stage-b-zenodo-shard-index-1",
        "status": "PASS",
        "shards": [
            {
                "name": "p1.zip", "class": "phishing",
                "range": [1, 2], "md5": "a" * 32,
                "record_ids": [f"{3:024x}", f"{1:024x}"],
            },
            {
                "name": "p2.zip", "class": "phishing",
                "range": [3, 4], "md5": "b" * 32,
                "record_ids": [f"{2:024x}", f"{4:024x}"],
            },
        ],
    }
    remapped, report = apply_verified_shard_index(
        [record(1), record(2), record(3), record(4)],
        shards,
        klass="phishing",
        shard_index=index,
    )
    assert report["exact_match"] is True
    assigned = {int(r.record_key, 16): r.shard_name for r in remapped}
    assert assigned == {1: "p1.zip", 2: "p2.zip", 3: "p1.zip", 4: "p2.zip"}


def test_exact_shard_index_rejects_missing_csv_id():
    shards = [shard("p1.zip", 1, 2, "a" * 32)]
    index = {
        "schema_version": "stage-b-zenodo-shard-index-1",
        "status": "PASS",
        "shards": [{
            "name": "p1.zip", "class": "phishing",
            "range": [1, 2], "md5": "a" * 32,
            "record_ids": [f"{1:024x}", f"{99:024x}"],
        }],
    }
    with pytest.raises(TemporalCoveragePlanError, match="reconciliation failed"):
        apply_verified_shard_index(
            [record(1), record(2)],
            shards,
            klass="phishing",
            shard_index=index,
        )
