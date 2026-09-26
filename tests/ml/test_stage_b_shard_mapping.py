from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ml.data.stage_b_temporal_coverage import (
    MetaRecord,
    Shard,
    TemporalCoveragePlanError,
    infer_shard_mapping_from_reference,
)


def make_records():
    base = datetime(2023, 1, 1, tzinfo=timezone.utc)
    # CSV order intentionally differs from archive construction order.
    ids = [5, 1, 9, 2, 10, 3, 11, 4, 12, 6, 8, 7]
    rows = []
    for ordinal, value in enumerate(ids, start=1):
        rows.append(MetaRecord(
            ordinal=ordinal,
            record_key=f"{value:024x}",
            klass="phishing",
            # Deliberately scramble date order so ObjectID ordering is the only
            # exact strategy for the reference tail.
            observed_at=base + timedelta(days=(value * 7) % 11),
            domain_group=f"d{value}.example",
            brand_group=f"brand-{value}",
            shard_name="unverified",
        ))
    return rows


def shards():
    return [
        Shard("phishing_0001-0006.zip", "phishing", 1, 6, "", 1, "a" * 32),
        Shard("phishing_0007-0012.zip", "phishing", 7, 12, "", 1, "b" * 32),
    ]


def write_reference(root: Path, values):
    for value in values:
        d = root / f"{value:024x}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "index.html").write_text("<html></html>", encoding="utf-8")


def test_infers_objectid_lexicographic_shard_order_from_known_tail(tmp_path: Path):
    reference = tmp_path / "tail"
    write_reference(reference, range(7, 13))

    remapped, report = infer_shard_mapping_from_reference(
        root=reference,
        shard=shards()[1],
        records=make_records(),
        shards=shards(),
    )

    assert report["exact_match"] is True
    assert report["chosen_strategy"] == "record_key_lexicographic"
    tail = {
        int(record.record_key, 16)
        for record in remapped
        if record.shard_name == "phishing_0007-0012.zip"
    }
    assert tail == set(range(7, 13))


def test_rejects_reference_that_matches_no_supported_ordering(tmp_path: Path):
    reference = tmp_path / "tail"
    # Same width, but a deliberately incompatible mixed set.
    write_reference(reference, [1, 3, 5, 8, 10, 12])

    with pytest.raises(TemporalCoveragePlanError, match="no deterministic shard ordering"):
        infer_shard_mapping_from_reference(
            root=reference,
            shard=shards()[1],
            records=make_records(),
            shards=shards(),
        )
