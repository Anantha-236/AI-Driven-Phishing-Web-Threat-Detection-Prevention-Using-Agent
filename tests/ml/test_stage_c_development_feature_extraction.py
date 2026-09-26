from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

import ml.data.stage_c_development_feature_extraction as mod
from ml.data.stage_c_development_feature_extraction import StageCFeatureExtractionError


def r(sample, artifact, nested="part.zip", partition="train", label=0):
    return {
        "sample_id": sample,
        "partition": partition,
        "label": label,
        "html_sha256": artifact,
        "nested_archive": nested,
        "member_name": f"{sample}.html",
        "html_size_bytes": 10,
    }


def test_batch_scheduler_replays_every_sample_once_and_separates_duplicates():
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    rows = [r("s1", a), r("s2", a), r("s3", b), r("s4", c), r("s5", a)]
    batches = mod.build_replay_batches(rows, batch_size=3)
    flattened = [x["sample_id"] for batch in batches for x in batch["rows"]]
    assert sorted(flattened) == ["s1", "s2", "s3", "s4", "s5"]
    for batch in batches:
        hashes = [x["html_sha256"] for x in batch["rows"]]
        assert len(hashes) == len(set(hashes))


def test_batch_scheduler_separates_nested_archives():
    rows = [r("s1", "a" * 64, "p1.zip"), r("s2", "b" * 64, "p2.zip")]
    batches = mod.build_replay_batches(rows, batch_size=10)
    assert len(batches) == 2
    assert {b["nested_archive"] for b in batches} == {"p1.zip", "p2.zip"}


def test_batch_scheduler_is_deterministic():
    rows = [r("s3", "c" * 64), r("s1", "a" * 64), r("s2", "b" * 64)]
    a = mod.build_replay_batches(rows, batch_size=2)
    b = mod.build_replay_batches(list(reversed(rows)), batch_size=2)
    view = lambda batches: [
        (x["batch_id"], [y["sample_id"] for y in x["rows"]]) for x in batches
    ]
    assert view(a) == view(b)


def test_batch_size_guard():
    with pytest.raises(StageCFeatureExtractionError):
        mod.build_replay_batches([], batch_size=0)
    with pytest.raises(StageCFeatureExtractionError):
        mod.build_replay_batches([], batch_size=1001)


def test_feature_row_is_closed_schema():
    row = {"sample_id": "s", "partition": "train", "label": 0, "feature_vector": [0] * 27}
    mod._validate_feature_row(row)
    bad = deepcopy(row)
    bad["raw_url"] = "https://example.invalid"
    with pytest.raises(StageCFeatureExtractionError, match="prohibited"):
        mod._validate_feature_row(bad)


def test_feature_row_rejects_nonfinite():
    row = {"sample_id": "s", "partition": "train", "label": 0, "feature_vector": [0] * 26 + [float("nan")]}
    with pytest.raises(StageCFeatureExtractionError, match="NaN"):
        mod._validate_feature_row(row)


def test_frozen_text_is_idempotent_and_refuses_drift(tmp_path):
    path = tmp_path / "x.jsonl"
    assert mod._atomic_frozen_text(path, b"one\n") == "CREATED"
    assert mod._atomic_frozen_text(path, b"one\n") == "EXISTING_MATCH"
    with pytest.raises(StageCFeatureExtractionError, match="non-identical"):
        mod._atomic_frozen_text(path, b"two\n")


def test_checkpoint_pair_incomplete_is_rejected(tmp_path):
    batch = {
        "batch_id": "batch-00001-test",
        "sample_count": 1,
        "sample_set_sha256": mod.canonical_hash(["s1"]),
        "artifact_set_sha256": mod.canonical_hash(["a" * 64]),
        "rows": [r("s1", "a" * 64)],
    }
    f, _ = mod._checkpoint_paths(tmp_path, batch["batch_id"])
    f.parent.mkdir(parents=True)
    f.write_text("{}\n", encoding="utf-8")
    with pytest.raises(StageCFeatureExtractionError, match="incomplete checkpoint pair"):
        mod._verify_checkpoint(output_root=tmp_path, batch=batch, state_sha256="x" * 64)


def test_exact_production_feature_order_constant():
    assert len(mod.EXPECTED_FEATURES) == 27
    assert mod.EXPECTED_FEATURES[:5] == [
        "document_started", "has_password", "has_otp", "has_payment", "has_identity"
    ]
    assert mod.EXPECTED_FEATURES[20:23] == [
        "unknown_document_ratio", "known_target_ratio", "contradiction_count"
    ]
    assert mod.canonical_hash({
        "feature_version": "context-features-1",
        "feature_names": mod.EXPECTED_FEATURES,
    }) == mod.EXPECTED_FEATURE_CONTRACT_SHA256


def test_authorization_hash_is_frozen():
    assert mod.EXPECTED_AUTHORIZATION_SHA256 == (
        "b83f7038a98704465b4097b7f0b54d3ae62f9d72caa5ec31eb82b4d031bda27b"
    )


def test_module_has_no_training_dependency_or_final_dataset_reference():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src
    assert "compphish" not in src
    assert "fmbs4kp9wz" not in src


def test_memory_plan_never_persists_source_url_brand_or_disk_path():
    batch = {
        "batch_id": "batch-1",
        "rows": [r("s1", "a" * 64)],
    }
    plan = mod._memory_plan(batch, wait_ms=250)
    item = plan["items"][0]
    assert set(item) == {"sample_id", "ground_truth", "artifact_sha256", "wait_ms"}
    assert "url" not in item
    assert "brand_group" not in item
    assert "html_path" not in item

