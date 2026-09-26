from __future__ import annotations

from copy import deepcopy

import pytest

from ml.evaluation.stage_b_scaled_replay import (
    ScaledReplayError,
    batch_raw_plan,
    canonical_hash,
    merge_batch_episodes,
    validate_batch_episode_output,
)


def raw_plan(count=5):
    return {
        "schema_version": "stage-b-archive-replay-plan-1",
        "plan_id": "plan-1",
        "created_at": "2026-09-25T00:00:00Z",
        "dataset": {
            "dataset_id": "dataset",
            "provider": "provider",
            "source_reference": "source",
            "source_snapshot_sha256": "a" * 64,
            "independence_group": "source-group",
            "license_reference": "research",
            "research_use_allowed": True,
        },
        "items": [
            {
                "sample_id": f"sample-{i:03d}",
                "html_path": f"sample-{i:03d}.html",
                "ground_truth": i % 2,
                "observed_at": "2023-01-01T00:00:00Z",
                "artifact_sha256": f"{i+1:064x}",
                "domain_group": f"d{i}.example",
                "brand_group": f"b{i}",
                "source_group": "source-group",
                "wait_ms": 600,
            }
            for i in range(count)
        ],
    }


def episode_for(sample_id):
    events = [{
        "event_type": "DOCUMENT_STARTED",
        "event_seq": 1,
        "schema_version": "1.2.0",
        "session_id": "s",
        "tab_id": 1,
        "frame_id": 0,
        "timestamp_ms": 1,
    }]
    return {
        "sample_id": sample_id,
        "events_sha256": canonical_hash(events),
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "observation_horizon_ms": 600,
        "dropped_events": 0,
        "delivery_errors": 0,
        "external_requests_blocked": 0,
        "events": events,
    }


def batch_output(plan):
    return {
        "schema_version": "stage-b-event-episodes-1",
        "collector_version": "stage-b-archive-replay-1",
        "plan_sha256": "x" * 64,
        "source_hashes": {"collector_js_sha256": "a" * 64},
        "safety_policy": {"archived_local_files_only": True},
        "episodes": [episode_for(row["sample_id"]) for row in plan["items"]],
        "failures": [],
    }


def test_batching_is_deterministic_and_complete():
    plan = raw_plan(7)
    first = batch_raw_plan(plan, batch_size=3)
    second = batch_raw_plan(deepcopy(plan), batch_size=3)
    assert first == second
    assert [len(x["items"]) for x in first] == [3, 3, 1]
    assert [row["sample_id"] for b in first for row in b["items"]] == sorted(
        row["sample_id"] for row in plan["items"]
    )


def test_valid_batch_episode_output_requires_exact_sample_set():
    plan = batch_raw_plan(raw_plan(3), batch_size=3)[0]
    result = validate_batch_episode_output(batch_output(plan), plan)
    assert result["status"] == "PASS"
    assert result["samples"] == 3


def test_batch_episode_rejects_missing_sample():
    plan = batch_raw_plan(raw_plan(3), batch_size=3)[0]
    output = batch_output(plan)
    output["episodes"].pop()
    with pytest.raises(ScaledReplayError, match="sample set mismatch"):
        validate_batch_episode_output(output, plan)


def test_batch_episode_rejects_dropped_events():
    plan = batch_raw_plan(raw_plan(1), batch_size=1)[0]
    output = batch_output(plan)
    output["episodes"][0]["dropped_events"] = 1
    with pytest.raises(ScaledReplayError, match="dropped events"):
        validate_batch_episode_output(output, plan)


def test_merge_is_exact_and_sorted():
    batches = batch_raw_plan(raw_plan(5), batch_size=2)
    outputs = [batch_output(batch) for batch in batches]
    merged = merge_batch_episodes(outputs, batches, source_plan_sha256="f" * 64)
    assert merged["schema_version"] == "stage-b-event-episodes-1"
    assert merged["failures"] == []
    assert len(merged["episodes"]) == 5
    assert [row["sample_id"] for row in merged["episodes"]] == sorted(
        row["sample_id"] for row in merged["episodes"]
    )


def test_merge_rejects_collector_source_change():
    batches = batch_raw_plan(raw_plan(4), batch_size=2)
    outputs = [batch_output(batch) for batch in batches]
    outputs[1]["source_hashes"] = {"collector_js_sha256": "b" * 64}
    with pytest.raises(ScaledReplayError, match="source hashes"):
        merge_batch_episodes(outputs, batches, source_plan_sha256="f" * 64)
