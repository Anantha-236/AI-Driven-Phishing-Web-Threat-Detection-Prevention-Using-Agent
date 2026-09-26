from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ml.evaluation.stage_b_contextual_replay_v2 import (
    PROTOCOL_ID,
    ScaledReplayError,
    build_collector_plan_from_v2_normalized,
    checkpoint_sources_match,
    validate_task28_outputs,
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized(root: Path):
    items = []
    for i, label in enumerate((0, 1, 0, 1)):
        path = root / f"s{i}.html"
        data = f"<html>{i}</html>".encode()
        path.write_bytes(data)
        items.append({
            "sample_id": f"s{i}",
            "html_path": path.name,
            "ground_truth": label,
            "observed_at": f"2023-01-0{i+1}T00:00:00+00:00",
            "artifact_sha256": sha(data),
            "domain_group": f"tenant-{i}.workers.dev",
            "brand_group": "microsoft" if label else "legit",
            "source_group": "source",
            "wait_ms": 600,
        })
    return {
        "schema_version": "stage-b-archive-replay-normalized-1",
        "plan_id": "v2-normalized",
        "created_at": "2026-09-26T00:00:00Z",
        "dataset": {
            "dataset_id": "fixture",
            "provider": "fixture",
            "source_reference": "fixture",
            "source_snapshot_sha256": "a" * 64,
            "independence_group": "source",
            "license_reference": "research",
            "research_use_allowed": True,
        },
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "items": items,
        "safety_contract": {
            "local_files_only": True,
        },
    }


def raw_from(normalized_plan):
    return {
        "schema_version": "stage-b-archive-replay-plan-1",
        "plan_id": "old-v1-raw",
        "created_at": normalized_plan["created_at"],
        "dataset": dict(normalized_plan["dataset"]),
        "items": [
            {
                **{
                    k: row[k]
                    for k in (
                        "sample_id", "html_path", "ground_truth",
                        "observed_at", "artifact_sha256", "brand_group",
                        "source_group", "wait_ms",
                    )
                },
                # Deliberately stale v1 domain grouping.
                "domain_group": "workers.dev",
            }
            for row in normalized_plan["items"]
        ],
    }


def splits(normalized_plan):
    names = ("train", "selection", "calibration", "test")
    parts = {}
    for name, row in zip(names, normalized_plan["items"], strict=True):
        parts[name] = {
            "sample_count": 1,
            "legitimate": int(row["ground_truth"] == 0),
            "phishing": int(row["ground_truth"] == 1),
            "records": [{
                "sample_id": row["sample_id"],
                "partition": name,
                "ground_truth": row["ground_truth"],
                "artifact_group": row["artifact_sha256"],
                "domain_group": row["domain_group"],
                "brand_group": row["brand_group"],
                "source_groups": ["source"],
                "observed_at": row["observed_at"],
            }],
        }
    return {
        "schema_version": "stage-b-splits-1",
        "partitions": parts,
        "audit": {
            "protocol_id": PROTOCOL_ID,
            "research_only": True,
            "deployment_authorized": False,
            "strict_forward_test": True,
            "isolation_dimensions": ["artifact_group", "domain_group"],
            "audit_only_dimensions": ["brand_group"],
        },
    }


def report(samples=4):
    return {
        "schema_version": "stage-b-contextual-research-v2-report-1",
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "protocol_id": PROTOCOL_ID,
        "active_isolation_dimensions": ["artifact_group", "domain_group"],
        "audit_only_dimensions": ["brand_group"],
        "supervised_samples": samples,
    }


def write_protocol_files(root: Path, raw, norm, split, rep):
    import json
    (root / "supervised-replay-plan.json").write_text(json.dumps(raw))
    (root / "supervised-replay-plan.normalized.json").write_text(
        json.dumps(norm)
    )
    (root / "research-splits.json").write_text(json.dumps(split))
    (root / "contextual-v2-report.json").write_text(json.dumps(rep))


def test_collector_plan_uses_v2_exact_host_metadata(tmp_path: Path):
    norm = normalized(tmp_path)
    raw = raw_from(norm)
    collector = build_collector_plan_from_v2_normalized(norm)
    assert raw["items"][0]["domain_group"] == "workers.dev"
    assert (
        collector["items"][0]["domain_group"]
        == norm["items"][0]["domain_group"]
    )
    assert collector["plan_id"].endswith("-collector")


def test_task28_preflight_accepts_stale_raw_domain_but_reconciles_v2(
    tmp_path: Path,
):
    archive = tmp_path / "archive"
    protocol = tmp_path / "protocol"
    archive.mkdir()
    protocol.mkdir()
    norm = normalized(archive)
    raw = raw_from(norm)
    split = splits(norm)
    rep = report()
    write_protocol_files(protocol, raw, norm, split, rep)

    result, collector = validate_task28_outputs(
        protocol_root=protocol,
        archive_root=archive,
        raw_plan=raw,
        normalized_plan=norm,
        splits=split,
        report=rep,
    )
    assert result["status"] == "PASS"
    assert result["samples"] == 4
    assert collector["items"][1]["domain_group"] == "tenant-1.workers.dev"


def test_task28_preflight_rejects_split_metadata_drift(tmp_path: Path):
    archive = tmp_path / "archive"
    protocol = tmp_path / "protocol"
    archive.mkdir()
    protocol.mkdir()
    norm = normalized(archive)
    raw = raw_from(norm)
    split = splits(norm)
    split["partitions"]["train"]["records"][0]["domain_group"] = "wrong.example"
    rep = report()
    write_protocol_files(protocol, raw, norm, split, rep)

    with pytest.raises(ScaledReplayError, match="metadata mismatch"):
        validate_task28_outputs(
            protocol_root=protocol,
            archive_root=archive,
            raw_plan=raw,
            normalized_plan=norm,
            splits=split,
            report=rep,
        )


def test_task28_preflight_rejects_wrong_protocol(tmp_path: Path):
    archive = tmp_path / "archive"
    protocol = tmp_path / "protocol"
    archive.mkdir()
    protocol.mkdir()
    norm = normalized(archive)
    raw = raw_from(norm)
    split = splits(norm)
    rep = report()
    rep["protocol_id"] = "wrong"
    write_protocol_files(protocol, raw, norm, split, rep)

    with pytest.raises(ScaledReplayError, match="protocol_id"):
        validate_task28_outputs(
            protocol_root=protocol,
            archive_root=archive,
            raw_plan=raw,
            normalized_plan=norm,
            splits=split,
            report=rep,
        )


def test_task28_preflight_rejects_sample_count_mismatch(tmp_path: Path):
    archive = tmp_path / "archive"
    protocol = tmp_path / "protocol"
    archive.mkdir()
    protocol.mkdir()
    norm = normalized(archive)
    raw = raw_from(norm)
    split = splits(norm)
    rep = report(samples=999)
    write_protocol_files(protocol, raw, norm, split, rep)

    with pytest.raises(ScaledReplayError, match="sample count"):
        validate_task28_outputs(
            protocol_root=protocol,
            archive_root=archive,
            raw_plan=raw,
            normalized_plan=norm,
            splits=split,
            report=rep,
        )


def test_checkpoint_source_hash_guard_rejects_stale_build():
    old = {
        "source_hashes": {
            "collector_js_sha256": "a" * 64,
            "service_worker_js_sha256": "b" * 64,
            "tsfeg_source_sha256": "c" * 64,
        }
    }
    expected = {
        "collector_js_sha256": "a" * 64,
        "service_worker_js_sha256": "b" * 64,
        "tsfeg_source_sha256": "d" * 64,
    }
    assert checkpoint_sources_match(old, old["source_hashes"]) is True
    assert checkpoint_sources_match(old, expected) is False
