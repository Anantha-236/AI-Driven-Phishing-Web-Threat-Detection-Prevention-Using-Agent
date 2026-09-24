from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ml.data.stage_b_features import (
    FeatureMaterializationError,
    materialize_feature_dataset,
    validate_feature_dataset,
)


def h(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def event(event_type="DOCUMENT_STARTED", **overrides):
    base = {
        "event_type": event_type,
        "sensitive_type": None,
        "field_id": None,
        "form_id": None,
        "frame_origin": "https://example.test",
        "target_origin": None,
        "destination_origin": None,
        "initiator_origin": None,
        "request_type": None,
        "interaction_type": None,
        "timestamp_ms": 1000,
        "schema_version": "1.2.0",
        "session_id": "session-1",
        "tab_id": 1,
        "document_id": "doc-1",
        "frame_id": 0,
        "parent_frame_id": None,
        "event_seq": 1,
        "received_ms": 1001,
        "trust": "ISOLATED_CONTENT_SCRIPT",
        "confidence": 1,
    }
    base.update(overrides)
    return base


def splits():
    parts = {}
    for i, name in enumerate(["train", "selection", "calibration", "test"]):
        parts[name] = {
            "records": [{
                "sample_id": f"sample-{name}",
                "ground_truth": i % 2,
                "artifact_group": f"artifact-{name}",
                "domain_group": f"{name}.example",
                "brand_group": f"brand-{name}",
                "source_groups": [f"source-{name}"],
                "observed_at": f"2026-09-{20+i:02d}T12:00:00Z",
            }]
        }
    return {"schema_version": "stage-b-splits-1", "partitions": parts, "excluded_unlabeled": []}


def episodes():
    rows = []
    for name in ["train", "selection", "calibration", "test"]:
        evs = [event(), event("FIELD_DISCOVERED", event_seq=2, sensitive_type="PASSWORD", field_id="e-1")]
        rows.append({
            "sample_id": f"sample-{name}",
            "events": evs,
            "events_sha256": h(evs),
            "collection_provenance": "REAL_BROWSER",
        })
    return {"schema_version": "stage-b-event-episodes-1", "episodes": rows}


def test_materializes_vectors_with_production_contract_and_never_exports_events(tmp_path: Path):
    result = materialize_feature_dataset(splits(), episodes(), repo_root=Path(__file__).resolve().parents[2])
    assert result["schema_version"] == "stage-b-feature-dataset-1"
    assert result["feature_version"] == "context-features-1"
    assert result["feature_names"][:3] == ["document_started", "has_password", "has_otp"]
    assert len(result["feature_contract_sha256"]) == 64
    assert len(result["extractor_source_sha256"]) == 64
    row = result["partitions"]["train"]["records"][0]
    assert row["feature_vector"][:3] == [1, 1, 0]
    assert len(row["feature_vector"]) == len(result["feature_names"])
    def assert_no_events_key(value):
        if isinstance(value, dict):
            assert "events" not in value
            for child in value.values():
                assert_no_events_key(child)
        elif isinstance(value, list):
            for child in value:
                assert_no_events_key(child)
    assert_no_events_key(result)


def test_requires_exactly_one_episode_for_every_supervised_sample():
    data = episodes()
    data["episodes"].pop()
    with pytest.raises(FeatureMaterializationError, match="missing event episode"):
        materialize_feature_dataset(splits(), data, repo_root=Path(__file__).resolve().parents[2])

    data = episodes()
    data["episodes"].append(dict(data["episodes"][0]))
    with pytest.raises(FeatureMaterializationError, match="duplicate episode"):
        materialize_feature_dataset(splits(), data, repo_root=Path(__file__).resolve().parents[2])


def test_rejects_event_hash_mismatch():
    data = episodes()
    data["episodes"][0]["events_sha256"] = "0" * 64
    with pytest.raises(FeatureMaterializationError, match="event hash mismatch"):
        materialize_feature_dataset(splits(), data, repo_root=Path(__file__).resolve().parents[2])


def test_rejects_secret_or_unknown_event_fields():
    data = episodes()
    data["episodes"][0]["events"][0]["password"] = "secret"
    data["episodes"][0]["events_sha256"] = h(data["episodes"][0]["events"])
    with pytest.raises(FeatureMaterializationError, match="unexpected event fields"):
        materialize_feature_dataset(splits(), data, repo_root=Path(__file__).resolve().parents[2])


def test_preserves_partition_and_leakage_audit_identifiers():
    result = materialize_feature_dataset(splits(), episodes(), repo_root=Path(__file__).resolve().parents[2])
    for name in ["train", "selection", "calibration", "test"]:
        row = result["partitions"][name]["records"][0]
        assert row["partition"] == name
        assert row["artifact_group"] == f"artifact-{name}"
        assert row["domain_group"] == f"{name}.example"
        assert row["source_groups"] == [f"source-{name}"]


def test_validator_detects_feature_contract_or_vector_drift():
    result = materialize_feature_dataset(splits(), episodes(), repo_root=Path(__file__).resolve().parents[2])
    validate_feature_dataset(result)

    changed = json.loads(json.dumps(result))
    changed["feature_names"] = list(reversed(changed["feature_names"]))
    with pytest.raises(FeatureMaterializationError, match="feature contract hash"):
        validate_feature_dataset(changed)

    changed = json.loads(json.dumps(result))
    changed["partitions"]["train"]["records"][0]["feature_vector"].append(1)
    with pytest.raises(FeatureMaterializationError, match="feature vector length"):
        validate_feature_dataset(changed)
