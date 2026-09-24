from copy import deepcopy

import pytest

from ml.data.stage_b_acquisition import AcquisitionPlanError, validate_acquisition_plan


def splits():
    return {
        "schema_version": "stage-b-splits-1",
        "partitions": {
            "train": {"records": [{"sample_id": "train-1"}]},
            "selection": {"records": [{"sample_id": "selection-1"}]},
            "calibration": {"records": [{"sample_id": "calibration-1"}]},
            "test": {"records": [{"sample_id": "test-1"}]},
        },
    }


def plan():
    return {
        "schema_version": "stage-b-acquisition-plan-1",
        "plan_id": "controlled-smoke",
        "created_at": "2026-09-24T17:00:00Z",
        "items": [
            {
                "sample_id": "train-1",
                "mode": "CONTROLLED_LOCAL",
                "target_url": "http://127.0.0.1:41731/suspicious",
                "collection_provenance": "CONTROLLED_BROWSER",
                "wait_ms": 500,
            }
        ],
    }


def test_accepts_controlled_loopback_plan_and_preserves_only_closed_fields():
    result = validate_acquisition_plan(plan(), splits())
    assert result["plan_id"] == "controlled-smoke"
    assert result["items"][0]["sample_id"] == "train-1"
    assert result["items"][0]["target_url"].startswith("http://127.0.0.1:")


def test_controlled_local_rejects_non_loopback_target():
    candidate = plan()
    candidate["items"][0]["target_url"] = "https://example.com/"
    with pytest.raises(AcquisitionPlanError, match="loopback"):
        validate_acquisition_plan(candidate, splits())


def test_live_passive_requires_explicit_runtime_authorization_and_real_provenance():
    candidate = plan()
    candidate["items"][0].update({
        "mode": "LIVE_PASSIVE",
        "target_url": "https://example.com/",
        "collection_provenance": "REAL_BROWSER",
    })
    with pytest.raises(AcquisitionPlanError, match="allow_live_passive"):
        validate_acquisition_plan(candidate, splits())

    result = validate_acquisition_plan(candidate, splits(), allow_live_passive=True)
    assert result["items"][0]["mode"] == "LIVE_PASSIVE"

    bad = deepcopy(candidate)
    bad["items"][0]["collection_provenance"] = "CONTROLLED_BROWSER"
    with pytest.raises(AcquisitionPlanError, match="REAL_BROWSER"):
        validate_acquisition_plan(bad, splits(), allow_live_passive=True)


def test_rejects_credential_bearing_urls_fragments_and_interaction_controls():
    candidate = plan()
    candidate["items"][0]["target_url"] = "http://user:secret@127.0.0.1:41731/"
    with pytest.raises(AcquisitionPlanError, match="credentials"):
        validate_acquisition_plan(candidate, splits())

    candidate = plan()
    candidate["items"][0]["target_url"] += "#secret"
    with pytest.raises(AcquisitionPlanError, match="fragment"):
        validate_acquisition_plan(candidate, splits())

    candidate = plan()
    candidate["items"][0]["interaction"] = "submit"
    with pytest.raises(AcquisitionPlanError, match="unexpected acquisition item fields"):
        validate_acquisition_plan(candidate, splits())


def test_rejects_unknown_duplicate_samples_and_invalid_wait_bounds():
    candidate = plan()
    candidate["items"][0]["sample_id"] = "unknown"
    with pytest.raises(AcquisitionPlanError, match="not present in locked splits"):
        validate_acquisition_plan(candidate, splits())

    candidate = plan()
    candidate["items"].append(deepcopy(candidate["items"][0]))
    with pytest.raises(AcquisitionPlanError, match="duplicate sample_id"):
        validate_acquisition_plan(candidate, splits())

    candidate = plan()
    candidate["items"][0]["wait_ms"] = 20000
    with pytest.raises(AcquisitionPlanError, match="wait_ms"):
        validate_acquisition_plan(candidate, splits())


def test_plan_timestamp_must_be_timezone_aware_and_schema_is_closed():
    candidate = plan()
    candidate["created_at"] = "2026-09-24T17:00:00"
    with pytest.raises(AcquisitionPlanError, match="timezone"):
        validate_acquisition_plan(candidate, splits())

    candidate = plan()
    candidate["headers"] = {"Authorization": "secret"}
    with pytest.raises(AcquisitionPlanError, match="unexpected acquisition plan fields"):
        validate_acquisition_plan(candidate, splits())
