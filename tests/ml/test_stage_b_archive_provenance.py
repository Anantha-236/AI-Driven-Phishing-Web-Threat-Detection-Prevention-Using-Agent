from __future__ import annotations

import pytest

from ml.data.stage_b_readiness import (
    DEFAULT_POLICY,
    ReadinessAuditError,
    validate_readiness_policy,
)


def research_policy():
    return {
        "schema_version": "stage-b-readiness-policy-1",
        "min_samples_per_class": {
            "train": 100, "selection": 50, "calibration": 50, "test": 100,
        },
        "allowed_provenance": {
            "train": ["ARCHIVED_BROWSER_REPLAY"],
            "selection": ["ARCHIVED_BROWSER_REPLAY"],
            "calibration": ["ARCHIVED_BROWSER_REPLAY"],
            "test": ["ARCHIVED_BROWSER_REPLAY"],
        },
        "require_strict_forward_test": True,
        "require_group_isolation": ["artifact_group", "domain_group", "brand_group"],
        "notes": ["research-only replay"],
    }


def test_default_policy_remains_non_archive_for_selection_calibration_test():
    assert "ARCHIVED_BROWSER_REPLAY" not in DEFAULT_POLICY["allowed_provenance"]["selection"]
    assert "ARCHIVED_BROWSER_REPLAY" not in DEFAULT_POLICY["allowed_provenance"]["calibration"]
    assert "ARCHIVED_BROWSER_REPLAY" not in DEFAULT_POLICY["allowed_provenance"]["test"]


def test_research_policy_explicitly_accepts_archive_replay_provenance():
    validated = validate_readiness_policy(research_policy())
    assert validated["allowed_provenance"]["test"] == ["ARCHIVED_BROWSER_REPLAY"]
    assert "source_groups" not in validated["require_group_isolation"]


def test_unknown_archive_like_provenance_still_fails_closed():
    policy = research_policy()
    policy["allowed_provenance"]["train"] = ["ARCHIVED_HTML"]
    with pytest.raises(ReadinessAuditError, match="invalid provenance"):
        validate_readiness_policy(policy)
