"""Research-only readiness wrapper for ARCHIVED_BROWSER_REPLAY feature datasets."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .stage_b_readiness import audit_feature_dataset_readiness


class ResearchReadinessError(ValueError):
    """Raised when a research replay readiness policy is not explicitly non-deployable."""


def audit_research_replay_readiness(
    feature_data: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    active = deepcopy(dict(policy))
    notes = active.get("notes")
    if not isinstance(notes, list) or not any(
        isinstance(note, str) and "RESEARCH-ONLY" in note.upper()
        for note in notes
    ):
        raise ResearchReadinessError("research readiness policy must explicitly declare RESEARCH-ONLY")

    allowed = active.get("allowed_provenance")
    if not isinstance(allowed, Mapping) or any(
        values != ["ARCHIVED_BROWSER_REPLAY"] for values in allowed.values()
    ):
        raise ResearchReadinessError(
            "research replay readiness may allow only ARCHIVED_BROWSER_REPLAY"
        )
    isolation = active.get("require_group_isolation")
    if isolation != ["artifact_group", "domain_group", "brand_group"]:
        raise ResearchReadinessError(
            "research replay readiness must isolate artifact/domain/brand and omit source_groups"
        )
    if active.get("require_strict_forward_test") is not True:
        raise ResearchReadinessError("research replay readiness requires strict-forward final test")

    result = audit_feature_dataset_readiness(feature_data, active)
    result["research_protocol"] = "single-source-archive-replay-research-v1"
    result["research_only"] = True
    result["source_independence_relaxed"] = True
    result["production_readiness_equivalent"] = False
    result["deployment_authorized"] = False
    result["limitations"] = [
        *result.get("limitations", []),
        "This readiness result intentionally relaxes source-group independence for one archive source.",
        "training_allowed authorizes research benchmarking only; it never authorizes deployment.",
    ]
    return result
