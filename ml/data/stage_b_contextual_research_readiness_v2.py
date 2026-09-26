"""Research readiness wrapper for contextual archive protocol v2."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .stage_b_readiness import audit_feature_dataset_readiness


class ContextualResearchReadinessError(ValueError):
    pass


def audit_contextual_research_v2_readiness(
    feature_data: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    active = deepcopy(dict(policy))
    notes = active.get("notes")
    if not isinstance(notes, list) or not any(
        isinstance(note, str) and "RESEARCH-ONLY" in note.upper()
        for note in notes
    ):
        raise ContextualResearchReadinessError(
            "contextual v2 readiness must explicitly declare RESEARCH-ONLY"
        )

    if active.get("require_group_isolation") != [
        "artifact_group", "domain_group"
    ]:
        raise ContextualResearchReadinessError(
            "contextual v2 readiness must isolate artifact_group and domain_group"
        )

    allowed = active.get("allowed_provenance")
    if not isinstance(allowed, Mapping) or any(
        values != ["ARCHIVED_BROWSER_REPLAY"]
        for values in allowed.values()
    ):
        raise ContextualResearchReadinessError(
            "contextual v2 readiness may allow only ARCHIVED_BROWSER_REPLAY"
        )

    if active.get("require_strict_forward_test") is not True:
        raise ContextualResearchReadinessError(
            "contextual v2 readiness requires strict-forward test"
        )

    result = audit_feature_dataset_readiness(feature_data, active)
    result["research_protocol"] = (
        "single-source-contextual-archive-replay-research-v2"
    )
    result["research_only"] = True
    result["source_independence_relaxed"] = True
    result["production_readiness_equivalent"] = False
    result["deployment_authorized"] = False
    result["brand_group_role"] = "AUDIT_ONLY_NOT_MODEL_OBSERVABLE"
    result["limitations"] = [
        *result.get("limitations", []),
        "Brand identity is retained for subgroup audit but is not a v2 leakage-isolation dimension.",
        "The contextual model vector contains no literal brand identity.",
        "Single-source archive research cannot establish production readiness.",
    ]
    return result
