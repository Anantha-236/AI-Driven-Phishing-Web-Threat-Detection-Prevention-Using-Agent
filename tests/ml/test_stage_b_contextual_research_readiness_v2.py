from __future__ import annotations

from ml.data.stage_b_contextual_research_readiness_v2 import (
    ContextualResearchReadinessError,
)


def test_v2_readiness_module_imports():
    assert ContextualResearchReadinessError.__name__ == "ContextualResearchReadinessError"
