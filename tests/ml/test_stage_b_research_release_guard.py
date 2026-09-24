from ml.training.stage_b_release_candidate import _readiness_allows_integration


def test_research_readiness_blocks_release_integration_eligibility():
    assert _readiness_allows_integration({"deployment_authorized": False}) is False


def test_normal_readiness_without_explicit_research_block_remains_eligible_for_other_gates():
    assert _readiness_allows_integration({}) is True
    assert _readiness_allows_integration({"deployment_authorized": True}) is True
