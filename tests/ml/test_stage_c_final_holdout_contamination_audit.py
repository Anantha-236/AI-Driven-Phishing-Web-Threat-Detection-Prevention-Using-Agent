from pathlib import Path

import pytest

import ml.data.stage_c_final_holdout_contamination_audit as mod
from ml.data.stage_c_final_holdout_contamination_audit import (
    StageCFinalHoldoutContaminationError,
)


def row(sample, label, html, url, host="h"):
    return {
        "sample_id": sample,
        "label": label,
        "html_sha256": html,
        "normalized_url_sha256": url,
        "hostname_sha256": host * 64 if len(host) == 1 else host,
        "html_member_name": f"{sample}.txt",
        "html_basename": f"{sample}.txt",
    }


def h(ch):
    return ch * 64


def test_schemas_and_frozen_task29_hashes():
    assert mod.AUDIT_SCHEMA == "stage-c-final-holdout-contamination-audit-1"
    assert mod.CLEAN_SET_SCHEMA == "stage-c-final-holdout-clean-evaluation-set-1"
    assert mod.EXPECTED_TASK29_RECORD_SET_SHA256 == (
        "30712d728fdaee1681bf227018ea953a5f52c490ea0e560cf49d257c04609167"
    )


def test_stage_b_consumed_test_fingerprint_is_frozen():
    assert mod.EXPECTED_STAGE_B_TEST_PARTITION_SHA256 == (
        "a7d83608610370f7772ee2820bdf0229cd14e97c6f18143130125c7db7a4fd2d"
    )


def test_url_normalization_matches_task29_semantics():
    normalized, host = mod.normalize_url(
        "HTTPS://Example.COM:443/login?q=1#fragment"
    )
    assert normalized == "https://example.com/login?q=1"
    assert host == "example.com"


def test_identity_components_join_exact_html():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 0, h("a"), h("2")),
        row("c", 1, h("c"), h("3")),
    ]
    comps = mod.build_identity_components(rows)
    assert sorted(len(x) for x in comps) == [1, 2]


def test_identity_components_join_normalized_url():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 0, h("b"), h("1")),
        row("c", 1, h("c"), h("3")),
    ]
    comps = mod.build_identity_components(rows)
    assert sorted(len(x) for x in comps) == [1, 2]


def test_identity_components_are_transitive():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 0, h("a"), h("2")),
        row("c", 0, h("c"), h("2")),
    ]
    comps = mod.build_identity_components(rows)
    assert len(comps) == 1
    assert len(comps[0]) == 3


def test_stage_b_fingerprint_uses_only_consumed_identity_fields():
    rows = [
        {
            "sample_id": "b",
            "ground_truth": 1,
            "feature_vector": [1.0, 2.0],
            "artifact_group": h("a"),
            "domain_group": "example.com",
        },
        {
            "sample_id": "a",
            "ground_truth": 0,
            "feature_vector": [0.0, 3.0],
            "artifact_group": h("b"),
            "domain_group": "example.org",
        },
    ]
    first = mod._stage_b_test_fingerprint(rows)
    rows[0]["artifact_group"] = h("c")
    rows[0]["domain_group"] = "changed.example"
    assert mod._stage_b_test_fingerprint(rows) == first


def test_stage_b_fingerprint_changes_with_feature_vector():
    rows = [{
        "sample_id": "a",
        "ground_truth": 0,
        "feature_vector": [0.0],
    }]
    first = mod._stage_b_test_fingerprint(rows)
    rows[0]["feature_vector"] = [1.0]
    assert mod._stage_b_test_fingerprint(rows) != first


def test_cross_label_component_detection_basis():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 1, h("a"), h("2")),
    ]
    comps = mod.build_identity_components(rows)
    assert len({x["label"] for x in comps[0]}) == 2


def test_wilson_minimum_is_frozen():
    assert mod.MIN_LEGITIMATE_FOR_WILSON == 381


def test_task30_never_scores_or_extracts_features():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "predict_proba" not in source
    assert ".fit(" not in source
    assert '"model_scoring_performed": False' in source
    assert '"features_extracted": False' in source


def test_clean_selection_is_identity_only():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "IDENTITY_ONLY_NO_MODEL_SCORE_NO_MODEL_PERFORMANCE" in source
    assert "ONE_LEXICOGRAPHICALLY_SMALLEST_SAMPLE_ID" in source


def test_hard_overlap_reasons_are_explicit():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "EXACT_HTML_OVERLAP_STAGE_C_DEVELOPMENT" in source
    assert "NORMALIZED_URL_OVERLAP_STAGE_C_DEVELOPMENT" in source
    assert "EXACT_HTML_OVERLAP_CONSUMED_STAGE_B_TEST" in source


def test_stage_c_hostname_overlap_is_audit_only():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "stage_c_development_hostname_overlap_samples_audit_only" in source


def test_raw_urls_are_not_emitted():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"raw_urls_emitted": False' in source


def test_next_gate_is_feature_extraction_authorization():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "AUTHORIZE_STAGE_C_FINAL_HOLDOUT_FEATURE_EXTRACTION_ON_"
        in source
    )


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "audit.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCFinalHoldoutContaminationError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})
