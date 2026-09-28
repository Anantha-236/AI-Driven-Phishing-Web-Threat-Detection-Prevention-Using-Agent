from pathlib import Path

import ml.data.stage_c_final_holdout_contamination_audit as mod


def h(ch):
    return ch * 64


def row(sample, label, html, url):
    return {
        "sample_id": sample,
        "label": label,
        "html_sha256": html,
        "normalized_url_sha256": url,
        "hostname_sha256": h("f"),
        "html_member_name": f"{sample}.txt",
        "html_basename": f"{sample}.txt",
    }


def test_same_url_different_label_does_not_collapse():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 1, h("b"), h("1")),
    ]
    components = mod.build_identity_components(rows)
    assert len(components) == 2


def test_same_url_same_label_still_deduplicates():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 0, h("b"), h("1")),
    ]
    components = mod.build_identity_components(rows)
    assert len(components) == 1


def test_exact_html_different_labels_still_joins_for_quarantine():
    rows = [
        row("a", 0, h("a"), h("1")),
        row("b", 1, h("a"), h("2")),
    ]
    components = mod.build_identity_components(rows)
    assert len(components) == 1
    assert {x["label"] for x in components[0]} == {0, 1}


def test_hotfix_declares_no_relabeling_conflict_policy():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "EXACT_HTML_CROSS_LABEL_CONFLICT_WITHIN_HOLDOUT" in source
    assert (
        "QUARANTINE_ENTIRE_CONFLICTING_EXACT_HTML_COMPONENT_NO_RELABELING"
        in source
    )


def test_old_conflicting_label_hard_failure_removed():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "final-holdout identity components contain conflicting labels"
        not in source
    )


def test_duplicate_accounting_excludes_cross_label_components():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        'if len({row["label"] for row in component}) == 1'
        in source
    )


def test_model_and_threshold_remain_frozen():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"model_scoring_performed": False' in source
    assert '"features_extracted": False' in source
    assert '"threshold_changed": False' in source
    assert '"model_refit": False' in source
