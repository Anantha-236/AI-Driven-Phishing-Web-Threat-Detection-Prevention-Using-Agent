from __future__ import annotations

import copy

import pytest

from ml.evaluation.stage_b_controlled_shadow import (
    ControlledShadowEvaluationError,
    evaluate_controlled_shadow,
    validate_controlled_shadow_dataset,
)


def record(family, label, layout, baseline, stage=None, status="OBSERVED"):
    return {
        "case_id": f"f{family}-l{label}-x{layout}",
        "family": str(family),
        "layout": layout,
        "label": label,
        "baseline_action": "WARN" if baseline else "ALLOW",
        "baseline_intervention": baseline,
        "stage_b_status": status,
        "stage_b_score": (0.9 if stage else 0.1) if status == "OBSERVED" else None,
        "stage_b_intervention": stage if status == "OBSERVED" else None,
        "stage_b_threshold": 0.5 if status == "OBSERVED" else None,
        "stage_b_latency_ms": 4.0 if status == "OBSERVED" else None,
        "stage_b_model_id": "stage-b-test" if status == "OBSERVED" else None,
        "stage_b_integration_eligible": False if status == "OBSERVED" else None,
    }


def dataset():
    rows = []
    for family in range(1, 6):
        for layout in (0, 1):
            rows.append(record(family, 0, layout, False, False))
            rows.append(record(family, 1, layout, True, True))
    for layout in (0, 1):
        rows.append(record(6, 0, layout, False, False))
        rows.append(record(6, 1, layout, False, False))
    return {
        "schema_version": "stage-b-controlled-shadow-dataset-1",
        "protocol": "CONTROLLED_NON_FINAL",
        "fixture_protocol": "authored-research-v1",
        "final_test_reused": False,
        "records": rows,
    }


def test_primary_metrics_exclude_observationally_ambiguous_family_6():
    report = evaluate_controlled_shadow(dataset())
    assert report["case_counts"] == {
        "total": 24,
        "primary_families_1_to_5": 20,
        "ambiguity_family_6": 4,
    }
    assert report["baseline_primary_metrics"]["accuracy"] == 1.0
    assert report["stage_b_primary_metrics"]["accuracy"] == 1.0
    assert report["ambiguity_family_6"]["paired_layouts"] == 2
    assert report["promotion_decision"] == "NOT_PERMITTED_FROM_CONTROLLED_FIXTURES"


def test_disagreement_analysis_attributes_controlled_label_correctness_only_when_comparable():
    data = dataset()
    target = next(row for row in data["records"] if row["family"] == "2" and row["label"] == 1 and row["layout"] == 0)
    target["stage_b_score"] = 0.1
    target["stage_b_intervention"] = False
    report = evaluate_controlled_shadow(data)
    disagreement = report["disagreement_analysis"]
    assert disagreement["disagreement_cases"] == 1
    assert disagreement["baseline_correct_when_disagree"] == 1
    assert disagreement["stage_b_correct_when_disagree"] == 0


def test_stage_b_unavailable_is_reported_as_coverage_gap_not_as_wrong_prediction():
    data = dataset()
    for row in data["records"]:
        if row["family"] == "3":
            row.update({
                "stage_b_status": "ERROR",
                "stage_b_score": None,
                "stage_b_intervention": None,
                "stage_b_threshold": None,
                "stage_b_latency_ms": None,
                "stage_b_model_id": None,
                "stage_b_integration_eligible": None,
            })
    report = evaluate_controlled_shadow(data)
    assert report["family_metrics"]["3"]["stage_b"] is None
    assert report["family_metrics"]["3"]["stage_b_scored_cases"] == 0
    assert report["stage_b_primary_coverage"] == 0.8


def test_family_6_pair_difference_is_diagnostic_not_primary_correctness():
    data = dataset()
    target = next(row for row in data["records"] if row["family"] == "6" and row["label"] == 1 and row["layout"] == 0)
    target["stage_b_score"] = 0.9
    target["stage_b_intervention"] = True
    report = evaluate_controlled_shadow(data)
    assert report["ambiguity_family_6"]["stage_b_intervention_pair_disagreements"] == 1
    assert report["stage_b_primary_metrics"]["total"] == 20


def test_rejects_locked_final_test_reuse_and_privacy_unsafe_fields():
    data = dataset()
    data["final_test_reused"] = True
    with pytest.raises(ControlledShadowEvaluationError, match="final test"):
        validate_controlled_shadow_dataset(data)

    data = dataset()
    data["records"][0]["document_id"] = "secret-doc"
    with pytest.raises(ControlledShadowEvaluationError, match="privacy-unsafe"):
        validate_controlled_shadow_dataset(data)


def test_rejects_inconsistent_threshold_intervention_and_duplicate_case_ids():
    data = dataset()
    data["records"][0]["stage_b_intervention"] = True
    with pytest.raises(ControlledShadowEvaluationError, match="threshold mismatch"):
        validate_controlled_shadow_dataset(data)

    data = dataset()
    data["records"][1]["case_id"] = data["records"][0]["case_id"]
    with pytest.raises(ControlledShadowEvaluationError, match="duplicate"):
        validate_controlled_shadow_dataset(data)
