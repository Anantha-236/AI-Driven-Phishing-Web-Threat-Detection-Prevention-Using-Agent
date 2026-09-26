from __future__ import annotations

import numpy as np
import pytest

from ml.evaluation.stage_b_contextual_final_evidence_v2 import (
    FinalEvidenceSealError,
    build_final_evidence_seal,
    build_read_only_error_analysis,
    canonical_hash,
)


def feature_fixture():
    return {
        "feature_names": ["f0", "f1"],
    }


def rows_fixture():
    return [
        {"sample_id": "a", "feature_vector": [0.0, 1.0]},
        {"sample_id": "b", "feature_vector": [2.0, 0.0]},
        {"sample_id": "c", "feature_vector": [0.5, 1.5]},
        {"sample_id": "d", "feature_vector": [3.0, 0.5]},
    ]


def test_read_only_analysis_uses_fixed_threshold_only():
    result = build_read_only_error_analysis(
        feature_data=feature_fixture(),
        test_rows=rows_fixture(),
        labels=np.asarray([0, 0, 1, 1]),
        scores=np.asarray([0.1, 0.9, 0.4, 0.95]),
        threshold=0.8,
        test_score_sha256="a" * 64,
    )
    assert result["sample_counts"] == {
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1,
        "true_positive": 1,
    }
    assert result["frozen_threshold"] == 0.8


def test_read_only_analysis_emits_no_sample_or_host_identifiers():
    result = build_read_only_error_analysis(
        feature_data=feature_fixture(),
        test_rows=rows_fixture(),
        labels=np.asarray([0, 0, 1, 1]),
        scores=np.asarray([0.1, 0.9, 0.4, 0.95]),
        threshold=0.8,
        test_score_sha256="b" * 64,
    )

    # The privacy metadata is allowed to say that sample IDs were *not*
    # emitted. Check actual output content instead of rejecting the harmless
    # key name "sample_ids_emitted".
    rendered = str(result)

    for sample_id in ("a", "b", "c", "d"):
        assert f"'sample_id': '{sample_id}'" not in rendered
        assert f'"sample_id": "{sample_id}"' not in rendered

    assert "domain_group" not in rendered
    assert "brand_group" not in rendered

    privacy = result["privacy"]
    assert privacy["aggregate_only"] is True
    assert privacy["sample_ids_emitted"] is False
    assert privacy["domains_emitted"] is False
    assert privacy["brands_emitted"] is False
    assert privacy["urls_emitted"] is False
    assert privacy["raw_html_emitted"] is False
    assert privacy["event_payloads_emitted"] is False


def test_feature_contrast_is_aggregate_only():
    result = build_read_only_error_analysis(
        feature_data=feature_fixture(),
        test_rows=rows_fixture(),
        labels=np.asarray([0, 0, 1, 1]),
        scores=np.asarray([0.1, 0.9, 0.4, 0.95]),
        threshold=0.8,
        test_score_sha256="c" * 64,
    )
    contrasts = result["feature_contrasts"][
        "false_positive_vs_true_negative"
    ]
    assert contrasts
    assert set(contrasts[0]) == {
        "feature",
        "false_positive_mean",
        "true_negative_mean",
        "mean_difference",
        "standardized_difference",
    }


def test_evidence_seal_rejects_wrong_tag_target():
    verification = {
        "dataset_sha256": "1" * 64,
        "test_partition_sha256": "2" * 64,
        "test_score_sha256": "3" * 64,
        "selected_candidate": "random_forest_compact",
        "threshold": 0.8,
    }
    final = {
        "calibration_method": "sigmoid",
        "test_samples": 10,
        "fixed_operating_point": {
            "confusion_matrix": {
                "tn": 4, "fp": 1, "fn": 2, "tp": 3
            },
            "precision": 0.75,
            "recall": 0.6,
            "observed_fpr": 0.2,
            "fpr_wilson_95": [0.04, 0.62],
            "research_fpr_cap": 0.01,
            "observed_fpr_within_research_cap": False,
            "wilson_95_upper_within_research_cap": False,
        },
        "threshold_free_metrics": {
            "average_precision": 0.8,
            "roc_auc": 0.8,
            "brier_score": 0.2,
        },
    }
    with pytest.raises(
        FinalEvidenceSealError,
        match="tag does not resolve",
    ):
        build_final_evidence_seal(
            verification=verification,
            final_lock={},
            final_report=final,
            lock_file_sha256="4" * 64,
            final_report_file_sha256="5" * 64,
            pre_final_commit="6" * 40,
            pre_final_tag="pre-final",
            tag_target_commit="7" * 40,
            error_analysis={"ok": True},
        )


def test_evidence_seal_preserves_failed_fpr_objective():
    verification = {
        "dataset_sha256": "1" * 64,
        "test_partition_sha256": "2" * 64,
        "test_score_sha256": "3" * 64,
        "selected_candidate": "rf",
        "threshold": 0.8,
    }
    final = {
        "calibration_method": "sigmoid",
        "test_samples": 10,
        "fixed_operating_point": {
            "confusion_matrix": {
                "tn": 4, "fp": 1, "fn": 2, "tp": 3
            },
            "precision": 0.75,
            "recall": 0.6,
            "observed_fpr": 0.2,
            "fpr_wilson_95": [0.04, 0.62],
            "research_fpr_cap": 0.01,
            "observed_fpr_within_research_cap": False,
            "wilson_95_upper_within_research_cap": False,
        },
        "threshold_free_metrics": {
            "average_precision": 0.8,
            "roc_auc": 0.8,
            "brier_score": 0.2,
        },
    }
    result = build_final_evidence_seal(
        verification=verification,
        final_lock={"lock": 1},
        final_report=final,
        lock_file_sha256="4" * 64,
        final_report_file_sha256="5" * 64,
        pre_final_commit="6" * 40,
        pre_final_tag=None,
        tag_target_commit=None,
        error_analysis={"ok": True},
    )
    assert (
        result["conclusion"]["research_fpr_objective_supported"]
        is False
    )
    assert result["deployment_authorized"] is False


def test_canonical_hash_is_order_independent_for_objects():
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash(
        {"b": 2, "a": 1}
    )
