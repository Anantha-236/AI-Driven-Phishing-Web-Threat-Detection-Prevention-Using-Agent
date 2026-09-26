from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ml.data.stage_b_connectivity_attribution import analyze_connectivity_attribution


def policy():
    return {
        "min_samples_per_class": {
            "train": 2,
            "selection": 1,
            "calibration": 1,
            "test": 2,
        }
    }


def make_plan(brand_bridge=False, domain_bridge=False):
    start = datetime(2023, 1, 1, tzinfo=timezone.utc)
    items = []
    for label in (0, 1):
        for i in range(12):
            items.append({
                "sample_id": f"s-{label}-{i}",
                "archive_path": f"{label}/{i}.html",
                "ground_truth": label,
                "domain_group": f"d-{label}-{i}.example",
                "brand_group": f"b-{label}-{i}",
                "source_group": "source",
                "artifact_sha256": f"{label + 1:x}" + f"{i + 1:063x}"[-63:],
                "observed_at": (start + timedelta(days=i)).isoformat(),
                "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
            })
    # phishing rows begin at index 12
    if brand_bridge:
        items[12]["brand_group"] = "shared-brand"
        items[-1]["brand_group"] = "shared-brand"
    if domain_bridge:
        items[13]["domain_group"] = "shared.example"
        items[-2]["domain_group"] = "shared.example"

    return {
        "schema_version": "stage-b-archive-replay-normalized-1",
        "plan_id": "fixture",
        "collection_provenance": "ARCHIVED_BROWSER_REPLAY",
        "dataset": {
            "dataset_id": "fixture",
            "source_type": "ARCHIVE_DATASET",
            "independence_group": "source",
            "license_reference": "fixture",
            "research_use_acknowledged": True,
        },
        "items": items,
    }


def test_all_modes_reported():
    result = analyze_connectivity_attribution(make_plan(), policy())
    assert set(result["modes"]) == {
        "artifact_only",
        "artifact_domain",
        "artifact_brand",
        "artifact_domain_brand",
    }


def test_output_is_diagnostic_only():
    result = analyze_connectivity_attribution(make_plan(brand_bridge=True), policy())
    assert result["research_only"] is True
    assert result["deployment_authorized"] is False


def test_connectivity_ablation_changes_component_count():
    result = analyze_connectivity_attribution(
        make_plan(brand_bridge=True, domain_bridge=True),
        policy(),
    )
    assert (
        result["modes"]["artifact_only"]["connected_components"]
        > result["modes"]["artifact_domain_brand"]["connected_components"]
    )
