"""Task 26: non-destructive phishing tenant-host grouping experiment.

The current Zenodo adapter derives a conservative registrable-domain-like
domain_group. For phishing pages on multi-tenant hosting, that can collapse
unrelated tenants into shared provider roots (for example workers.dev).

This experiment rewrites ONLY phishing domain_group values using the exact
hostname from the metadata CSV `url` column. Legitimate grouping, brand_group,
artifact identity, chronology, labels, and source provenance remain unchanged.

The output is a new normalized research plan for feasibility analysis only.
It does not mutate Task 20 artifacts or authorize deployment.
"""
from __future__ import annotations

from collections import Counter
import copy
import json
from pathlib import Path
from typing import Any, Mapping

from .stage_b_zenodo8041387 import (
    Zenodo8041387AdapterError,
    hostname_from_source,
    normalize_record_key,
    read_csv,
)

SCHEMA = "stage-b-phishing-tenant-host-experiment-1"


class TenantHostExperimentError(ValueError):
    pass


def _record_id_from_sample_id(sample_id: str) -> str:
    if not isinstance(sample_id, str) or not sample_id:
        raise TenantHostExperimentError("sample_id must be non-empty")
    token = sample_id.rsplit(":", 1)[-1].strip().lower()
    if not token:
        raise TenantHostExperimentError(f"cannot derive record ID from {sample_id!r}")
    return token


def build_phishing_tenant_host_plan(
    normalized_plan: Mapping[str, Any],
    phishing_csv: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if normalized_plan.get("schema_version") != "stage-b-archive-replay-normalized-1":
        raise TenantHostExperimentError("expected normalized Stage B archive replay plan")

    headers, rows = read_csv(phishing_csv)
    if "_id" not in headers:
        raise TenantHostExperimentError("phishing CSV must contain _id")
    if "url" not in headers:
        raise TenantHostExperimentError(
            "phishing CSV must contain the exact url column for tenant-host analysis"
        )

    metadata: dict[str, dict[str, str]] = {}
    for row in rows:
        raw_id = row.get("_id", "")
        if not raw_id:
            continue
        try:
            key = str(normalize_record_key(raw_id)).lower()
        except Zenodo8041387AdapterError:
            continue
        if key in metadata:
            raise TenantHostExperimentError(f"duplicate phishing metadata ID: {key}")
        metadata[key] = row

    output = copy.deepcopy(dict(normalized_plan))
    items = output.get("items")
    if not isinstance(items, list) or not items:
        raise TenantHostExperimentError("normalized plan requires items")

    before = Counter()
    after = Counter()
    changed = 0
    phishing_count = 0
    missing: list[str] = []

    for item in items:
        if not isinstance(item, dict):
            raise TenantHostExperimentError("plan item must be an object")
        if item.get("ground_truth") != 1:
            continue

        phishing_count += 1
        old = str(item.get("domain_group", "")).strip().lower()
        before[old] += 1

        record_id = _record_id_from_sample_id(item.get("sample_id", ""))
        row = metadata.get(record_id)
        if row is None:
            missing.append(record_id)
            continue

        raw_url = row.get("url", "")
        try:
            host = hostname_from_source(raw_url)
        except Zenodo8041387AdapterError as exc:
            raise TenantHostExperimentError(
                f"invalid url metadata for phishing record {record_id}: {exc}"
            ) from exc

        item["domain_group"] = host
        after[host] += 1
        if host != old:
            changed += 1

    if missing:
        raise TenantHostExperimentError(
            f"phishing metadata missing for {len(missing)} plan records; first={missing[0]}"
        )
    if phishing_count == 0:
        raise TenantHostExperimentError("plan contains no phishing records")

    plan_id = output.get("plan_id")
    output["plan_id"] = f"{plan_id}-phishing-tenant-host-v2"

    report = {
        "schema_version": SCHEMA,
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "phishing_samples": phishing_count,
        "changed_domain_groups": changed,
        "unique_domain_groups_before": len(before),
        "unique_domain_groups_after": len(after),
        "largest_groups_before": before.most_common(20),
        "largest_groups_after": after.most_common(20),
        "semantics": {
            "phishing_domain_group": "exact hostname from metadata CSV url",
            "legitimate_domain_group": "unchanged",
            "brand_group": "unchanged",
            "artifact_sha256": "unchanged",
            "observed_at": "unchanged",
        },
        "warning": (
            "This is a feasibility experiment only. A PASS here does not modify "
            "Task 20 or the research split contract."
        ),
    }
    return output, report
