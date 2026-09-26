"""Task 27: attribute Stage B split infeasibility to grouping dimensions.

Diagnostic only. It compares strict-forward readiness feasibility under four
connectivity semantics on the same frozen candidate:

1. artifact only
2. artifact + domain
3. artifact + brand
4. artifact + domain + brand (current full semantics)

No candidate, split contract, threshold, or deployment guard is modified.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable, Mapping
import hashlib
import json

from .stage_b_research_splitting import _validate_archive_plan, PARTITIONS


class ConnectivityAttributionError(ValueError):
    pass


class _UF:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _hash_ids(ids: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(ids, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:24]


def componentize(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    allowed = {"artifact_group", "domain_group", "brand_group"}
    if not keys or any(key not in allowed for key in keys):
        raise ConnectivityAttributionError("invalid component keys")

    uf = _UF(len(rows))
    seen: dict[tuple[str, str], int] = {}

    for i, row in enumerate(rows):
        for key in keys:
            value = str(row[key])
            token = (key, value)
            if token in seen:
                uf.union(i, seen[token])
            else:
                seen[token] = i

    buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for i, row in enumerate(rows):
        buckets[uf.find(i)].append(row)

    out = []
    for bucket in buckets.values():
        ids = sorted(row["sample_id"] for row in bucket)
        out.append({
            "component_id": "component-" + _hash_ids(ids),
            "records": bucket,
            "sample_count": len(bucket),
            "labels": {row["ground_truth"] for row in bucket},
            "min_time": min(row["_observed_dt"] for row in bucket),
            "max_time": max(row["_observed_dt"] for row in bucket),
        })
    out.sort(key=lambda c: (c["min_time"], c["max_time"], c["component_id"]))
    return out


def _sample_counts(components: Iterable[Mapping[str, Any]]) -> dict[int, int]:
    counts = Counter()
    for comp in components:
        for row in comp["records"]:
            counts[row["ground_truth"]] += 1
    return {0: counts[0], 1: counts[1]}


def _label_component_counts(components: Iterable[Mapping[str, Any]]) -> dict[int, int]:
    comps = list(components)
    return {
        label: sum(1 for comp in comps if label in comp["labels"])
        for label in (0, 1)
    }


def _feasibility(components, required_upstream: int, required_test: int) -> dict[str, Any]:
    cutoffs = sorted({comp["min_time"] for comp in components})
    rows = []

    for cutoff in cutoffs:
        prefix = [c for c in components if c["max_time"] < cutoff]
        suffix = [c for c in components if c["min_time"] >= cutoff]
        bridge = [c for c in components if c["min_time"] < cutoff <= c["max_time"]]
        if not prefix or not suffix:
            continue

        pc = _sample_counts(prefix)
        sc = _sample_counts(suffix)
        bc = _sample_counts(bridge)
        pcc = _label_component_counts(prefix)

        feasible = (
            pc[0] >= required_upstream
            and pc[1] >= required_upstream
            and sc[0] >= required_test
            and sc[1] >= required_test
            and pcc[0] >= 3
            and pcc[1] >= 3
        )
        rows.append({
            "cutoff": cutoff.isoformat(),
            "feasible": feasible,
            "prefix_legitimate": pc[0],
            "prefix_phishing": pc[1],
            "test_legitimate": sc[0],
            "test_phishing": sc[1],
            "bridge_legitimate": bc[0],
            "bridge_phishing": bc[1],
            "bridge_samples": bc[0] + bc[1],
            "prefix_phishing_components": pcc[1],
        })

    feasible_rows = [row for row in rows if row["feasible"]]

    # For infeasible modes, surface candidates closest to satisfying phishing
    # minima rather than trivial latest cutoffs with zero bridge.
    def deficit(row):
        return (
            max(0, required_upstream - row["prefix_phishing"])
            + max(0, required_test - row["test_phishing"]),
            row["bridge_phishing"],
            row["bridge_samples"],
            row["cutoff"],
        )

    ranked = sorted(rows, key=lambda row: (0 if row["feasible"] else 1, *deficit(row)))

    return {
        "cutoffs_examined": len(rows),
        "feasible_cutoffs": len(feasible_rows),
        "feasibility": "FEASIBLE" if feasible_rows else "INFEASIBLE",
        "best_candidates": ranked[:10],
    }


def _largest_components(components, limit=10):
    result = []
    for comp in sorted(components, key=lambda c: c["sample_count"], reverse=True)[:limit]:
        labels = Counter(row["ground_truth"] for row in comp["records"])
        brands = Counter(row["brand_group"] for row in comp["records"])
        domains = Counter(row["domain_group"] for row in comp["records"])
        result.append({
            "component_id": comp["component_id"],
            "samples": comp["sample_count"],
            "legitimate": labels[0],
            "phishing": labels[1],
            "min_time": comp["min_time"].isoformat(),
            "max_time": comp["max_time"].isoformat(),
            "unique_brands": len(brands),
            "unique_domains": len(domains),
            "top_brands": brands.most_common(10),
            "top_domains": domains.most_common(10),
        })
    return result


def analyze_connectivity_attribution(
    normalized_plan: Mapping[str, Any],
    readiness_policy: Mapping[str, Any],
) -> dict[str, Any]:
    rows, _ = _validate_archive_plan(normalized_plan)

    minima = readiness_policy.get("min_samples_per_class")
    if not isinstance(minima, Mapping):
        raise ConnectivityAttributionError("readiness policy requires min_samples_per_class")

    for name in PARTITIONS:
        if type(minima.get(name)) is not int or minima[name] < 1:
            raise ConnectivityAttributionError(f"invalid readiness minimum for {name}")

    required_upstream = minima["train"] + minima["selection"] + minima["calibration"]
    required_test = minima["test"]

    modes = {
        "artifact_only": ("artifact_group",),
        "artifact_domain": ("artifact_group", "domain_group"),
        "artifact_brand": ("artifact_group", "brand_group"),
        "artifact_domain_brand": ("artifact_group", "domain_group", "brand_group"),
    }

    analyses = {}
    for name, keys in modes.items():
        comps = componentize(rows, keys)
        label_components = _label_component_counts(comps)
        analyses[name] = {
            "keys": list(keys),
            "connected_components": len(comps),
            "label_component_counts": {
                "legitimate": label_components[0],
                "phishing": label_components[1],
            },
            "largest_components": _largest_components(comps),
            "strict_forward": _feasibility(comps, required_upstream, required_test),
        }

    full = analyses["artifact_domain_brand"]["strict_forward"]["feasibility"]
    no_brand = analyses["artifact_domain"]["strict_forward"]["feasibility"]
    no_domain = analyses["artifact_brand"]["strict_forward"]["feasibility"]
    artifact_only = analyses["artifact_only"]["strict_forward"]["feasibility"]

    if full == "FEASIBLE":
        conclusion = "CURRENT_FULL_SEMANTICS_FEASIBLE"
    elif no_brand == "FEASIBLE" and no_domain != "FEASIBLE":
        conclusion = "BRAND_CONNECTIVITY_IS_DECISIVE_BLOCKER"
    elif no_domain == "FEASIBLE" and no_brand != "FEASIBLE":
        conclusion = "DOMAIN_CONNECTIVITY_IS_DECISIVE_BLOCKER"
    elif no_brand == "FEASIBLE" and no_domain == "FEASIBLE":
        conclusion = "DOMAIN_AND_BRAND_EACH_CAN_INDUCE_INFEASIBILITY"
    elif artifact_only == "FEASIBLE":
        conclusion = "COMBINED_GROUP_CONNECTIVITY_BLOCKS_READINESS"
    else:
        conclusion = "CHRONOLOGY_OR_SAMPLE_COVERAGE_BLOCKS_READINESS_EVEN_WITHOUT_DOMAIN_BRAND_LINKS"

    labels = Counter(row["ground_truth"] for row in rows)
    return {
        "status": "PASS",
        "schema_version": "stage-b-connectivity-attribution-1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_samples": len(rows),
        "candidate_labels": {
            "legitimate": labels[0],
            "phishing": labels[1],
        },
        "requirements": {
            "upstream_per_class": required_upstream,
            "test_per_class": required_test,
        },
        "conclusion": conclusion,
        "modes": analyses,
        "warning": (
            "Ablation feasibility is diagnostic evidence only. It does not authorize "
            "removing domain or brand isolation from the research split contract."
        ),
    }
