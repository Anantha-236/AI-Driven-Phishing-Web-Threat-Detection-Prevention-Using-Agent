
"""Stage C Task 7 — duplicate audit + strict-forward split feasibility.

This module is planning-only. It does not materialize features or train models.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib, json, math
from pathlib import Path
from typing import Any, Mapping

INDEX_SCHEMA = "stage-c-development-record-index-1"
REPORT_SCHEMA = "stage-c-development-record-index-report-1"
AUDIT_SCHEMA = "stage-c-development-duplicate-audit-1"
FEAS_SCHEMA = "stage-c-development-temporal-feasibility-1"
POLICY_SCHEMA = "stage-c-development-split-planning-policy-1"

class StageCSplitFeasibilityError(ValueError):
    pass

def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCSplitFeasibilityError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCSplitFeasibilityError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCSplitFeasibilityError(f"JSON root must be object: {path}")
    return value

def frozen_write_json(path: Path, value: Any) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = json.loads(path.read_text(encoding="utf-8"))
        if current != value:
            raise StageCSplitFeasibilityError(
                f"refusing to replace non-identical frozen Task-7 output: {path}"
            )
        return "EXISTING_MATCH"
    path.write_text(rendered, encoding="utf-8")
    return "CREATED"

def parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise StageCSplitFeasibilityError(f"invalid created_date: {value!r}") from exc

def _require_inputs(index: Mapping[str, Any], report: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    if index.get("schema_version") != INDEX_SCHEMA or index.get("status") != "PASS":
        raise StageCSplitFeasibilityError("Task-6 record index is not PASS")
    if report.get("schema_version") != REPORT_SCHEMA or report.get("status") != "PASS":
        raise StageCSplitFeasibilityError("Task-6 report is not PASS")
    if policy.get("schema_version") != POLICY_SCHEMA:
        raise StageCSplitFeasibilityError("unsupported Task-7 policy")
    if index.get("record_count") != 80000 or report.get("record_count") != 80000:
        raise StageCSplitFeasibilityError("Task-6 record count is not frozen at 80000")
    if index.get("class_counts") != {"legitimate": 50000, "phishing": 30000}:
        raise StageCSplitFeasibilityError("Task-6 class counts changed")
    for source in (index, report, policy):
        if source.get("deployment_authorized") is not False:
            raise StageCSplitFeasibilityError("deployment authorization unexpectedly enabled")
    if index.get("model_training_authorized") is not False:
        raise StageCSplitFeasibilityError("Task-6 unexpectedly authorizes training")
    if index.get("feature_extraction_authorized") is not False:
        raise StageCSplitFeasibilityError("Task-6 unexpectedly authorizes feature extraction")
    if index.get("final_holdout_touched") is not False:
        raise StageCSplitFeasibilityError("Task-6 indicates final holdout access")

def build_duplicate_audit(index: Mapping[str, Any]) -> tuple[dict[str, Any], set[str]]:
    records = index.get("records")
    if not isinstance(records, list) or not records:
        raise StageCSplitFeasibilityError("Task-6 records missing or empty")

    by_hash: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in records:
        if not isinstance(row, Mapping):
            raise StageCSplitFeasibilityError("invalid Task-6 record row")
        digest = row.get("html_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise StageCSplitFeasibilityError("invalid html_sha256 in Task-6 index")
        by_hash[digest].append(row)

    duplicate_groups = {h: rows for h, rows in by_hash.items() if len(rows) > 1}
    cross_label = {
        h: rows
        for h, rows in duplicate_groups.items()
        if len({int(x["label"]) for x in rows}) > 1
    }
    same_label = {
        h: rows
        for h, rows in duplicate_groups.items()
        if h not in cross_label
    }

    cross_label_ids = {
        str(row["sample_id"])
        for rows in cross_label.values()
        for row in rows
    }
    oversized_ids = {
        str(row["sample_id"])
        for row in records
        if bool(row.get("oversized_over_12_mib"))
    }
    quarantine_ids = cross_label_ids | oversized_ids

    def group_summary(groups):
        sizes = sorted((len(rows) for rows in groups.values()), reverse=True)
        return {
            "groups": len(groups),
            "samples": sum(sizes),
            "largest_group_samples": sizes[0] if sizes else 0,
            "median_group_samples": (
                sizes[len(sizes)//2] if sizes else 0
            ),
        }

    cross_label_distribution = Counter()
    for rows in cross_label.values():
        labels = tuple(sorted(Counter(int(x["label"]) for x in rows).items()))
        cross_label_distribution[str(labels)] += 1

    audit = {
        "schema_version": AUDIT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "record_count": len(records),
        "unique_artifacts": len(by_hash),
        "duplicate_artifacts": group_summary(duplicate_groups),
        "same_label_duplicate_artifacts": group_summary(same_label),
        "cross_label_duplicate_artifacts": group_summary(cross_label),
        "cross_label_group_label_composition_counts": dict(sorted(cross_label_distribution.items())),
        "oversized_sample_count": len(oversized_ids),
        "quarantine_union_count": len(quarantine_ids),
        "quarantine_overlap_cross_label_and_oversized": len(cross_label_ids & oversized_ids),
        "quarantine_sample_set_sha256": canonical_hash(sorted(quarantine_ids)),
        "eligible_sample_count": len(records) - len(quarantine_ids),
        "interpretation": {
            "cross_label_exact_html": (
                "Exact-byte-identical HTML carrying both labels is excluded from Stage-C supervised "
                "development because HTML artifact identity cannot resolve contradictory labels and "
                "row-wise splitting would create direct artifact leakage."
            ),
            "same_label_duplicates": (
                "Same-label exact duplicates may remain eligible only as indivisible artifact groups; "
                "all members of a group must remain in the same partition or bridge quarantine."
            ),
            "oversized_html": (
                "Canonical HTML over 12 MiB is excluded from automated Stage-C replay until a separate "
                "bounded-ingestion policy explicitly handles it."
            ),
        },
    }
    audit["audit_evidence_sha256"] = canonical_hash(audit)
    return audit, quarantine_ids

def _quantile(values: list[datetime], q: float) -> datetime:
    if not values:
        raise StageCSplitFeasibilityError("cannot take quantile of empty timestamp list")
    q = min(1.0, max(0.0, q))
    pos = q * (len(values) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    # choose an observed timestamp deterministically rather than interpolating timestamps
    return values[lo if (pos - lo) < 0.5 else hi]

def _frange(start: float, stop: float, step: float):
    n = int(round((stop - start) / step))
    for i in range(n + 1):
        yield round(start + i * step, 10)

def build_artifact_groups(index: Mapping[str, Any], quarantine_ids: set[str]) -> list[dict[str, Any]]:
    by_hash: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in index["records"]:
        if str(row["sample_id"]) in quarantine_ids:
            continue
        by_hash[str(row["html_sha256"])].append(row)

    groups = []
    for digest, rows in by_hash.items():
        labels = {int(x["label"]) for x in rows}
        if len(labels) != 1:
            raise StageCSplitFeasibilityError(
                "cross-label artifact survived quarantine"
            )
        times = [parse_time(str(x["created_date"])) for x in rows]
        groups.append({
            "artifact_sha256": digest,
            "label": next(iter(labels)),
            "samples": len(rows),
            "min_time": min(times),
            "max_time": max(times),
        })
    groups.sort(key=lambda x: (x["min_time"], x["max_time"], x["artifact_sha256"]))
    return groups

def evaluate_cutoffs(groups: list[dict[str, Any]], c1: datetime, c2: datetime) -> dict[str, Any]:
    if not c1 < c2:
        raise StageCSplitFeasibilityError("cutoffs must be strictly increasing")

    counts = {
        "train": Counter(),
        "selection": Counter(),
        "calibration": Counter(),
        "bridge": Counter(),
    }
    group_counts = Counter()

    for g in groups:
        mn, mx = g["min_time"], g["max_time"]
        label = int(g["label"])
        samples = int(g["samples"])
        if mx < c1:
            part = "train"
        elif mn >= c1 and mx < c2:
            part = "selection"
        elif mn >= c2:
            part = "calibration"
        else:
            part = "bridge"
        counts[part][label] += samples
        group_counts[part] += 1

    def render(counter: Counter):
        return {
            "total": counter[0] + counter[1],
            "legitimate": counter[0],
            "phishing": counter[1],
        }

    return {
        "first_cutoff": c1.isoformat(sep=" "),
        "second_cutoff": c2.isoformat(sep=" "),
        "partitions": {
            "train": render(counts["train"]),
            "selection": render(counts["selection"]),
            "calibration": render(counts["calibration"]),
        },
        "bridge_quarantine": render(counts["bridge"]),
        "artifact_groups": {
            "train": group_counts["train"],
            "selection": group_counts["selection"],
            "calibration": group_counts["calibration"],
            "bridge": group_counts["bridge"],
        },
    }

def score_candidate(candidate: Mapping[str, Any], eligible_count: int, policy: Mapping[str, Any]) -> tuple:
    targets = policy["chronology"]["target_record_fractions"]
    partitions = candidate["partitions"]

    fraction_error = 0.0
    for part in ("train", "selection", "calibration"):
        actual = partitions[part]["total"] / max(eligible_count, 1)
        fraction_error += abs(actual - float(targets[part]))

    bridge = candidate["bridge_quarantine"]["total"]
    bridge_fraction = bridge / max(eligible_count, 1)

    floors = policy["planning_floors"]
    floor_deficit = 0
    for part in ("selection", "calibration"):
        for label in ("legitimate", "phishing"):
            floor_deficit += max(
                0,
                int(floors[part][label]) - int(partitions[part][label])
            )

    # prioritize satisfying floors, then bridge minimization, then target fractions
    return (floor_deficit, bridge_fraction, fraction_error)

def analyze_temporal_feasibility(
    *,
    index: Mapping[str, Any],
    quarantine_ids: set[str],
    audit: Mapping[str, Any],
    policy: Mapping[str, Any],
    max_results: int = 20,
) -> dict[str, Any]:
    groups = build_artifact_groups(index, quarantine_ids)
    eligible_times = sorted(
        parse_time(str(row["created_date"]))
        for row in index["records"]
        if str(row["sample_id"]) not in quarantine_ids
    )
    if not eligible_times:
        raise StageCSplitFeasibilityError("no eligible records after quarantine")

    grid = policy["chronology"]["candidate_quantile_grid"]
    first_cutoffs = sorted(set(
        _quantile(eligible_times, q)
        for q in _frange(
            float(grid["first_cutoff_min"]),
            float(grid["first_cutoff_max"]),
            float(grid["first_cutoff_step"]),
        )
    ))
    second_cutoffs = sorted(set(
        _quantile(eligible_times, q)
        for q in _frange(
            float(grid["second_cutoff_min"]),
            float(grid["second_cutoff_max"]),
            float(grid["second_cutoff_step"]),
        )
    ))

    eligible_count = int(audit["eligible_sample_count"])
    candidates = []
    floors = policy["planning_floors"]

    for c1 in first_cutoffs:
        for c2 in second_cutoffs:
            if c1 >= c2:
                continue
            item = evaluate_cutoffs(groups, c1, c2)
            item["planning_floors_satisfied"] = all(
                item["partitions"][part][label] >= int(floors[part][label])
                for part in ("selection", "calibration")
                for label in ("legitimate", "phishing")
            )
            item["_score"] = score_candidate(item, eligible_count, policy)
            candidates.append(item)

    candidates.sort(key=lambda x: (
        x["_score"],
        x["first_cutoff"],
        x["second_cutoff"],
    ))
    for rank, item in enumerate(candidates, 1):
        item["rank"] = rank
        item["score"] = {
            "planning_floor_deficit": item["_score"][0],
            "bridge_fraction": item["_score"][1],
            "target_fraction_absolute_error": item["_score"][2],
        }
        del item["_score"]

    feasible = [x for x in candidates if x["planning_floors_satisfied"]]
    best = feasible[0] if feasible else (candidates[0] if candidates else None)

    result = {
        "schema_version": FEAS_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "input_record_count": index["record_count"],
        "quarantine_sample_count": len(quarantine_ids),
        "eligible_sample_count": eligible_count,
        "eligible_artifact_groups": len(groups),
        "eligible_time_min": eligible_times[0].isoformat(sep=" "),
        "eligible_time_max": eligible_times[-1].isoformat(sep=" "),
        "candidate_pairs_examined": len(candidates),
        "planning_floor_feasible_pairs": len(feasible),
        "feasibility": (
            "STRICT_FORWARD_ARTIFACT_GROUP_SPLIT_FEASIBLE"
            if feasible
            else "NO_PLANNING_FLOOR_FEASIBLE_PAIR"
        ),
        "recommended_candidate": best,
        "top_candidates": candidates[:max_results],
        "policy_sha256": canonical_hash(policy),
        "duplicate_audit_sha256": audit["audit_evidence_sha256"],
        "next_gate": (
            "FREEZE_STAGE_C_DEVELOPMENT_SPLIT_CONTRACT"
            if feasible
            else "REVISE_STAGE_C_DEVELOPMENT_SPLIT_PLAN"
        ),
    }
    result["feasibility_evidence_sha256"] = canonical_hash(result)
    return result
