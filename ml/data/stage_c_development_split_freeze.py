
"""Stage C Task 8 — freeze the development split contract."""
from __future__ import annotations
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Mapping

from .stage_c_duplicate_split_feasibility import (
    build_duplicate_audit,
    canonical_hash,
    load_json,
    parse_time,
)

CONTRACT_SCHEMA = "stage-c-development-split-contract-1"
MANIFEST_SCHEMA = "stage-c-development-split-manifest-1"
QUARANTINE_SCHEMA = "stage-c-development-split-quarantine-1"

class StageCSplitFreezeError(ValueError):
    pass

def frozen_write_json(path: Path, value: Any) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = json.loads(path.read_text(encoding="utf-8"))
        if current != value:
            raise StageCSplitFreezeError(
                f"refusing to replace non-identical frozen Task-8 output: {path}"
            )
        return "EXISTING_MATCH"
    path.write_text(rendered, encoding="utf-8")
    return "CREATED"

def _require_inputs(index: Mapping[str, Any], task6_report: Mapping[str, Any],
                    audit: Mapping[str, Any], feasibility: Mapping[str, Any]) -> None:
    if index.get("schema_version") != "stage-c-development-record-index-1" or index.get("status") != "PASS":
        raise StageCSplitFreezeError("Task-6 development record index is not PASS")
    if task6_report.get("schema_version") != "stage-c-development-record-index-report-1" or task6_report.get("status") != "PASS":
        raise StageCSplitFreezeError("Task-6 report is not PASS")
    if audit.get("schema_version") != "stage-c-development-duplicate-audit-1" or audit.get("status") != "PASS":
        raise StageCSplitFreezeError("Task-7 duplicate audit is not PASS")
    if feasibility.get("schema_version") != "stage-c-development-temporal-feasibility-1" or feasibility.get("status") != "PASS":
        raise StageCSplitFreezeError("Task-7 split feasibility is not PASS")
    if feasibility.get("feasibility") != "STRICT_FORWARD_ARTIFACT_GROUP_SPLIT_FEASIBLE":
        raise StageCSplitFreezeError("Task-7 did not establish strict-forward feasibility")
    if feasibility.get("next_gate") != "FREEZE_STAGE_C_DEVELOPMENT_SPLIT_CONTRACT":
        raise StageCSplitFreezeError("Task-7 next gate does not authorize split freeze")

    candidate = feasibility.get("recommended_candidate")
    if not isinstance(candidate, Mapping):
        raise StageCSplitFreezeError("Task-7 recommended candidate missing")
    if candidate.get("rank") != 1:
        raise StageCSplitFreezeError("Task-7 recommended candidate is not frozen rank 1")
    if candidate.get("planning_floors_satisfied") is not True:
        raise StageCSplitFreezeError("Task-7 recommended candidate does not satisfy planning floors")
    if candidate.get("score", {}).get("planning_floor_deficit") != 0:
        raise StageCSplitFreezeError("Task-7 recommended candidate has planning floor deficit")

    for name, source in (
        ("Task-6 index", index),
        ("Task-6 report", task6_report),
        ("Task-7 audit", audit),
        ("Task-7 feasibility", feasibility),
    ):
        if source.get("deployment_authorized") is not False:
            raise StageCSplitFreezeError(f"{name} unexpectedly authorizes deployment")
        if source.get("final_holdout_touched") is not False:
            raise StageCSplitFreezeError(f"{name} indicates final holdout access")

    if index.get("model_training_authorized") is not False:
        raise StageCSplitFreezeError("Task-6 unexpectedly authorizes training")
    if index.get("feature_extraction_authorized") is not False:
        raise StageCSplitFreezeError("Task-6 unexpectedly authorizes feature extraction")

    if index.get("record_count") != 80000:
        raise StageCSplitFreezeError("Task-6 record count changed")
    if task6_report.get("record_count") != 80000:
        raise StageCSplitFreezeError("Task-6 report record count changed")
    if audit.get("record_count") != 80000:
        raise StageCSplitFreezeError("Task-7 audit record count changed")
    if feasibility.get("input_record_count") != 80000:
        raise StageCSplitFreezeError("Task-7 feasibility input count changed")
    if task6_report.get("record_set_sha256") != index.get("record_set_sha256"):
        raise StageCSplitFreezeError("Task-6 record-set identity mismatch")

def _partition_for_group(min_time, max_time, first_cutoff, second_cutoff) -> str:
    if max_time < first_cutoff:
        return "train"
    if min_time >= first_cutoff and max_time < second_cutoff:
        return "selection"
    if min_time >= second_cutoff:
        return "calibration"
    return "bridge"

def freeze_development_split(*, index: Mapping[str, Any], task6_report: Mapping[str, Any],
                             audit: Mapping[str, Any], feasibility: Mapping[str, Any]):
    _require_inputs(index, task6_report, audit, feasibility)

    records = index.get("records")
    expected_input_count = int(index.get("record_count", -1))
    if not isinstance(records, list) or len(records) != expected_input_count:
        raise StageCSplitFreezeError(
            f"Task-6 record rows missing: expected={expected_input_count} actual={len(records) if isinstance(records, list) else 'invalid'}"
        )

    reproduced_audit, initial_quarantine_ids = build_duplicate_audit(index)
    if reproduced_audit["quarantine_sample_set_sha256"] != audit.get("quarantine_sample_set_sha256"):
        raise StageCSplitFreezeError("Task-7 initial quarantine identity does not reproduce")
    if reproduced_audit["quarantine_union_count"] != audit.get("quarantine_union_count"):
        raise StageCSplitFreezeError("Task-7 initial quarantine count does not reproduce")

    candidate = feasibility["recommended_candidate"]
    first_cutoff = parse_time(candidate["first_cutoff"])
    second_cutoff = parse_time(candidate["second_cutoff"])
    if not first_cutoff < second_cutoff:
        raise StageCSplitFreezeError("Task-7 cutoffs are not strictly increasing")

    eligible_by_hash = defaultdict(list)
    for row in records:
        if str(row["sample_id"]) in initial_quarantine_ids:
            continue
        eligible_by_hash[str(row["html_sha256"])].append(row)

    partitions = {"train": [], "selection": [], "calibration": []}
    bridge_entries = []
    partition_artifacts = {"train": set(), "selection": set(), "calibration": set(), "bridge": set()}

    for artifact_sha, rows in eligible_by_hash.items():
        labels = {int(x["label"]) for x in rows}
        if len(labels) != 1:
            raise StageCSplitFreezeError("cross-label artifact survived Task-7 quarantine")
        times = [parse_time(str(x["created_date"])) for x in rows]
        part = _partition_for_group(min(times), max(times), first_cutoff, second_cutoff)
        partition_artifacts[part].add(artifact_sha)
        for row in rows:
            entry = {
                "sample_id": str(row["sample_id"]),
                "rec_id": int(row["rec_id"]),
                "label": int(row["label"]),
                "created_date": str(row["created_date"]),
                "html_sha256": artifact_sha,
            }
            if part == "bridge":
                entry["reason"] = "ARTIFACT_GROUP_SPANS_STRICT_FORWARD_CUTOFF"
                bridge_entries.append(entry)
            else:
                partitions[part].append(entry)

    for part in partitions:
        partitions[part].sort(key=lambda x: (x["created_date"], x["rec_id"], x["sample_id"]))
    bridge_entries.sort(key=lambda x: (x["created_date"], x["rec_id"], x["sample_id"]))

    by_hash_all = defaultdict(list)
    for row in records:
        by_hash_all[str(row["html_sha256"])].append(row)
    cross_label_hashes = {
        h for h, rows in by_hash_all.items()
        if len({int(x["label"]) for x in rows}) > 1
    }

    initial_entries = []
    for row in records:
        sample_id = str(row["sample_id"])
        if sample_id not in initial_quarantine_ids:
            continue
        reasons = []
        if str(row["html_sha256"]) in cross_label_hashes:
            reasons.append("CROSS_LABEL_EXACT_HTML_GROUP")
        if bool(row.get("oversized_over_12_mib")):
            reasons.append("OVERSIZED_CANONICAL_HTML_OVER_12_MIB")
        if not reasons:
            raise StageCSplitFreezeError("Task-7 quarantine sample has no reproducible reason")
        initial_entries.append({
            "sample_id": sample_id,
            "rec_id": int(row["rec_id"]),
            "label": int(row["label"]),
            "created_date": str(row["created_date"]),
            "html_sha256": str(row["html_sha256"]),
            "reasons": reasons,
        })
    initial_entries.sort(key=lambda x: (x["created_date"], x["rec_id"], x["sample_id"]))

    names = ["train", "selection", "calibration", "bridge"]
    overlaps = {}
    for i, left in enumerate(names):
        for right in names[i+1:]:
            count = len(partition_artifacts[left].intersection(partition_artifacts[right]))
            overlaps[f"{left}__{right}"] = count
            if count:
                raise StageCSplitFreezeError(f"artifact leakage across {left}/{right}: {count}")

    def counts(rows):
        c = Counter(int(x["label"]) for x in rows)
        return {"total": len(rows), "legitimate": c[0], "phishing": c[1]}

    actual_partition_counts = {part: counts(rows) for part, rows in partitions.items()}
    actual_bridge_counts = counts(bridge_entries)

    for part in ("train", "selection", "calibration"):
        if actual_partition_counts[part] != candidate["partitions"][part]:
            raise StageCSplitFreezeError(
                f"reproduced {part} counts differ from Task-7 recommendation"
            )
    if actual_bridge_counts != candidate["bridge_quarantine"]:
        raise StageCSplitFreezeError("reproduced bridge counts differ from Task-7 recommendation")

    total_accounted = len(initial_entries) + len(bridge_entries) + sum(len(x) for x in partitions.values())
    if total_accounted != expected_input_count:
        raise StageCSplitFreezeError(
            f"Task-8 sample accounting mismatch: expected={expected_input_count} actual={total_accounted}"
        )

    train_max = max((parse_time(x["created_date"]) for x in partitions["train"]), default=None)
    selection_min = min((parse_time(x["created_date"]) for x in partitions["selection"]), default=None)
    selection_max = max((parse_time(x["created_date"]) for x in partitions["selection"]), default=None)
    calibration_min = min((parse_time(x["created_date"]) for x in partitions["calibration"]), default=None)

    if train_max and not train_max < first_cutoff:
        raise StageCSplitFreezeError("train chronology crosses first cutoff")
    if selection_min and not selection_min >= first_cutoff:
        raise StageCSplitFreezeError("selection starts before first cutoff")
    if selection_max and not selection_max < second_cutoff:
        raise StageCSplitFreezeError("selection crosses second cutoff")
    if calibration_min and not calibration_min >= second_cutoff:
        raise StageCSplitFreezeError("calibration starts before second cutoff")

    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": False,
        "model_training_authorized": False,
        "final_holdout_touched": False,
        "first_cutoff": candidate["first_cutoff"],
        "second_cutoff": candidate["second_cutoff"],
        "partitions": partitions,
        "partition_counts": actual_partition_counts,
        "partition_sample_set_sha256": {
            part: canonical_hash(sorted(x["sample_id"] for x in rows))
            for part, rows in partitions.items()
        },
        "partition_artifact_set_sha256": {
            part: canonical_hash(sorted(partition_artifacts[part]))
            for part in ("train", "selection", "calibration")
        },
    }
    manifest["manifest_sha256"] = canonical_hash(manifest)

    quarantine = {
        "schema_version": QUARANTINE_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "research_only": True,
        "supervised_use_authorized": False,
        "final_holdout_touched": False,
        "initial_quarantine": {
            "count": len(initial_entries),
            "entries": initial_entries,
            "sample_set_sha256": audit["quarantine_sample_set_sha256"],
        },
        "chronology_bridge_quarantine": {
            "count": len(bridge_entries),
            "counts": actual_bridge_counts,
            "entries": bridge_entries,
            "sample_set_sha256": canonical_hash(sorted(x["sample_id"] for x in bridge_entries)),
            "artifact_set_sha256": canonical_hash(sorted(partition_artifacts["bridge"])),
        },
        "total_quarantine_count": len(initial_entries) + len(bridge_entries),
    }
    quarantine["quarantine_manifest_sha256"] = canonical_hash(quarantine)

    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "feature_extraction_authorized": False,
        "model_training_authorized": False,
        "final_holdout_touched": False,
        "source_identities": {
            "task6_record_set_sha256": task6_report["record_set_sha256"],
            "task6_index_evidence_sha256": task6_report["index_evidence_sha256"],
            "task7_duplicate_audit_sha256": audit["audit_evidence_sha256"],
            "task7_feasibility_evidence_sha256": feasibility["feasibility_evidence_sha256"],
            "task7_quarantine_sample_set_sha256": audit["quarantine_sample_set_sha256"],
        },
        "selection_rationale": {
            "candidate_rank": candidate["rank"],
            "planning_floors_satisfied": candidate["planning_floors_satisfied"],
            "planning_floor_deficit": candidate["score"]["planning_floor_deficit"],
            "bridge_fraction": candidate["score"]["bridge_fraction"],
            "target_fraction_absolute_error": candidate["score"]["target_fraction_absolute_error"],
            "objective_order": [
                "planning_floor_deficit",
                "bridge_fraction",
                "target_fraction_absolute_error",
            ],
            "interpretation": (
                "The frozen Task-7 policy prioritizes class-floor satisfaction, then "
                "bridge minimization, then target-fraction approximation. The 60/20/20 "
                "development fractions are a soft planning target."
            ),
        },
        "cutoffs": {
            "first": candidate["first_cutoff"],
            "second": candidate["second_cutoff"],
            "strict_forward": True,
        },
        "counts": {
            "input": expected_input_count,
            "initial_quarantine": len(initial_entries),
            "bridge_quarantine": len(bridge_entries),
            "train": actual_partition_counts["train"],
            "selection": actual_partition_counts["selection"],
            "calibration": actual_partition_counts["calibration"],
            "total_quarantined": len(initial_entries) + len(bridge_entries),
            "total_supervised_development": sum(x["total"] for x in actual_partition_counts.values()),
        },
        "chronology_proof": {
            "train_max": train_max.isoformat(sep=" ") if train_max else None,
            "selection_min": selection_min.isoformat(sep=" ") if selection_min else None,
            "selection_max": selection_max.isoformat(sep=" ") if selection_max else None,
            "calibration_min": calibration_min.isoformat(sep=" ") if calibration_min else None,
        },
        "artifact_isolation": {
            "dimension": "html_sha256",
            "pairwise_overlap_counts": overlaps,
            "all_zero": all(v == 0 for v in overlaps.values()),
        },
        "partition_manifest_sha256": manifest["manifest_sha256"],
        "quarantine_manifest_sha256": quarantine["quarantine_manifest_sha256"],
        "next_gate": "REGISTER_STAGE_C_DEVELOPMENT_SPLIT_AND_AUTHORIZE_FEATURE_EXTRACTION",
    }
    contract["contract_sha256"] = canonical_hash(contract)
    return contract, manifest, quarantine
