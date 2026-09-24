"""Controlled labeled Stage B shadow evaluation.

This module evaluates authored loopback fixtures only. It is intentionally
separate from the locked Stage B train/selection/calibration/final-test chain.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

DATASET_SCHEMA = "stage-b-controlled-shadow-dataset-1"
REPORT_SCHEMA = "stage-b-controlled-shadow-evaluation-1"
PRIMARY_FAMILIES = {"1", "2", "3", "4", "5"}
AMBIGUITY_FAMILY = "6"


class ControlledShadowEvaluationError(ValueError):
    pass


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _confusion(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in rows:
        pred = row[key]
        label = int(row["label"])
        if pred and label == 1:
            tp += 1
        elif pred and label == 0:
            fp += 1
        elif not pred and label == 0:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": total,
        "accuracy": _rate(tp + tn, total),
        "recall": _rate(tp, tp + fn),
        "precision": _rate(tp, tp + fp),
        "specificity": _rate(tn, tn + fp),
        "false_positive_rate": _rate(fp, fp + tn),
        "false_negative_rate": _rate(fn, fn + tp),
    }


def _validate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "case_id", "family", "layout", "label",
        "baseline_action", "baseline_intervention",
        "stage_b_status", "stage_b_score", "stage_b_intervention",
        "stage_b_threshold", "stage_b_latency_ms",
        "stage_b_model_id", "stage_b_integration_eligible",
    }
    missing = required - set(record)
    if missing:
        raise ControlledShadowEvaluationError(f"record missing fields: {sorted(missing)}")

    forbidden = {
        "url", "target_url", "page_url", "frame_origin", "target_origin",
        "document_id", "form_id", "event_payload", "events", "session_id", "tab_id",
    }
    present = forbidden & set(record)
    if present:
        raise ControlledShadowEvaluationError(f"privacy-unsafe record fields: {sorted(present)}")

    family = str(record["family"])
    if family not in {"1", "2", "3", "4", "5", "6"}:
        raise ControlledShadowEvaluationError(f"unsupported controlled family: {family}")
    layout = int(record["layout"])
    label = int(record["label"])
    if layout not in {0, 1} or label not in {0, 1}:
        raise ControlledShadowEvaluationError("layout/label must be binary")

    baseline_action = str(record["baseline_action"])
    if baseline_action not in {"ALLOW", "WARN", "CONFIRM"}:
        raise ControlledShadowEvaluationError(f"unsupported baseline action: {baseline_action}")
    baseline_intervention = bool(record["baseline_intervention"])
    if baseline_intervention != (baseline_action != "ALLOW"):
        raise ControlledShadowEvaluationError("baseline intervention/action mismatch")

    status = str(record["stage_b_status"])
    if status not in {"NOT_INSTALLED", "READY", "OBSERVED", "ERROR"}:
        raise ControlledShadowEvaluationError(f"invalid Stage B status: {status}")

    stage_intervention = record["stage_b_intervention"]
    score = record["stage_b_score"]
    threshold = record["stage_b_threshold"]
    latency = record["stage_b_latency_ms"]

    if status == "OBSERVED":
        if not isinstance(stage_intervention, bool):
            raise ControlledShadowEvaluationError("OBSERVED Stage B record needs a boolean intervention")
        for name, value in (("score", score), ("threshold", threshold), ("latency", latency)):
            if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ControlledShadowEvaluationError(f"OBSERVED Stage B record has invalid {name}")
        if not 0 <= float(score) <= 1 or not 0 <= float(threshold) <= 1 or float(latency) < 0:
            raise ControlledShadowEvaluationError("OBSERVED Stage B numeric range invalid")
        if stage_intervention != (float(score) >= float(threshold)):
            raise ControlledShadowEvaluationError("Stage B intervention/threshold mismatch")
    else:
        if stage_intervention is not None or score is not None:
            raise ControlledShadowEvaluationError("unscored Stage B record must not invent score/intervention")

    return {
        "case_id": str(record["case_id"]),
        "family": family,
        "layout": layout,
        "label": label,
        "baseline_action": baseline_action,
        "baseline_intervention": baseline_intervention,
        "stage_b_status": status,
        "stage_b_score": None if score is None else float(score),
        "stage_b_intervention": stage_intervention,
        "stage_b_threshold": None if threshold is None else float(threshold),
        "stage_b_latency_ms": None if latency is None else float(latency),
        "stage_b_model_id": None if record["stage_b_model_id"] is None else str(record["stage_b_model_id"]),
        "stage_b_integration_eligible": (
            None if record["stage_b_integration_eligible"] is None
            else bool(record["stage_b_integration_eligible"])
        ),
    }


def validate_controlled_shadow_dataset(dataset: Mapping[str, Any]) -> dict[str, Any]:
    if dataset.get("schema_version") != DATASET_SCHEMA:
        raise ControlledShadowEvaluationError("unsupported controlled shadow dataset schema")
    if dataset.get("protocol") != "CONTROLLED_NON_FINAL":
        raise ControlledShadowEvaluationError("dataset must be explicitly CONTROLLED_NON_FINAL")
    if dataset.get("final_test_reused") is not False:
        raise ControlledShadowEvaluationError("locked Stage B final test must not be reused")

    records_raw = dataset.get("records")
    if not isinstance(records_raw, list) or not records_raw:
        raise ControlledShadowEvaluationError("controlled shadow records are required")
    records = [_validate_record(record) for record in records_raw]
    ids = [row["case_id"] for row in records]
    if len(ids) != len(set(ids)):
        raise ControlledShadowEvaluationError("duplicate controlled case_id")

    return {
        "schema_version": DATASET_SCHEMA,
        "protocol": "CONTROLLED_NON_FINAL",
        "final_test_reused": False,
        "fixture_protocol": str(dataset.get("fixture_protocol", "unknown")),
        "records": records,
    }


def _ambiguity_pairs(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_layout: dict[int, dict[int, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_layout[row["layout"]][row["label"]] = row

    pair_count = 0
    baseline_disagreements = 0
    stage_pairs = 0
    stage_disagreements = 0
    score_deltas: list[float] = []

    for labels in by_layout.values():
        if 0 not in labels or 1 not in labels:
            continue
        pair_count += 1
        a, b = labels[0], labels[1]
        if a["baseline_intervention"] != b["baseline_intervention"]:
            baseline_disagreements += 1
        if a["stage_b_status"] == b["stage_b_status"] == "OBSERVED":
            stage_pairs += 1
            if a["stage_b_intervention"] != b["stage_b_intervention"]:
                stage_disagreements += 1
            score_deltas.append(abs(a["stage_b_score"] - b["stage_b_score"]))

    return {
        "paired_layouts": pair_count,
        "baseline_intervention_pair_disagreements": baseline_disagreements,
        "stage_b_scored_pairs": stage_pairs,
        "stage_b_intervention_pair_disagreements": stage_disagreements,
        "mean_absolute_stage_b_score_pair_delta": (
            sum(score_deltas) / len(score_deltas) if score_deltas else None
        ),
        "interpretation": (
            "Family 6 intentionally presents identical observable metadata for opposing simulated intent. "
            "Pair disagreement is therefore a determinism/hidden-signal diagnostic, not a correctness win."
        ),
    }


def evaluate_controlled_shadow(dataset: Mapping[str, Any]) -> dict[str, Any]:
    validated = validate_controlled_shadow_dataset(dataset)
    records = validated["records"]
    primary = [row for row in records if row["family"] in PRIMARY_FAMILIES]
    ambiguity = [row for row in records if row["family"] == AMBIGUITY_FAMILY]
    observed_primary = [row for row in primary if row["stage_b_status"] == "OBSERVED"]

    baseline_metrics = _confusion(primary, "baseline_intervention")
    stage_metrics = _confusion(observed_primary, "stage_b_intervention") if observed_primary else None

    comparable = observed_primary
    disagreements = [
        row for row in comparable
        if row["baseline_intervention"] != row["stage_b_intervention"]
    ]
    baseline_correct = sum(
        int(row["baseline_intervention"]) == row["label"] for row in disagreements
    )
    stage_correct = sum(
        int(row["stage_b_intervention"]) == row["label"] for row in disagreements
    )

    by_family = {}
    for family in sorted(PRIMARY_FAMILIES):
        rows = [row for row in primary if row["family"] == family]
        observed = [row for row in rows if row["stage_b_status"] == "OBSERVED"]
        by_family[family] = {
            "cases": len(rows),
            "baseline": _confusion(rows, "baseline_intervention"),
            "stage_b": _confusion(observed, "stage_b_intervention") if observed else None,
            "stage_b_scored_cases": len(observed),
        }

    statuses = Counter(row["stage_b_status"] for row in records)
    latencies = [
        row["stage_b_latency_ms"] for row in records
        if row["stage_b_status"] == "OBSERVED" and row["stage_b_latency_ms"] is not None
    ]
    model_ids = sorted({
        row["stage_b_model_id"] for row in records if row["stage_b_model_id"]
    })

    return {
        "schema_version": REPORT_SCHEMA,
        "status": "PASS",
        "source_protocol": validated["protocol"],
        "fixture_protocol": validated["fixture_protocol"],
        "final_test_reused": False,
        "decision_authority": "SHADOW_ONLY",
        "promotion_decision": "NOT_PERMITTED_FROM_CONTROLLED_FIXTURES",
        "case_counts": {
            "total": len(records),
            "primary_families_1_to_5": len(primary),
            "ambiguity_family_6": len(ambiguity),
        },
        "stage_b_status_counts": dict(sorted(statuses.items())),
        "stage_b_primary_coverage": _rate(len(observed_primary), len(primary)),
        "baseline_primary_metrics": baseline_metrics,
        "stage_b_primary_metrics": stage_metrics,
        "disagreement_analysis": {
            "comparable_cases": len(comparable),
            "disagreement_cases": len(disagreements),
            "disagreement_rate": _rate(len(disagreements), len(comparable)),
            "baseline_correct_when_disagree": baseline_correct,
            "stage_b_correct_when_disagree": stage_correct,
            "ties_or_neither_when_disagree": (
                len(disagreements) - baseline_correct - stage_correct
            ),
        },
        "family_metrics": by_family,
        "ambiguity_family_6": _ambiguity_pairs(ambiguity),
        "latency": {
            "observations": len(latencies),
            "mean_ms": sum(latencies) / len(latencies) if latencies else None,
            "max_ms": max(latencies) if latencies else None,
        },
        "model_ids": model_ids,
        "limitations": [
            "All labels are authored controlled-fixture intent, not real-world adjudication.",
            "Families share loopback infrastructure and are not independent domains, brands, users, or campaigns.",
            "Family 6 labels are intentionally observationally indistinguishable and are excluded from primary correctness metrics.",
            "This dataset is separate from and cannot replace, reopen, or reinterpret the locked Stage B final test.",
            "Controlled-fixture results cannot establish population phishing recall, precision, or false-positive rate.",
            "No deployment or promotion decision is permitted from this report.",
        ],
    }


def evaluate_file(input_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    dataset = json.loads(Path(input_path).read_text(encoding="utf-8"))
    report = evaluate_controlled_shadow(dataset)
    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
