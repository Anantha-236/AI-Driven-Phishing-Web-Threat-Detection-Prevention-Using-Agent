"""Strict dataset/split checks and finite-sample contextual model reporting."""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter

import numpy as np
from sklearn.metrics import (accuracy_score, auc, average_precision_score, brier_score_loss,
    confusion_matrix, f1_score, log_loss, precision_recall_curve, precision_score,
    recall_score, roc_auc_score)

PARTITIONS = ("train", "selection", "calibration", "test")
LABEL_SOURCES = {
    "REAL": {"INDEPENDENT_REVIEW", "VERIFIED_SOURCE_REVIEW"},
    "ARCHIVED": {"INDEPENDENT_REVIEW", "VERIFIED_SOURCE_REVIEW"},
    "CONTROLLED": {"CONTROLLED_SCENARIO_SPEC"},
    "SYNTHETIC": {"SYNTHETIC_AUTHOR_SPEC"},
}
EVENT_KEYS = {
    "event_type", "sensitive_type", "field_id", "form_id", "frame_origin", "target_origin",
    "destination_origin", "initiator_origin", "request_type", "interaction_type", "timestamp_ms",
    "schema_version", "session_id", "tab_id", "document_id", "frame_id", "parent_frame_id",
    "event_seq", "received_ms", "trust", "confidence", "evidence_status", "analysis_version",
    "model_version", "policy_version", "page_purpose", "purpose_source",
}


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def validate_context_dataset(data, feature_names):
    """Reject label feedback, stale features, secret-bearing events and split leakage.

    A declared reviewed label is not independently established by this validator.
    Its review reference and provenance remain part of the external data audit.
    """
    if data.get("protocol") != "contextual-training-1" or data.get("feature_version") != "context-features-1":
        raise ValueError("Unsupported contextual dataset protocol or feature version")
    if data.get("feature_names") != list(feature_names) or data.get("representation") != "contextual-flat":
        raise ValueError("Ordered contextual feature contract mismatch")
    provenance = data.get("provenance")
    if provenance not in LABEL_SOURCES:
        raise ValueError("Explicit dataset provenance required")
    rows = data.get("episodes", [])
    if not rows:
        raise ValueError("Empty contextual dataset")
    seen = set()
    indices = {name: [] for name in PARTITIONS}
    for i, row in enumerate(rows):
        sid = row.get("session_id")
        if not isinstance(sid, str) or not sid or sid in seen:
            raise ValueError("Session identity missing or duplicated")
        seen.add(sid)
        if row.get("provenance") != provenance:
            raise ValueError("Provenance must not be silently mixed")
        if type(row.get("ground_truth")) is not int or row["ground_truth"] not in (0, 1):
            raise ValueError("Ground truth must be explicit binary author/review label")
        if row.get("label_source") not in LABEL_SOURCES[provenance] or row.get("label_validated") is not True:
            raise ValueError("Validated independent label source required; predictions are never labels")
        if not isinstance(row.get("label_validation_reference"), str) or not row["label_validation_reference"].strip():
            raise ValueError("Label review/scenario reference required")
        if row.get("partition") not in indices:
            raise ValueError("Explicit train, selection, calibration, test partitions required")
        indices[row["partition"]].append(i)
        if not row.get("service_category"):
            raise ValueError("Service category or explicit unknown category required")
        events = row.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("Sanitized event timeline required")
        if any(not isinstance(event, dict) or set(event) - EVENT_KEYS for event in events):
            raise ValueError("Unexpected event fields: possible privacy boundary violation")
        if canonical_hash(events) != row.get("events_sha256"):
            raise ValueError("Event evidence hash mismatch")
        vector = row.get("feature_vector")
        if not isinstance(vector, list) or len(vector) != len(feature_names):
            raise ValueError("Feature vector shape mismatch")
        for name, value in zip(feature_names, vector, strict=True):
            bound = 1 if name.endswith("_ratio") else 10
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= bound:
                raise ValueError(f"Invalid contextual feature {name}")
    manifest = {"partition_order": list(PARTITIONS), "partitions": {}, "group_checks": {}}
    for name, subset in indices.items():
        labels = [rows[i]["ground_truth"] for i in subset]
        if set(labels) != {0, 1}:
            raise ValueError(f"{name} must contain both independently labeled classes")
        manifest["partitions"][name] = dict(sample_count=len(subset), legitimate=labels.count(0), phishing=labels.count(1),
            session_ids=[rows[i]["session_id"] for i in subset])
    for grouping in ("domain_group", "brand_group", "template_group", "pair_id"):
        values = [r.get(grouping) for r in rows]
        if any(v is None or v == "" for v in values):
            manifest["group_checks"][grouping] = {"status": "UNAVAILABLE", "reason": "Missing externally meaningful group labels"}
            continue
        by_partition = {name: {rows[i][grouping] for i in subset} for name, subset in indices.items()}
        for a, left in enumerate(PARTITIONS):
            for right in PARTITIONS[a + 1:]:
                if by_partition[left] & by_partition[right]:
                    raise ValueError(f"{grouping} leakage between {left} and {right}")
        manifest["group_checks"][grouping] = {"status": "PASS", "unique_groups": len(set(values)),
            "groups_by_partition": {k: sorted(v) for k, v in by_partition.items()},
            "scope": "SYNTHETIC_PIPELINE_ONLY" if provenance == "SYNTHETIC" else "DECLARED_GROUP_ISOLATION"}
    times = [row.get("time_group") for row in rows]
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in times):
        manifest["group_checks"]["temporal"] = {"status": "UNAVAILABLE", "reason": "Numeric time groups unavailable"}
    else:
        for left, right in zip(PARTITIONS, PARTITIONS[1:]):
            if max(times[i] for i in indices[left]) >= min(times[i] for i in indices[right]):
                raise ValueError(f"Temporal leakage/order violation between {left} and {right}")
        manifest["group_checks"]["temporal"] = {"status": "PASS", "time_basis": sorted({row.get("time_basis", "UNSPECIFIED") for row in rows}),
            "scope": "SYNTHETIC_PIPELINE_ONLY" if provenance == "SYNTHETIC" else "DECLARED_CHRONOLOGY"}
    return indices, manifest


def wilson_interval(successes, count):
    if not count:
        return None
    z = 1.959963984540054
    p = successes / count
    denominator = 1 + z * z / count
    center = (p + z * z / (2 * count)) / denominator
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * count)) / count) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def contextual_metrics(labels, scores, threshold=0.5):
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    if labels.shape != scores.shape or not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
        raise ValueError("Invalid score array")
    predicted = scores >= threshold
    tn, fp, fn, tp = (int(x) for x in confusion_matrix(labels, predicted, labels=[0, 1]).ravel())
    both = len(set(labels)) == 2
    precision_curve, recall_curve, _ = precision_recall_curve(labels, scores)
    bins = []
    ece = 0.0
    for lower, upper in zip(np.linspace(0, 1, 6)[:-1], np.linspace(0, 1, 6)[1:]):
        mask = (scores >= lower) & (scores <= upper if upper == 1 else scores < upper)
        count = int(mask.sum())
        mean = float(scores[mask].mean()) if count else None
        observed = float(labels[mask].mean()) if count else None
        bins.append(dict(lower=float(lower), upper=float(upper), count=count, mean_score=mean, observed_fraction=observed))
        if count:
            ece += count / len(labels) * abs(mean - observed)
    return dict(sample_count=len(labels), threshold=threshold, accuracy=float(accuracy_score(labels, predicted)),
        precision=float(precision_score(labels, predicted, zero_division=0)), recall=float(recall_score(labels, predicted, zero_division=0)),
        f1=float(f1_score(labels, predicted, zero_division=0)),
        average_precision=float(average_precision_score(labels, scores)) if both else None,
        pr_auc_trapezoidal=float(auc(recall_curve, precision_curve)) if both else None,
        roc_auc=float(roc_auc_score(labels, scores)) if both else None,
        fpr=fp / (fp + tn) if fp + tn else None, fnr=fn / (fn + tp) if fn + tp else None,
        fpr_wilson_95=wilson_interval(fp, fp + tn), fnr_wilson_95=wilson_interval(fn, fn + tp),
        interval_limitation="Binomial reference assumes independent trials; dependent authored fixtures do not establish population error bounds.",
        confusion_matrix=dict(tn=tn, fp=fp, fn=fn, tp=tp), brier_score=float(brier_score_loss(labels, scores)),
        log_loss=float(log_loss(labels, np.column_stack([1 - scores, scores]), labels=[0, 1])),
        expected_calibration_error_5_bins=float(ece), calibration_bins=bins)


def observable_ambiguity(rows):
    counts = {}
    for row in rows:
        key = tuple(row["feature_vector"])
        counts.setdefault(key, Counter())[row["ground_truth"]] += 1
    collisions = [labels for labels in counts.values() if len(labels) == 2]
    unavoidable = sum(min(labels.values()) for labels in collisions)
    return dict(opposing_label_feature_vectors=len(collisions), minimum_errors_from_identical_vectors=unavoidable,
                maximum_accuracy_on_these_fixed_vectors=1 - unavoidable / len(rows),
                interpretation="Descriptive bound for these fixed labels and vectors; no claim about real-world performance.")
