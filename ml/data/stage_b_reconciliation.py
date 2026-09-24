"""Cross-source reconciliation and quarantine for Stage B ingested URL records.

This layer runs before split construction. It collapses exact duplicates, assigns
shared artifact groups to query/path variants, and quarantines verified-label or
source-independence conflicts instead of silently resolving them.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
from typing import Any, Iterable, Mapping

from .stage_b_ingestion import BATCH_SCHEMA, RECORD_SCHEMA


RECONCILED_SCHEMA = "stage-b-reconciled-1"
ALLOWED_RECORD_FIELDS = {
    "schema_version", "sample_id", "dataset_id", "source_record_id",
    "source_group", "source_artifact_sha256", "ground_truth", "label_status",
    "label_source", "observed_at", "hostname", "origin", "domain_group",
    "brand_group", "url_sha256", "origin_path_sha256", "redacted_url",
    "redistribution_allowed", "local_only", "rank",
}


class ReconciliationError(ValueError):
    """Raised when an ingestion batch violates the Stage B reconciliation contract."""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_batch(batch: Mapping[str, Any]) -> list[dict[str, Any]]:
    if batch.get("schema_version") != BATCH_SCHEMA:
        raise ReconciliationError("unsupported ingestion batch schema")
    dataset_id = batch.get("dataset_id")
    if not isinstance(dataset_id, str) or not dataset_id:
        raise ReconciliationError("batch dataset_id is required")
    source = batch.get("source_artifact")
    if not isinstance(source, Mapping):
        raise ReconciliationError("batch source_artifact is required")
    artifact = source.get("sha256")
    source_group = source.get("independence_group")
    if not _is_sha256(artifact):
        raise ReconciliationError("batch source artifact SHA-256 is invalid")
    if not isinstance(source_group, str) or not source_group:
        raise ReconciliationError("batch source independence group is required")

    raw_rows = batch.get("records")
    if not isinstance(raw_rows, list):
        raise ReconciliationError("batch records must be a list")

    rows: list[dict[str, Any]] = []
    for raw in raw_rows:
        if not isinstance(raw, Mapping):
            raise ReconciliationError("ingested record must be an object")
        unexpected = set(raw) - ALLOWED_RECORD_FIELDS
        if unexpected:
            raise ReconciliationError(
                f"unexpected record fields: {', '.join(sorted(unexpected))}"
            )
        if raw.get("schema_version") != RECORD_SCHEMA:
            raise ReconciliationError("unsupported ingested record schema")
        if raw.get("dataset_id") != dataset_id:
            raise ReconciliationError("record dataset_id does not match batch")
        if raw.get("source_group") != source_group:
            raise ReconciliationError("record source_group does not match batch")
        if raw.get("source_artifact_sha256") != artifact:
            raise ReconciliationError("record source artifact does not match batch")
        if not _is_sha256(raw.get("url_sha256")) or not _is_sha256(raw.get("origin_path_sha256")):
            raise ReconciliationError("record URL fingerprints must be SHA-256")
        if raw.get("label_status") not in {"VERIFIED_SOURCE_LABEL", "UNLABELED_CANDIDATE"}:
            raise ReconciliationError("unsupported label status")
        label = raw.get("ground_truth")
        if raw.get("label_status") == "VERIFIED_SOURCE_LABEL":
            if type(label) is not int or label not in (0, 1):
                raise ReconciliationError("verified labels must be explicit binary ground truth")
        elif label is not None:
            raise ReconciliationError("unlabeled candidates cannot carry ground truth")
        rows.append(dict(raw))
    return rows


class _UnionFind:
    def __init__(self, count: int) -> None:
        self.parent = list(range(count))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _artifact_group(rows: list[dict[str, Any]]) -> str:
    material = "|".join(sorted({row["url_sha256"] for row in rows}))
    return "artifact-" + _sha256_text(material)[:24]


def _merge_exact_rows(rows: list[dict[str, Any]], artifact_group: str) -> dict[str, Any]:
    verified = [
        row for row in rows
        if row["label_status"] == "VERIFIED_SOURCE_LABEL" and row["ground_truth"] in (0, 1)
    ]
    representative = deepcopy(verified[0] if verified else rows[0])
    representative["artifact_group"] = artifact_group
    representative["source_datasets"] = sorted({row["dataset_id"] for row in rows})
    representative["source_groups"] = sorted({row["source_group"] for row in rows})
    representative["source_artifacts"] = sorted({row["source_artifact_sha256"] for row in rows})
    representative["duplicate_count"] = len(rows)
    if verified:
        representative["ground_truth"] = verified[0]["ground_truth"]
        representative["label_status"] = "VERIFIED_SOURCE_LABEL"
        representative["label_source"] = verified[0].get("label_source")
    else:
        representative["ground_truth"] = None
        representative["label_status"] = "UNLABELED_CANDIDATE"
        representative["label_source"] = None
    return representative


def reconcile_ingestion_batches(batches: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    artifact_groups_by_hash: dict[str, set[str]] = defaultdict(set)
    artifact_record_indices: dict[str, list[int]] = defaultdict(list)

    for batch in batches:
        batch_rows = _validate_batch(batch)
        artifact = batch["source_artifact"]["sha256"]
        source_group = batch["source_artifact"]["independence_group"]
        artifact_groups_by_hash[artifact].add(source_group)
        start = len(rows)
        rows.extend(batch_rows)
        artifact_record_indices[artifact].extend(range(start, len(rows)))

    uf = _UnionFind(len(rows))
    by_url: dict[str, int] = {}
    by_origin_path: dict[str, int] = {}
    for index, row in enumerate(rows):
        url_hash = row["url_sha256"]
        origin_path = row["origin_path_sha256"]
        if url_hash in by_url:
            uf.union(index, by_url[url_hash])
        else:
            by_url[url_hash] = index
        if origin_path in by_origin_path:
            uf.union(index, by_origin_path[origin_path])
        else:
            by_origin_path[origin_path] = index

    clusters: dict[int, list[int]] = defaultdict(list)
    for index in range(len(rows)):
        clusters[uf.find(index)].append(index)

    source_conflict_artifacts = {
        artifact for artifact, groups in artifact_groups_by_hash.items() if len(groups) > 1
    }
    verified_label_conflicts = 0
    accepted: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    quarantined_record_count = 0

    for indices in clusters.values():
        cluster_rows = [rows[i] for i in indices]
        group_id = _artifact_group(cluster_rows)
        reasons: list[str] = []
        verified_labels = {
            row["ground_truth"] for row in cluster_rows
            if row["label_status"] == "VERIFIED_SOURCE_LABEL" and row["ground_truth"] in (0, 1)
        }
        if verified_labels == {0, 1}:
            reasons.append("VERIFIED_LABEL_CONFLICT")
            verified_label_conflicts += 1
        if any(row["source_artifact_sha256"] in source_conflict_artifacts for row in cluster_rows):
            reasons.append("SOURCE_INDEPENDENCE_VIOLATION")

        if reasons:
            quarantined_record_count += len(cluster_rows)
            quarantine.append({
                "artifact_group": group_id,
                "reasons": reasons,
                "record_count": len(cluster_rows),
                "url_sha256": sorted({row["url_sha256"] for row in cluster_rows}),
                "origin_path_sha256": sorted({row["origin_path_sha256"] for row in cluster_rows}),
                "datasets": sorted({row["dataset_id"] for row in cluster_rows}),
                "source_groups": sorted({row["source_group"] for row in cluster_rows}),
                "labels": sorted(verified_labels),
            })
            continue

        exact_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in cluster_rows:
            exact_groups[row["url_sha256"]].append(row)
        for exact_rows in exact_groups.values():
            accepted.append(_merge_exact_rows(exact_rows, group_id))

    origin_path_variants = 0
    origin_to_urls: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        origin_to_urls[row["origin_path_sha256"]].add(row["url_sha256"])
    origin_path_variants = sum(1 for values in origin_to_urls.values() if len(values) > 1)

    accepted.sort(key=lambda row: (row["artifact_group"], row["url_sha256"]))
    quarantine.sort(key=lambda item: item["artifact_group"])

    return {
        "schema_version": RECONCILED_SCHEMA,
        "stats": {
            "input_records": len(rows),
            "canonical_records": len(accepted),
            "duplicate_records_removed": len(rows) - len(accepted) - quarantined_record_count,
            "artifact_groups": len(clusters),
            "origin_path_variant_groups": origin_path_variants,
            "quarantined_groups": len(quarantine),
            "quarantined_records": quarantined_record_count,
            "verified_label_conflicts": verified_label_conflicts,
            "source_independence_conflicts": len(source_conflict_artifacts),
        },
        "records": accepted,
        "quarantine": quarantine,
        "limitations": [
            "artifact_group binds exact/query variants before split construction but is not a registrable-domain group.",
            "Verified labels are never inferred from unlabeled popularity candidates.",
            "Conflicting verified labels and duplicated source artifacts across declared independence groups are quarantined.",
        ],
    }
