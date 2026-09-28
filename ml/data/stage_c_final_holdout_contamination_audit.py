"""Stage C Task 30 — final-holdout contamination and duplicate audit.

This task audits the frozen CompPhish v3 final-holdout identity index against:
1. the complete Stage-C development identity index; and
2. the exact already-consumed Stage-B contextual-v2 final-test partition.

It also prevents duplicate weighting inside the final holdout by grouping rows
connected through exact HTML identity, or through normalized-URL identity only
when the labels agree, and choosing a single deterministic representative from
each clean same-label component.

Hard quarantine conditions:
- exact HTML overlap with Stage-C development
- normalized URL overlap with Stage-C development
- exact HTML overlap with the consumed Stage-B final test
- identical HTML carrying conflicting labels inside the final holdout

Same normalized URL with different HTML and different labels is not collapsed
into one identity component. This preserves possible temporal/state changes at
the same URL while still preventing duplicate weighting within each label.

Audit-only signals:
- hostname overlap with Stage-C development
- Stage-B domain-group counts (domain semantics are not directly comparable to
  the privacy-reduced hostname hashes in Task 29)

No model is loaded or scored. No feature extraction or metrics occur.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

AUDIT_SCHEMA = "stage-c-final-holdout-contamination-audit-1"
CLEAN_SET_SCHEMA = "stage-c-final-holdout-clean-evaluation-set-1"

EXPECTED_TASK29_RECORD_SET_SHA256 = (
    "30712d728fdaee1681bf227018ea953a5f52c490ea0e560cf49d257c04609167"
)
EXPECTED_TASK29_INDEX_IDENTITY_SHA256 = (
    "4c3171b1ee2e342a5542b73c58acc8cffc98ac902870fd45b2f4b41b794966c1"
)
EXPECTED_STAGE_B_TEST_PARTITION_SHA256 = (
    "a7d83608610370f7772ee2820bdf0229cd14e97c6f18143130125c7db7a4fd2d"
)

EXPECTED_FINAL_SAMPLE_COUNT = 15358
EXPECTED_FINAL_CLASS_COUNTS = {"0": 8154, "1": 7204}
EXPECTED_DEVELOPMENT_RECORD_COUNT = 80000

MIN_LEGITIMATE_FOR_WILSON = 381
RECOMMENDED_LEGITIMATE = 1200
RECOMMENDED_PHISHING = 1000


class StageCFinalHoldoutContaminationError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCFinalHoldoutContaminationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCFinalHoldoutContaminationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCFinalHoldoutContaminationError(
            f"JSON root must be object: {path}"
        )
    return value


def frozen_write_json(path: Path, value: Any) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCFinalHoldoutContaminationError(
                f"refusing to replace non-identical frozen Task-30 output: {path}"
            )
        return "EXISTING_MATCH"
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with tmp.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return "CREATED"


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def normalize_url(url: str) -> tuple[str, str]:
    raw = url.strip()
    if not raw:
        raise StageCFinalHoldoutContaminationError("empty development URL")
    probe = raw if "://" in raw else f"http://{raw}"
    try:
        parts = urlsplit(probe)
        host = (parts.hostname or "").casefold().rstrip(".")
        port = parts.port
    except ValueError as exc:
        raise StageCFinalHoldoutContaminationError(
            f"invalid development URL: {raw!r}"
        ) from exc
    if not host:
        raise StageCFinalHoldoutContaminationError(
            f"development URL has no hostname: {raw!r}"
        )
    scheme = parts.scheme.casefold() or "http"
    netloc = host
    if port is not None:
        default = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        if not default:
            netloc = f"{host}:{port}"
    normalized = urlunsplit(
        (scheme, netloc, parts.path or "/", parts.query, "")
    )
    return normalized, host


def validate_final_index(index: Mapping[str, Any]) -> list[dict[str, Any]]:
    expected = {
        "schema_version": "stage-c-final-holdout-identity-index-1",
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "sample_count": EXPECTED_FINAL_SAMPLE_COUNT,
        "class_counts": EXPECTED_FINAL_CLASS_COUNTS,
        "raw_urls_persisted": False,
        "mapping_labels_accessed_for_identity_index": True,
        "mapping_labels_used_for_model_selection": False,
        "html_capture_bytes_accessed_for_identity_hashing": True,
        "html_features_extracted": False,
        "model_scoring_performed": False,
        "metrics_computed": False,
        "error_analysis_performed": False,
        "record_set_sha256": EXPECTED_TASK29_RECORD_SET_SHA256,
        "index_identity_sha256": EXPECTED_TASK29_INDEX_IDENTITY_SHA256,
        "next_gate": (
            "AUDIT_STAGE_C_FINAL_HOLDOUT_CONTAMINATION_AGAINST_"
            "DEVELOPMENT_AND_CONSUMED_STAGE_B_TEST"
        ),
    }
    for key, expected_value in expected.items():
        if index.get(key) != expected_value:
            raise StageCFinalHoldoutContaminationError(
                f"Task-29 index guard mismatch: {key}"
            )

    rows = index.get("records")
    if not isinstance(rows, list) or len(rows) != EXPECTED_FINAL_SAMPLE_COUNT:
        raise StageCFinalHoldoutContaminationError(
            "Task-29 final-holdout records missing"
        )
    if canonical_hash(rows) != EXPECTED_TASK29_RECORD_SET_SHA256:
        raise StageCFinalHoldoutContaminationError(
            "Task-29 record-set hash mismatch"
        )

    seen = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCFinalHoldoutContaminationError(
                "invalid Task-29 record"
            )
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen:
            raise StageCFinalHoldoutContaminationError(
                "Task-29 sample identity missing or duplicated"
            )
        seen.add(sample_id)
        if row.get("label") not in (0, 1):
            raise StageCFinalHoldoutContaminationError(
                "Task-29 record label invalid"
            )
        for field in (
            "html_sha256",
            "normalized_url_sha256",
            "hostname_sha256",
        ):
            if not _is_sha256(row.get(field)):
                raise StageCFinalHoldoutContaminationError(
                    f"Task-29 invalid {field}"
                )
        if not isinstance(row.get("html_member_name"), str):
            raise StageCFinalHoldoutContaminationError(
                "Task-29 HTML locator missing"
            )
    return [dict(row) for row in rows]


def validate_development_index(index: Mapping[str, Any]) -> list[dict[str, Any]]:
    expected = {
        "schema_version": "stage-c-development-record-index-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "feature_extraction_authorized": False,
        "final_holdout_touched": False,
        "record_count": EXPECTED_DEVELOPMENT_RECORD_COUNT,
        "class_counts": {"legitimate": 50000, "phishing": 30000},
    }
    for key, expected_value in expected.items():
        if index.get(key) != expected_value:
            raise StageCFinalHoldoutContaminationError(
                f"Stage-C development index guard mismatch: {key}"
            )

    rows = index.get("records")
    if not isinstance(rows, list) or len(rows) != EXPECTED_DEVELOPMENT_RECORD_COUNT:
        raise StageCFinalHoldoutContaminationError(
            "Stage-C development records missing"
        )
    expected_record_hash = index.get("record_set_sha256")
    if not _is_sha256(expected_record_hash):
        raise StageCFinalHoldoutContaminationError(
            "Stage-C development record_set_sha256 invalid"
        )
    if canonical_hash(rows) != expected_record_hash:
        raise StageCFinalHoldoutContaminationError(
            "Stage-C development record-set hash mismatch"
        )

    for row in rows:
        if not isinstance(row, Mapping):
            raise StageCFinalHoldoutContaminationError(
                "invalid Stage-C development record"
            )
        if not _is_sha256(row.get("html_sha256")):
            raise StageCFinalHoldoutContaminationError(
                "Stage-C development html_sha256 invalid"
            )
        if not isinstance(row.get("url"), str) or not row["url"].strip():
            raise StageCFinalHoldoutContaminationError(
                "Stage-C development URL missing"
            )
    return [dict(row) for row in rows]


def _stage_b_test_fingerprint(rows: list[Mapping[str, Any]]) -> str:
    material = []
    for row in rows:
        sample_id = row.get("sample_id")
        label = row.get("ground_truth")
        vector = row.get("feature_vector")
        if (
            not isinstance(sample_id, str)
            or not sample_id
            or label not in (0, 1)
            or not isinstance(vector, list)
            or any(
                type(v) not in (int, float) or not math.isfinite(v)
                for v in vector
            )
        ):
            raise StageCFinalHoldoutContaminationError(
                "invalid Stage-B test record identity"
            )
        material.append({
            "sample_id": sample_id,
            "ground_truth": label,
            "feature_vector": vector,
        })
    material.sort(key=lambda row: row["sample_id"])
    return canonical_hash(material)


def validate_consumed_stage_b_test(
    feature_data: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if feature_data.get("schema_version") != "stage-b-feature-dataset-1":
        raise StageCFinalHoldoutContaminationError(
            "unsupported Stage-B feature dataset schema"
        )
    if feature_data.get("representation") != "contextual-flat":
        raise StageCFinalHoldoutContaminationError(
            "unexpected Stage-B feature representation"
        )

    partitions = feature_data.get("partitions")
    if not isinstance(partitions, Mapping):
        raise StageCFinalHoldoutContaminationError(
            "Stage-B feature partitions missing"
        )
    test = partitions.get("test")
    if not isinstance(test, Mapping):
        raise StageCFinalHoldoutContaminationError(
            "Stage-B test partition missing"
        )
    rows = test.get("records")
    if not isinstance(rows, list) or not rows:
        raise StageCFinalHoldoutContaminationError(
            "Stage-B test records missing"
        )

    fingerprint = _stage_b_test_fingerprint(rows)
    if fingerprint != EXPECTED_STAGE_B_TEST_PARTITION_SHA256:
        raise StageCFinalHoldoutContaminationError(
            "Stage-B test partition does not match the consumed contextual-v2 "
            f"final test: expected={EXPECTED_STAGE_B_TEST_PARTITION_SHA256}, "
            f"actual={fingerprint}"
        )

    for row in rows:
        artifact = row.get("artifact_group")
        domain = row.get("domain_group")
        if not _is_sha256(artifact):
            raise StageCFinalHoldoutContaminationError(
                "Stage-B test artifact_group is not a SHA-256 identity"
            )
        if not isinstance(domain, str) or not domain.strip():
            raise StageCFinalHoldoutContaminationError(
                "Stage-B test domain_group missing"
            )
    return [dict(row) for row in rows]


class _UF:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_identity_components(
    rows: list[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    uf = _UF(len(rows))
    seen_html: dict[str, int] = {}
    seen_url_label: dict[tuple[str, int], int] = {}
    for i, row in enumerate(rows):
        html = row["html_sha256"]
        url = row["normalized_url_sha256"]
        label = row["label"]

        # Exact HTML is the strongest content identity and is joined regardless
        # of label so contradictory labels can be detected and quarantined.
        if html in seen_html:
            uf.union(i, seen_html[html])
        else:
            seen_html[html] = i

        # A URL can legitimately change state/content over time. Only collapse
        # same-URL rows when their labels already agree.
        url_label_key = (url, label)
        if url_label_key in seen_url_label:
            uf.union(i, seen_url_label[url_label_key])
        else:
            seen_url_label[url_label_key] = i

    buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for i, row in enumerate(rows):
        buckets[uf.find(i)].append(row)

    components = [
        sorted(bucket, key=lambda row: row["sample_id"])
        for bucket in buckets.values()
    ]
    components.sort(key=lambda bucket: bucket[0]["sample_id"])
    return components


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/data/stage_c_final_holdout_contamination_audit.py",
        "ml/data/audit_stage_c_final_holdout_contamination.py",
        "ml/data/stage_c_final_holdout_identity_index.py",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCFinalHoldoutContaminationError(
                "invalid Git HEAD identity"
            )
        for relative in paths:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"],
                cwd=repo_root,
                capture_output=True,
                check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *paths],
            cwd=repo_root,
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCFinalHoldoutContaminationError(
            "Task-30 and bound files must be committed before contamination audit"
        ) from exc
    if dirty != 0:
        raise StageCFinalHoldoutContaminationError(
            "Task-30/bound files differ from committed HEAD"
        )

    def file_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    return {
        "git_head": head,
        "task30_module_sha256": file_sha256(repo_root / paths[0]),
        "task30_cli_sha256": file_sha256(repo_root / paths[1]),
        "task29_module_sha256": file_sha256(repo_root / paths[2]),
    }


def audit_final_holdout_contamination(
    *,
    repo_root: Path,
    final_index_path: Path,
    development_index_path: Path,
    stage_b_feature_dataset_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    final_index = load_json(final_index_path)
    development_index = load_json(development_index_path)
    stage_b_features = load_json(stage_b_feature_dataset_path)

    final_rows = validate_final_index(final_index)
    development_rows = validate_development_index(development_index)
    stage_b_test_rows = validate_consumed_stage_b_test(stage_b_features)
    git = _git_provenance(repo_root)

    dev_html = {row["html_sha256"] for row in development_rows}
    dev_url_hashes: set[str] = set()
    dev_host_hashes: set[str] = set()
    for row in development_rows:
        normalized, host = normalize_url(row["url"])
        dev_url_hashes.add(
            hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        )
        dev_host_hashes.add(
            hashlib.sha256(host.encode("utf-8")).hexdigest()
        )

    stage_b_artifacts = {
        str(row["artifact_group"]).lower()
        for row in stage_b_test_rows
    }
    stage_b_domains = {
        str(row["domain_group"]).strip().casefold()
        for row in stage_b_test_rows
    }

    components = build_identity_components(final_rows)

    cross_label_components = [
        component
        for component in components
        if len({row["label"] for row in component}) > 1
    ]

    # These components are not relabeled and are not allowed into final
    # evaluation. Identical model input cannot have two ground truths.
    cross_label_conflict_sample_count = sum(
        len(component) for component in cross_label_components
    )

    quarantined: list[dict[str, Any]] = []
    eligible: list[dict[str, Any]] = []

    overlap_counts = Counter()
    hostname_overlap_samples = 0

    for component in components:
        reasons: set[str] = set()
        component_labels = sorted({row["label"] for row in component})
        if len(component_labels) > 1:
            reasons.add("EXACT_HTML_CROSS_LABEL_CONFLICT_WITHIN_HOLDOUT")

        for row in component:
            if row["html_sha256"] in dev_html:
                reasons.add("EXACT_HTML_OVERLAP_STAGE_C_DEVELOPMENT")
            if row["normalized_url_sha256"] in dev_url_hashes:
                reasons.add("NORMALIZED_URL_OVERLAP_STAGE_C_DEVELOPMENT")
            if row["html_sha256"] in stage_b_artifacts:
                reasons.add("EXACT_HTML_OVERLAP_CONSUMED_STAGE_B_TEST")
            if row["hostname_sha256"] in dev_host_hashes:
                hostname_overlap_samples += 1

        representative = component[0]
        if reasons:
            for reason in reasons:
                overlap_counts[reason] += len(component)
            quarantined.append({
                "component_sha256": canonical_hash(
                    sorted(row["sample_id"] for row in component)
                ),
                "representative_sample_id": representative["sample_id"],
                "sample_count": len(component),
                "label": (
                    component_labels[0]
                    if len(component_labels) == 1
                    else None
                ),
                "labels": component_labels,
                "reasons": sorted(reasons),
            })
            continue

        # One deterministic representative per exact-HTML/normalized-URL
        # connected component prevents duplicate weighting in the final test.
        eligible.append({
            "sample_id": representative["sample_id"],
            "label": representative["label"],
            "html_member_name": representative["html_member_name"],
            "html_basename": representative["html_basename"],
            "html_sha256": representative["html_sha256"],
            "normalized_url_sha256": representative["normalized_url_sha256"],
            "hostname_sha256": representative["hostname_sha256"],
            "identity_component_size": len(component),
            "identity_component_sha256": canonical_hash(
                sorted(row["sample_id"] for row in component)
            ),
        })

    eligible.sort(key=lambda row: row["sample_id"])
    quarantined.sort(key=lambda row: row["representative_sample_id"])

    labels = Counter(row["label"] for row in eligible)
    if labels[0] < MIN_LEGITIMATE_FOR_WILSON:
        raise StageCFinalHoldoutContaminationError(
            "clean final-holdout subset lacks enough legitimate samples for "
            f"1% FPR Wilson resolution: {labels[0]} < {MIN_LEGITIMATE_FOR_WILSON}"
        )
    if labels[1] < 1:
        raise StageCFinalHoldoutContaminationError(
            "clean final-holdout subset contains no phishing samples"
        )

    exact_html_duplicate_components = sum(
        1 for component in components
        if len({row["html_sha256"] for row in component}) < len(component)
    )
    normalized_url_duplicate_components = sum(
        1 for component in components
        if len({row["normalized_url_sha256"] for row in component}) < len(component)
    )
    duplicate_rows_removed = sum(
        max(0, len(component) - 1)
        for component in components
        if len({row["label"] for row in component}) == 1
        and not any(
            row["html_sha256"] in dev_html
            or row["normalized_url_sha256"] in dev_url_hashes
            or row["html_sha256"] in stage_b_artifacts
            for row in component
        )
    )

    clean_core = {
        "candidate_id": final_index["candidate_id"],
        "source_id": final_index["source_id"],
        "doi": final_index["doi"],
        "sample_count": len(eligible),
        "class_counts": {
            "legitimate": labels[0],
            "phishing": labels[1],
        },
        "records": eligible,
    }

    clean_set = {
        "schema_version": CLEAN_SET_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT_CLEAN_EVALUATION_SUBSET",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        **clean_core,
        "selection_basis": (
            "IDENTITY_ONLY_NO_MODEL_SCORE_NO_MODEL_PERFORMANCE"
        ),
        "deduplication_rule": (
            "ONE_LEXICOGRAPHICALLY_SMALLEST_SAMPLE_ID_PER_CONNECTED_COMPONENT_"
            "OF_EXACT_HTML_OR_SAME_LABEL_NORMALIZED_URL"
        ),
        "cross_label_exact_html_policy": (
            "QUARANTINE_ENTIRE_CONFLICTING_EXACT_HTML_COMPONENT_NO_RELABELING"
        ),
        "contamination_quarantine_applied": True,
        "model_scoring_performed": False,
        "features_extracted": False,
        "metrics_computed": False,
        "sample_set_sha256": canonical_hash(
            [row["sample_id"] for row in eligible]
        ),
        "record_set_sha256": canonical_hash(eligible),
        "clean_set_identity_sha256": canonical_hash(clean_core),
        "identity_bindings": {
            "task29_record_set_sha256": EXPECTED_TASK29_RECORD_SET_SHA256,
            "task29_index_identity_sha256": EXPECTED_TASK29_INDEX_IDENTITY_SHA256,
            "stage_c_development_record_set_sha256": development_index[
                "record_set_sha256"
            ],
            "consumed_stage_b_test_partition_sha256": (
                EXPECTED_STAGE_B_TEST_PARTITION_SHA256
            ),
            **git,
        },
        "next_gate": (
            "AUTHORIZE_STAGE_C_FINAL_HOLDOUT_FEATURE_EXTRACTION_ON_"
            "CLEAN_IDENTITY_SUBSET"
        ),
    }

    audit_core = {
        "original_final_holdout_samples": len(final_rows),
        "original_final_holdout_class_counts": EXPECTED_FINAL_CLASS_COUNTS,
        "identity_component_count": len(components),
        "eligible_clean_samples": len(eligible),
        "eligible_clean_class_counts": {
            "legitimate": labels[0],
            "phishing": labels[1],
        },
        "quarantined_component_count": len(quarantined),
        "quarantined_sample_count": sum(
            row["sample_count"] for row in quarantined
        ),
        "hard_overlap_sample_counts": dict(sorted(overlap_counts.items())),
        "duplicate_rows_removed_from_clean_weighting": duplicate_rows_removed,
        "exact_html_duplicate_components_within_holdout": (
            exact_html_duplicate_components
        ),
        "normalized_url_duplicate_components_within_holdout": (
            normalized_url_duplicate_components
        ),
        "stage_c_development_hostname_overlap_samples_audit_only": (
            hostname_overlap_samples
        ),
        "stage_b_consumed_test_sample_count": len(stage_b_test_rows),
        "stage_b_consumed_test_unique_artifacts": len(stage_b_artifacts),
        "stage_b_consumed_test_unique_domain_groups_audit_only": len(
            stage_b_domains
        ),
        "cross_label_identity_conflict_components": len(
            cross_label_components
        ),
        "cross_label_identity_conflict_samples": (
            cross_label_conflict_sample_count
        ),
        "cross_label_identity_conflict_policy": (
            "QUARANTINE_ENTIRE_CONFLICTING_EXACT_HTML_COMPONENT_NO_RELABELING"
        ),
        "wilson_resolution_minimum_legitimate_satisfied": (
            labels[0] >= MIN_LEGITIMATE_FOR_WILSON
        ),
        "recommended_final_scale_satisfied": (
            labels[0] >= RECOMMENDED_LEGITIMATE
            and labels[1] >= RECOMMENDED_PHISHING
        ),
    }

    audit = {
        "schema_version": AUDIT_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "role": "FINAL_HOLDOUT",
        "audit_mode": (
            "IDENTITY_CONTAMINATION_AND_DUPLICATE_WEIGHT_AUDIT_ONLY"
        ),
        "research_only": True,
        "deployment_authorized": False,
        **audit_core,
        "quarantine_records": quarantined,
        "raw_urls_emitted": False,
        "model_loaded": False,
        "model_scoring_performed": False,
        "features_extracted": False,
        "metrics_computed": False,
        "threshold_changed": False,
        "model_refit": False,
        "clean_sample_set_sha256": clean_set["sample_set_sha256"],
        "clean_record_set_sha256": clean_set["record_set_sha256"],
        "audit_evidence_sha256": canonical_hash(audit_core),
        "next_gate": clean_set["next_gate"],
    }

    return audit, clean_set
