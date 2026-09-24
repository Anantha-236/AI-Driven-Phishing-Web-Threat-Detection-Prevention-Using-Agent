"""Materialize Stage B contextual features with the deployed TypeScript extractor.

URL-feed records cannot be converted into browser-context features. This layer
requires a separately collected, privacy-safe event episode for every supervised
sample and invokes browser-extension/src/core/tsfeg.ts as the single extractor
source of truth.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import subprocess
from typing import Any, Mapping

from .stage_b_splitting import SPLIT_SCHEMA

FEATURE_DATASET_SCHEMA = "stage-b-feature-dataset-1"
EPISODE_SCHEMA = "stage-b-event-episodes-1"
PARTITIONS = ("train", "selection", "calibration", "test")

ALLOWED_EVENT_FIELDS = {
    "event_type", "sensitive_type", "field_id", "form_id", "frame_origin",
    "target_origin", "destination_origin", "initiator_origin", "request_type",
    "interaction_type", "page_purpose", "purpose_source", "timestamp_ms",
    "schema_version", "evidence_status", "analysis_version", "model_version",
    "policy_version", "session_id", "tab_id", "document_id", "frame_id",
    "parent_frame_id", "event_seq", "received_ms", "trust", "confidence",
}


class FeatureMaterializationError(ValueError):
    """Raised when Stage B event/features violate the locked feature contract."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_events(events: Any) -> list[dict[str, Any]]:
    if not isinstance(events, list) or not events:
        raise FeatureMaterializationError("event episode must contain sanitized events")
    cleaned: list[dict[str, Any]] = []
    seen_seq: set[int] = set()
    for raw in events:
        if not isinstance(raw, Mapping):
            raise FeatureMaterializationError("event episode entries must be objects")
        unexpected = set(raw) - ALLOWED_EVENT_FIELDS
        if unexpected:
            raise FeatureMaterializationError(
                f"unexpected event fields: {', '.join(sorted(unexpected))}"
            )
        seq = raw.get("event_seq")
        if type(seq) is not int or seq <= 0 or seq in seen_seq:
            raise FeatureMaterializationError("event_seq must be unique positive integers")
        seen_seq.add(seq)
        if raw.get("schema_version") not in {"1.1.0", "1.2.0"}:
            raise FeatureMaterializationError("unsupported event schema_version")
        if not isinstance(raw.get("session_id"), str) or not raw["session_id"]:
            raise FeatureMaterializationError("event session_id is required")
        if type(raw.get("tab_id")) is not int or raw["tab_id"] < 0:
            raise FeatureMaterializationError("event tab_id is invalid")
        if type(raw.get("frame_id")) is not int or raw["frame_id"] < 0:
            raise FeatureMaterializationError("event frame_id is invalid")
        if type(raw.get("timestamp_ms")) is not int or raw["timestamp_ms"] < 0:
            raise FeatureMaterializationError("event timestamp_ms is invalid")
        cleaned.append(dict(raw))
    cleaned.sort(key=lambda event: event["event_seq"])
    return cleaned


def _load_episode_index(data: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if data.get("schema_version") != EPISODE_SCHEMA:
        raise FeatureMaterializationError("unsupported event episode schema")
    rows = data.get("episodes")
    if not isinstance(rows, list):
        raise FeatureMaterializationError("episodes must be a list")
    index: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise FeatureMaterializationError("episode entry must be an object")
        sample_id = raw.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise FeatureMaterializationError("episode sample_id is required")
        if sample_id in index:
            raise FeatureMaterializationError(f"duplicate episode for sample {sample_id}")
        events = _validate_events(raw.get("events"))
        expected_hash = raw.get("events_sha256")
        if not _is_sha256(expected_hash) or _sha256_json(events) != expected_hash:
            raise FeatureMaterializationError(f"event hash mismatch for sample {sample_id}")
        provenance = raw.get("collection_provenance")
        if provenance not in {
            "REAL_BROWSER",
            "CONTROLLED_BROWSER",
            "ARCHIVED_SANITIZED_EVENTS",
            "ARCHIVED_BROWSER_REPLAY",
            "SYNTHETIC",
        }:
            raise FeatureMaterializationError("explicit collection_provenance is required")
        index[sample_id] = {
            "sample_id": sample_id,
            "events": events,
            "events_sha256": expected_hash,
            "collection_provenance": provenance,
        }
    return index


def _extract_with_typescript(
    episode_rows: list[dict[str, Any]],
    *,
    repo_root: Path,
    tsfeg_relative: str = "browser-extension/src/core/tsfeg.ts",
) -> tuple[dict[str, Any], str]:
    tsfeg_path = (repo_root / tsfeg_relative).resolve()
    if not tsfeg_path.is_file():
        raise FeatureMaterializationError(f"production extractor not found: {tsfeg_relative}")

    source_hash = hashlib.sha256(tsfeg_path.read_bytes()).hexdigest()
    node_source = r"""
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const extractorPath = process.argv[1];
const core = await import(pathToFileURL(extractorPath).href);
if (!Array.isArray(core.CONTEXT_FEATURES) || typeof core.CONTEXT_FEATURE_VERSION !== 'string' || typeof core.buildContextFeatures !== 'function') {
  throw new Error('tsfeg contextual feature exports unavailable');
}
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const extracted = input.map(row => core.buildContextFeatures(row.events, false));
process.stdout.write(JSON.stringify({
  feature_version: core.CONTEXT_FEATURE_VERSION,
  feature_names: [...core.CONTEXT_FEATURES],
  extracted,
}));
"""
    try:
        completed = subprocess.run(
            ["node", "--experimental-strip-types", "--input-type=module", "-e", node_source, str(tsfeg_path)],
            input=json.dumps(episode_rows),
            text=True,
            encoding="utf-8",
            capture_output=True,
            cwd=repo_root,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        details = getattr(exc, "stderr", "") or str(exc)
        raise FeatureMaterializationError(f"production feature extractor failed: {details.strip()}") from exc
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FeatureMaterializationError("production feature extractor returned invalid JSON") from exc
    return payload, source_hash


def _contract_hash(version: str, names: list[str]) -> str:
    return _sha256_json({"feature_version": version, "feature_names": names})


def materialize_feature_dataset(
    split_data: Mapping[str, Any],
    episode_data: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    if split_data.get("schema_version") != SPLIT_SCHEMA:
        raise FeatureMaterializationError("unsupported Stage B split schema")
    partitions = split_data.get("partitions")
    if not isinstance(partitions, Mapping) or set(partitions) != set(PARTITIONS):
        raise FeatureMaterializationError("all four locked partitions are required")

    episode_index = _load_episode_index(episode_data)
    supervised_ids: list[str] = []
    split_rows: list[tuple[str, dict[str, Any]]] = []
    for partition in PARTITIONS:
        payload = partitions[partition]
        records = payload.get("records") if isinstance(payload, Mapping) else None
        if not isinstance(records, list) or not records:
            raise FeatureMaterializationError(f"partition {partition} has no records")
        for raw in records:
            if not isinstance(raw, Mapping):
                raise FeatureMaterializationError("split record must be an object")
            sample_id = raw.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise FeatureMaterializationError("split record sample_id is required")
            if sample_id in supervised_ids:
                raise FeatureMaterializationError("sample appears in more than one partition")
            supervised_ids.append(sample_id)
            split_rows.append((partition, dict(raw)))

    missing = [sample_id for sample_id in supervised_ids if sample_id not in episode_index]
    if missing:
        raise FeatureMaterializationError(f"missing event episode for sample {missing[0]}")
    extras = sorted(set(episode_index) - set(supervised_ids))
    if extras:
        raise FeatureMaterializationError(f"unexpected event episode for sample {extras[0]}")

    extractor_input = [episode_index[row["sample_id"]] for _, row in split_rows]
    extracted, extractor_hash = _extract_with_typescript(extractor_input, repo_root=repo_root)
    version = extracted.get("feature_version")
    names = extracted.get("feature_names")
    outputs = extracted.get("extracted")
    if not isinstance(version, str) or not isinstance(names, list) or not names or not all(isinstance(name, str) for name in names):
        raise FeatureMaterializationError("invalid production feature contract")
    if not isinstance(outputs, list) or len(outputs) != len(split_rows):
        raise FeatureMaterializationError("production extractor output count mismatch")

    result_partitions = {name: {"records": []} for name in PARTITIONS}
    for (partition, source_row), episode, feature_output in zip(split_rows, extractor_input, outputs, strict=True):
        vector = feature_output.get("vector") if isinstance(feature_output, Mapping) else None
        if not isinstance(vector, list) or len(vector) != len(names):
            raise FeatureMaterializationError("production extractor vector shape mismatch")
        if any(type(value) not in (int, float) or not math.isfinite(value) for value in vector):
            raise FeatureMaterializationError("production extractor returned non-finite features")
        result_partitions[partition]["records"].append({
            "sample_id": source_row["sample_id"],
            "partition": partition,
            "ground_truth": source_row.get("ground_truth"),
            "artifact_group": source_row.get("artifact_group"),
            "domain_group": source_row.get("domain_group"),
            "brand_group": source_row.get("brand_group"),
            "source_groups": source_row.get("source_groups"),
            "observed_at": source_row.get("observed_at"),
            "events_sha256": episode["events_sha256"],
            "collection_provenance": episode["collection_provenance"],
            "feature_vector": vector,
        })

    for partition in PARTITIONS:
        result_partitions[partition]["records"].sort(key=lambda row: row["sample_id"])
        result_partitions[partition]["sample_count"] = len(result_partitions[partition]["records"])

    contract_hash = _contract_hash(version, names)
    result = {
        "schema_version": FEATURE_DATASET_SCHEMA,
        "representation": "contextual-flat",
        "feature_version": version,
        "feature_names": names,
        "feature_contract_sha256": contract_hash,
        "extractor_source_sha256": extractor_hash,
        "episode_set_sha256": _sha256_json([
            {"sample_id": row["sample_id"], "events_sha256": row["events_sha256"]}
            for row in sorted(extractor_input, key=lambda row: row["sample_id"])
        ]),
        "split_schema": SPLIT_SCHEMA,
        "partitions": result_partitions,
        "limitations": [
            "URL-feed metadata alone cannot produce contextual browser features; one sanitized event episode is required per supervised sample.",
            "Feature materialization uses the deployed TypeScript extractor as the single source of truth.",
            "Raw event episodes are intentionally omitted from the feature dataset output.",
        ],
    }
    validate_feature_dataset(result)
    return result


def validate_feature_dataset(data: Mapping[str, Any]) -> dict[str, Any]:
    if data.get("schema_version") != FEATURE_DATASET_SCHEMA:
        raise FeatureMaterializationError("unsupported feature dataset schema")
    if data.get("representation") != "contextual-flat":
        raise FeatureMaterializationError("unsupported feature representation")
    version = data.get("feature_version")
    names = data.get("feature_names")
    if not isinstance(version, str) or not isinstance(names, list) or not names or any(not isinstance(v, str) for v in names):
        raise FeatureMaterializationError("invalid feature contract")
    if data.get("feature_contract_sha256") != _contract_hash(version, names):
        raise FeatureMaterializationError("feature contract hash mismatch")
    if not _is_sha256(data.get("extractor_source_sha256")) or not _is_sha256(data.get("episode_set_sha256")):
        raise FeatureMaterializationError("feature dataset provenance hashes are invalid")

    partitions = data.get("partitions")
    if not isinstance(partitions, Mapping) or set(partitions) != set(PARTITIONS):
        raise FeatureMaterializationError("feature dataset requires four partitions")
    seen: set[str] = set()
    for partition in PARTITIONS:
        payload = partitions[partition]
        records = payload.get("records") if isinstance(payload, Mapping) else None
        if not isinstance(records, list) or not records:
            raise FeatureMaterializationError(f"feature partition {partition} is empty")
        for row in records:
            if not isinstance(row, Mapping) or row.get("partition") != partition:
                raise FeatureMaterializationError("feature record partition mismatch")
            sample_id = row.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id or sample_id in seen:
                raise FeatureMaterializationError("feature sample identity missing or duplicated")
            seen.add(sample_id)
            if row.get("ground_truth") not in (0, 1):
                raise FeatureMaterializationError("feature records require verified binary labels")
            vector = row.get("feature_vector")
            if not isinstance(vector, list) or len(vector) != len(names):
                raise FeatureMaterializationError("feature vector length mismatch")
            if any(type(value) not in (int, float) or not math.isfinite(value) for value in vector):
                raise FeatureMaterializationError("feature vector contains non-finite values")
            if not _is_sha256(row.get("events_sha256")):
                raise FeatureMaterializationError("feature row event provenance hash is invalid")
    return dict(data)
