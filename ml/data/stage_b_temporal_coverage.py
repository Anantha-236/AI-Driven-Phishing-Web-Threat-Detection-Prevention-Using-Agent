"""Metadata-first temporal coverage planning for Zenodo 8041387.

This module deliberately does not download archives. It uses the already-local
metadata CSVs to decide which archive shards are worth downloading before
spending bandwidth/disk.

Key guarantees:
- derives its scale target from the checked-in research readiness policy and
  research split fractions;
- infers the archive shard ordering from already-extracted reference shards;
- refuses unverified CSV-row-to-shard assumptions;
- optimizes *additional* download bytes, treating existing shards as zero
  marginal cost;
- requires both classes before and after one shared temporal cutoff;
- never persists raw source URLs.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .stage_b_research_splitting import DEFAULT_FRACTIONS, PARTITIONS
from .stage_b_zenodo8041387 import (
    Zenodo8041387AdapterError,
    canonical_brand,
    conservative_domain_group,
    discover_html,
    normalize_record_key,
    parse_observed_at,
    read_csv,
    resolve_columns,
)

INVENTORY_SCHEMA = "zenodo-8041387-full-file-inventory-1"
PLAN_SCHEMA = "stage-b-temporal-coverage-plan-1"
READINESS_SCHEMA = "stage-b-readiness-policy-1"
SHARD_ORDERING_STRATEGIES = (
    "csv_ordinal",
    "record_key_lexicographic",
    "record_key_lexicographic_desc",
    "observed_at_then_record_key",
    "observed_at_then_record_key_desc",
)


class TemporalCoveragePlanError(ValueError):
    pass


@dataclass(frozen=True)
class Shard:
    name: str
    klass: str
    start: int
    end: int
    size_display: str
    size_bytes_estimated: int
    md5: str


@dataclass(frozen=True)
class MetaRecord:
    ordinal: int
    record_key: int | str
    klass: str
    observed_at: datetime
    domain_group: str
    brand_group: str
    shard_name: str


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def load_inventory(data: Mapping[str, Any]) -> dict[str, list[Shard]]:
    if data.get("schema_version") != INVENTORY_SCHEMA:
        raise TemporalCoveragePlanError("unsupported Zenodo file inventory schema")
    raw_files = data.get("files")
    if not isinstance(raw_files, list):
        raise TemporalCoveragePlanError("inventory files must be a list")

    result: dict[str, list[Shard]] = {"phishing": [], "legitimate": []}
    for item in raw_files:
        if not isinstance(item, Mapping) or item.get("kind") != "archive":
            continue
        klass = item.get("class")
        if klass not in result:
            raise TemporalCoveragePlanError(f"invalid archive class: {klass!r}")
        name = item.get("name")
        start, end = item.get("start"), item.get("end")
        size = item.get("size_bytes_estimated")
        md5 = item.get("md5")
        if not isinstance(name, str) or not name.endswith(".zip"):
            raise TemporalCoveragePlanError("archive inventory entry requires .zip name")
        if not isinstance(start, int) or not isinstance(end, int) or start <= 0 or end < start:
            raise TemporalCoveragePlanError(f"invalid range for {name}")
        if not isinstance(size, int) or size <= 0:
            raise TemporalCoveragePlanError(f"invalid estimated size for {name}")
        if not isinstance(md5, str) or not re.fullmatch(r"[0-9a-f]{32}", md5):
            raise TemporalCoveragePlanError(f"invalid MD5 for {name}")
        result[klass].append(Shard(
            name=name,
            klass=klass,
            start=start,
            end=end,
            size_display=str(item.get("size_display", "")),
            size_bytes_estimated=size,
            md5=md5,
        ))

    expected_totals = {"phishing": 5151, "legitimate": 5244}
    for klass, shards in result.items():
        shards.sort(key=lambda shard: shard.start)
        expected_start = 1
        for shard in shards:
            if shard.start != expected_start:
                raise TemporalCoveragePlanError(
                    f"{klass} shard ranges are not contiguous at {shard.name}"
                )
            expected_start = shard.end + 1
        if expected_start - 1 != expected_totals[klass]:
            raise TemporalCoveragePlanError(
                f"{klass} shard inventory ends at {expected_start - 1}, expected {expected_totals[klass]}"
            )
    return result


def validate_readiness_targets(
    policy: Mapping[str, Any],
    *,
    reserve_fraction: float,
    fractions: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    if policy.get("schema_version") != READINESS_SCHEMA:
        raise TemporalCoveragePlanError("unsupported readiness policy schema")
    minima = policy.get("min_samples_per_class")
    if not isinstance(minima, Mapping) or set(minima) != set(PARTITIONS):
        raise TemporalCoveragePlanError("readiness policy must define per-class minima for all partitions")
    active = dict(DEFAULT_FRACTIONS if fractions is None else fractions)
    if set(active) != set(PARTITIONS):
        raise TemporalCoveragePlanError("fractions must cover all research partitions")
    if not (0 <= reserve_fraction < 0.80):
        raise TemporalCoveragePlanError("reserve_fraction must be in [0, 0.80)")

    implied = {}
    for partition in PARTITIONS:
        minimum = minima.get(partition)
        fraction = active.get(partition)
        if not isinstance(minimum, int) or minimum <= 0:
            raise TemporalCoveragePlanError(f"invalid readiness minimum for {partition}")
        if not isinstance(fraction, (int, float)) or fraction <= 0:
            raise TemporalCoveragePlanError(f"invalid fraction for {partition}")
        implied[partition] = math.ceil(minimum / float(fraction))

    supervised_target = max(implied.values())
    candidate_target = math.ceil(supervised_target / (1.0 - reserve_fraction))
    test_candidate_target = math.ceil(int(minima["test"]) / (1.0 - reserve_fraction))
    pre_candidate_target = candidate_target - test_candidate_target
    return {
        "readiness_min_samples_per_class": dict(minima),
        "split_fractions": {name: float(active[name]) for name in PARTITIONS},
        "fraction_implied_supervised_target_per_class": supervised_target,
        "planning_reserve_fraction": reserve_fraction,
        "candidate_metadata_target_per_class": candidate_target,
        "candidate_pre_cutoff_target_per_class": pre_candidate_target,
        "candidate_post_cutoff_target_per_class": test_candidate_target,
        "binding_partition": max(implied, key=lambda name: (implied[name], name)),
        "implied_total_per_class_by_partition": implied,
    }


def _shard_for_ordinal(shards: list[Shard], ordinal: int) -> Shard:
    for shard in shards:
        if shard.start <= ordinal <= shard.end:
            return shard
    raise TemporalCoveragePlanError(f"no shard covers metadata row ordinal {ordinal}")


def load_metadata_records(
    csv_path: Path,
    *,
    klass: str,
    shards: list[Shard],
) -> tuple[list[MetaRecord], dict[str, Any]]:
    if klass not in ("phishing", "legitimate"):
        raise TemporalCoveragePlanError("klass must be phishing or legitimate")
    label = 1 if klass == "phishing" else 0
    headers, rows = read_csv(csv_path)
    columns = resolve_columns(headers, label=label)
    records: list[MetaRecord] = []
    rejected: dict[str, int] = {}

    def reject(reason: str) -> None:
        rejected[reason] = rejected.get(reason, 0) + 1

    for ordinal, row in enumerate(rows, start=1):
        try:
            record_key = normalize_record_key(row.get(columns.id, ""))
            observed = datetime.fromisoformat(
                parse_observed_at(row.get(columns.date, "")).replace("Z", "+00:00")
            )
            domain_group = conservative_domain_group(row.get(columns.url, ""))
            if klass == "phishing":
                if not columns.brand:
                    raise Zenodo8041387AdapterError("phishing brand column unresolved")
                brand_group = canonical_brand(row.get(columns.brand, ""), {})
            else:
                brand_group = domain_group
            shard = _shard_for_ordinal(shards, ordinal)
        except Exception as exc:
            reject(type(exc).__name__)
            continue
        records.append(MetaRecord(
            ordinal=ordinal,
            record_key=record_key,
            klass=klass,
            observed_at=observed,
            domain_group=domain_group,
            brand_group=brand_group,
            shard_name=shard.name,
        ))

    if not records:
        raise TemporalCoveragePlanError(f"no usable {klass} metadata records")
    expected_count = sum(shard.end - shard.start + 1 for shard in shards)
    if len(rows) != expected_count:
        raise TemporalCoveragePlanError(
            f"{klass} metadata row count {len(rows)} does not match archive inventory count {expected_count}"
        )
    if len(records) != expected_count:
        raise TemporalCoveragePlanError(
            f"{klass} metadata parsing retained {len(records)} of {expected_count} records; "
            "cannot safely reconstruct shard membership when rows are missing"
        )
    return records, {
        "csv_rows": len(rows),
        "usable_metadata_rows": len(records),
        "rejected_metadata_rows": len(rows) - len(records),
        "rejected_by_reason": dict(sorted(rejected.items())),
        "resolved_columns": {
            "id": columns.id,
            "domain_or_url": columns.url,
            "date": columns.date,
            "brand": columns.brand,
        },
    }



def _ordering_key(record: MetaRecord, strategy: str):
    record_key = str(record.record_key)
    if strategy == "csv_ordinal":
        return record.ordinal
    if strategy in ("record_key_lexicographic", "record_key_lexicographic_desc"):
        return record_key
    if strategy in ("observed_at_then_record_key", "observed_at_then_record_key_desc"):
        return (record.observed_at, record_key)
    raise TemporalCoveragePlanError(f"unsupported shard ordering strategy: {strategy}")


def remap_records_to_shards(
    records: list[MetaRecord],
    shards: list[Shard],
    *,
    strategy: str,
) -> list[MetaRecord]:
    if strategy not in SHARD_ORDERING_STRATEGIES:
        raise TemporalCoveragePlanError(f"unsupported shard ordering strategy: {strategy}")
    expected_count = sum(shard.end - shard.start + 1 for shard in shards)
    if len(records) != expected_count:
        raise TemporalCoveragePlanError(
            f"cannot infer shard mapping from {len(records)} records; inventory requires {expected_count}"
        )
    reverse = strategy.endswith("_desc")
    ordered = sorted(
        records,
        key=lambda record: _ordering_key(record, strategy),
        reverse=reverse,
    )
    assignment: dict[tuple[int, str], str] = {}
    for rank, record in enumerate(ordered, start=1):
        shard = _shard_for_ordinal(shards, rank)
        assignment[(record.ordinal, str(record.record_key))] = shard.name
    return [
        replace(
            record,
            shard_name=assignment[(record.ordinal, str(record.record_key))],
        )
        for record in records
    ]


def _assignment_signature(records: list[MetaRecord]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(record.record_key), record.shard_name) for record in records))


def infer_shard_mapping_from_reference(
    *,
    root: Path,
    shard: Shard,
    records: list[MetaRecord],
    shards: list[Shard],
) -> tuple[list[MetaRecord], dict[str, Any]]:
    """Infer class-wide shard ordering from one known extracted reference shard.

    The archive ranges are ordinal ranges, but the CSV is not guaranteed to be
    stored in the same order used when the ZIP shards were created. We test a
    closed set of deterministic orderings and require an exact ID-set match
    against the extracted reference shard.
    """
    html = discover_html(root)
    observed = {str(key) for key in html}
    expected_width = shard.end - shard.start + 1
    if len(observed) != expected_width:
        raise TemporalCoveragePlanError(
            f"reference shard {shard.name} contains {len(observed)} record IDs; "
            f"inventory range requires {expected_width}"
        )

    diagnostics: dict[str, dict[str, int | bool]] = {}
    exact: list[tuple[str, list[MetaRecord]]] = []

    for strategy in SHARD_ORDERING_STRATEGIES:
        remapped = remap_records_to_shards(records, shards, strategy=strategy)
        predicted = {
            str(record.record_key)
            for record in remapped
            if record.shard_name == shard.name
        }
        overlap = len(predicted & observed)
        missing = len(predicted - observed)
        extras = len(observed - predicted)
        is_exact = predicted == observed
        diagnostics[strategy] = {
            "predicted": len(predicted),
            "observed": len(observed),
            "overlap": overlap,
            "missing": missing,
            "extras": extras,
            "exact_match": is_exact,
        }
        if is_exact:
            exact.append((strategy, remapped))

    if not exact:
        raise TemporalCoveragePlanError(
            f"no deterministic shard ordering reproduces {shard.name}; "
            f"diagnostics={json.dumps(diagnostics, sort_keys=True)}"
        )

    signatures: dict[tuple[tuple[str, str], ...], list[str]] = {}
    remapped_by_signature: dict[tuple[tuple[str, str], ...], list[MetaRecord]] = {}
    for strategy, remapped in exact:
        signature = _assignment_signature(remapped)
        signatures.setdefault(signature, []).append(strategy)
        remapped_by_signature[signature] = remapped

    if len(signatures) > 1:
        alternatives = [sorted(values) for values in signatures.values()]
        raise TemporalCoveragePlanError(
            f"reference shard {shard.name} matches multiple incompatible class-wide "
            f"orderings: {alternatives}"
        )

    signature = next(iter(signatures))
    strategies = sorted(signatures[signature])
    priority = {name: index for index, name in enumerate(SHARD_ORDERING_STRATEGIES)}
    chosen = min(strategies, key=lambda name: priority[name])
    remapped = remapped_by_signature[signature]
    return remapped, {
        "shard": shard.name,
        "archive_record_ids": len(observed),
        "exact_match": True,
        "chosen_strategy": chosen,
        "equivalent_exact_strategies": strategies,
        "diagnostics": diagnostics,
    }


def validate_existing_shard_identity(
    *,
    root: Path,
    shard: Shard,
    records: list[MetaRecord],
) -> dict[str, Any]:
    html = discover_html(root)
    observed = {str(key) for key in html}
    expected = {
        str(record.record_key)
        for record in records
        if record.shard_name == shard.name
    }
    missing = sorted(expected - observed)
    extras = sorted(observed - expected)
    if missing or extras:
        raise TemporalCoveragePlanError(
            f"current shard mapping validation failed for {shard.name}: "
            f"missing={len(missing)}, extras={len(extras)}"
        )
    return {
        "shard": shard.name,
        "expected_record_ids": len(expected),
        "archive_record_ids": len(observed),
        "exact_match": True,
    }



SHARD_INDEX_SCHEMA = "stage-b-zenodo-shard-index-1"


def apply_verified_shard_index(
    records: list[MetaRecord],
    shards: list[Shard],
    *,
    klass: str,
    shard_index: Mapping[str, Any],
) -> tuple[list[MetaRecord], dict[str, Any]]:
    if shard_index.get("schema_version") != SHARD_INDEX_SCHEMA:
        raise TemporalCoveragePlanError("unsupported shard-index schema")
    if shard_index.get("status") != "PASS":
        raise TemporalCoveragePlanError("shard index is not PASS")
    entries = shard_index.get("shards")
    if not isinstance(entries, list):
        raise TemporalCoveragePlanError("shard index requires shards list")

    expected_by_name = {shard.name: shard for shard in shards}
    indexed = [
        entry for entry in entries
        if isinstance(entry, Mapping) and entry.get("class") == klass
    ]
    if {entry.get("name") for entry in indexed} != set(expected_by_name):
        raise TemporalCoveragePlanError(
            f"{klass} shard index does not exactly cover inventory shard names"
        )

    record_to_shard: dict[str, str] = {}
    duplicate_ids: set[str] = set()
    per_shard = {}
    for entry in indexed:
        name = str(entry["name"])
        shard = expected_by_name[name]
        if entry.get("md5") != shard.md5:
            raise TemporalCoveragePlanError(f"shard-index MD5 mismatch for {name}")
        if entry.get("range") != [shard.start, shard.end]:
            raise TemporalCoveragePlanError(f"shard-index range mismatch for {name}")
        ids = entry.get("record_ids")
        if not isinstance(ids, list):
            raise TemporalCoveragePlanError(f"shard-index record_ids missing for {name}")
        expected_width = shard.end - shard.start + 1
        normalized = [str(value).lower() for value in ids]
        if len(normalized) != expected_width or len(set(normalized)) != expected_width:
            raise TemporalCoveragePlanError(
                f"shard-index unique ID count mismatch for {name}"
            )
        for record_id in normalized:
            if record_id in record_to_shard:
                duplicate_ids.add(record_id)
            record_to_shard[record_id] = name
        per_shard[name] = len(normalized)

    if duplicate_ids:
        raise TemporalCoveragePlanError(
            f"{klass} record IDs appear in multiple shards: {sorted(duplicate_ids)[:5]}"
        )

    metadata_ids = {str(record.record_key).lower() for record in records}
    indexed_ids = set(record_to_shard)
    missing = sorted(metadata_ids - indexed_ids)
    extras = sorted(indexed_ids - metadata_ids)
    if missing or extras:
        raise TemporalCoveragePlanError(
            f"{klass} exact shard-index/CSV ID reconciliation failed: "
            f"missing_from_index={len(missing)}, extra_in_index={len(extras)}"
        )

    remapped = [
        replace(
            record,
            shard_name=record_to_shard[str(record.record_key).lower()],
        )
        for record in records
    ]
    return remapped, {
        "class": klass,
        "metadata_record_ids": len(metadata_ids),
        "indexed_record_ids": len(indexed_ids),
        "exact_match": True,
        "per_shard_record_counts": dict(sorted(per_shard.items())),
    }

def _stats_by_shard(records: list[MetaRecord], shards: list[Shard], cutoff: datetime) -> dict[str, dict[str, Any]]:
    grouped = {shard.name: [] for shard in shards}
    for record in records:
        grouped[record.shard_name].append(record)
    result: dict[str, dict[str, Any]] = {}
    by_name = {shard.name: shard for shard in shards}
    for name, rows in grouped.items():
        shard = by_name[name]
        before = [row for row in rows if row.observed_at < cutoff]
        after = [row for row in rows if row.observed_at >= cutoff]
        result[name] = {
            "name": name,
            "class": shard.klass,
            "range": [shard.start, shard.end],
            "size_display": shard.size_display,
            "size_bytes_estimated": shard.size_bytes_estimated,
            "md5": shard.md5,
            "metadata_rows": len(rows),
            "before_cutoff": len(before),
            "after_cutoff": len(after),
            "unique_domains": len({row.domain_group for row in rows}),
            "unique_brands": len({row.brand_group for row in rows}),
            "earliest": min((row.observed_at for row in rows), default=None).isoformat() if rows else None,
            "latest": max((row.observed_at for row in rows), default=None).isoformat() if rows else None,
        }
    return result


def _subset_best(
    shards: list[Shard],
    stats: Mapping[str, Mapping[str, Any]],
    *,
    existing: set[str],
    target_total: int,
    target_before: int,
    target_after: int,
) -> tuple[list[str], dict[str, int]] | None:
    best = None
    n = len(shards)
    for mask in range(1, 1 << n):
        names = [shards[i].name for i in range(n) if mask & (1 << i)]
        total = sum(int(stats[name]["metadata_rows"]) for name in names)
        if total < target_total:
            continue
        before = sum(int(stats[name]["before_cutoff"]) for name in names)
        if before < target_before:
            continue
        after = sum(int(stats[name]["after_cutoff"]) for name in names)
        if after < target_after:
            continue
        marginal = sum(
            shards[i].size_bytes_estimated
            for i in range(n)
            if mask & (1 << i) and shards[i].name not in existing
        )
        full = sum(
            shards[i].size_bytes_estimated
            for i in range(n)
            if mask & (1 << i)
        )
        key = (
            marginal,
            len([name for name in names if name not in existing]),
            full,
            abs(total - target_total),
            -after,
            tuple(names),
        )
        if best is None or key < best[0]:
            best = (key, names, {
                "metadata_rows": total,
                "before_cutoff": before,
                "after_cutoff": after,
                "marginal_download_bytes_estimated": marginal,
                "selected_archive_bytes_estimated": full,
            })
    if best is None:
        return None
    return best[1], best[2]


def _candidate_cutoffs(records: list[MetaRecord], max_candidates: int) -> list[datetime]:
    times = sorted({record.observed_at for record in records})
    if len(times) <= max_candidates:
        return times
    # Even deterministic spread, while always retaining the late tail where the
    # strict-forward test cutoff is likely to land.
    indices = {
        round(i * (len(times) - 1) / (max_candidates - 1))
        for i in range(max_candidates)
    }
    return [times[index] for index in sorted(indices)]


def build_temporal_coverage_plan(
    *,
    phishing_records: list[MetaRecord],
    legitimate_records: list[MetaRecord],
    inventory: dict[str, list[Shard]],
    targets: Mapping[str, Any],
    existing_shards: Iterable[str],
    max_cutoff_candidates: int = 256,
) -> dict[str, Any]:
    if max_cutoff_candidates < 16:
        raise TemporalCoveragePlanError("max_cutoff_candidates must be at least 16")

    existing = set(existing_shards)
    known_names = {shard.name for values in inventory.values() for shard in values}
    unknown = sorted(existing - known_names)
    if unknown:
        raise TemporalCoveragePlanError(f"unknown existing shard(s): {unknown}")

    all_records = phishing_records + legitimate_records
    common_start = max(
        min(record.observed_at for record in phishing_records),
        min(record.observed_at for record in legitimate_records),
    )
    common_end = min(
        max(record.observed_at for record in phishing_records),
        max(record.observed_at for record in legitimate_records),
    )
    if common_start >= common_end:
        raise TemporalCoveragePlanError("classes have no overlapping metadata time window")

    overlap_records = [
        record for record in all_records
        if common_start <= record.observed_at <= common_end
    ]
    cutoffs = [
        cutoff for cutoff in _candidate_cutoffs(overlap_records, max_cutoff_candidates)
        if common_start < cutoff < common_end
    ]

    target_total = int(targets["candidate_metadata_target_per_class"])
    target_before = int(targets["candidate_pre_cutoff_target_per_class"])
    target_after = int(targets["candidate_post_cutoff_target_per_class"])

    candidates = []
    for cutoff in cutoffs:
        p_stats = _stats_by_shard(phishing_records, inventory["phishing"], cutoff)
        l_stats = _stats_by_shard(legitimate_records, inventory["legitimate"], cutoff)
        p_choice = _subset_best(
            inventory["phishing"], p_stats, existing=existing,
            target_total=target_total, target_before=target_before, target_after=target_after,
        )
        if p_choice is None:
            continue
        l_choice = _subset_best(
            inventory["legitimate"], l_stats, existing=existing,
            target_total=target_total, target_before=target_before, target_after=target_after,
        )
        if l_choice is None:
            continue

        p_names, p_totals = p_choice
        l_names, l_totals = l_choice
        marginal = (
            p_totals["marginal_download_bytes_estimated"]
            + l_totals["marginal_download_bytes_estimated"]
        )
        after_floor = min(p_totals["after_cutoff"], l_totals["after_cutoff"])
        class_total_floor = min(p_totals["metadata_rows"], l_totals["metadata_rows"])
        score = (
            marginal,
            -after_floor,
            -class_total_floor,
            cutoff.isoformat(),
            tuple(p_names),
            tuple(l_names),
        )
        candidates.append((score, cutoff, p_names, l_names, p_totals, l_totals, p_stats, l_stats))

    if not candidates:
        raise TemporalCoveragePlanError(
            "no shard subset can meet the metadata-level readiness/reserve targets "
            "for both classes under a shared strict-forward cutoff"
        )

    candidates.sort(key=lambda item: item[0])
    _, cutoff, p_names, l_names, p_totals, l_totals, p_stats, l_stats = candidates[0]
    selected_names = set(p_names + l_names)

    recommendations = []
    for klass, names, stats in (
        ("phishing", p_names, p_stats),
        ("legitimate", l_names, l_stats),
    ):
        for name in names:
            row = dict(stats[name])
            row["existing_local_shard"] = name in existing
            row["download_required"] = name not in existing
            recommendations.append(row)

    downloads = [row for row in recommendations if row["download_required"]]
    downloads.sort(key=lambda row: (row["class"], row["range"][0], row["name"]))
    recommendations.sort(key=lambda row: (row["class"], row["range"][0], row["name"]))

    return {
        "schema_version": PLAN_SCHEMA,
        "status": "PASS",
        "research_only": True,
        "deployment_authorized": False,
        "metadata_only_planning": True,
        "targets": dict(targets),
        "common_metadata_time_window": {
            "start": common_start.isoformat(),
            "end": common_end.isoformat(),
        },
        "recommended_strict_forward_cutoff": cutoff.isoformat(),
        "selected_metadata_upper_bound": {
            "phishing": p_totals,
            "legitimate": l_totals,
        },
        "selected_shards": recommendations,
        "download_recommendations": downloads,
        "estimated_additional_download_bytes": sum(
            int(row["size_bytes_estimated"]) for row in downloads
        ),
        "estimated_additional_download_gb_decimal": round(
            sum(int(row["size_bytes_estimated"]) for row in downloads) / 1_000_000_000,
            3,
        ),
        "existing_shards_used": sorted(selected_names & existing),
        "audit": {
            "candidate_cutoffs_evaluated": len(cutoffs),
            "selected_shard_count": len(recommendations),
            "download_shard_count": len(downloads),
            "planner_deterministic": True,
        },
        "limitations": [
            "This is a metadata-only acquisition plan; archive HTML usability is unknown until download/extraction/reconciliation.",
            "The planning reserve is an explicit assumption for quarantine/extraction loss, not a measured guarantee.",
            "Shard membership is taken from a verified ZIP central-directory index; its class-wide record-ID union must exactly equal the CSV _id set before planning.",
            "A metadata-level PASS does not satisfy the Stage B readiness gate.",
            "This remains single-source research evidence and cannot authorize deployment.",
        ],
    }
