from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_remote_zip_index import (
    INDEX_SCHEMA,
    RemoteZipIndexError,
    atomic_write_json,
    index_remote_zenodo_archive,
)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def expected_width(item):
    return int(item["end"]) - int(item["start"]) + 1


def valid_cached(item, cached):
    return (
        cached.get("name") == item.get("name")
        and cached.get("class") == item.get("class")
        and cached.get("md5") == item.get("md5")
        and cached.get("range") == [item.get("start"), item.get("end")]
        and cached.get("record_id_count") == expected_width(item)
        and isinstance(cached.get("record_ids"), list)
        and len(cached["record_ids"]) == expected_width(item)
    )


def validate_complete(entries, archive_items):
    by_name = {entry["name"]: entry for entry in entries}
    expected_names = {item["name"] for item in archive_items}
    if set(by_name) != expected_names:
        raise RemoteZipIndexError("shard index does not cover the complete archive inventory")

    class_ids = {"phishing": set(), "legitimate": set()}
    for item in archive_items:
        entry = by_name[item["name"]]
        width = expected_width(item)
        ids = entry["record_ids"]
        if len(ids) != width or len(set(ids)) != width:
            raise RemoteZipIndexError(
                f"{item['name']} exposes {len(set(ids))} unique record IDs; expected {width}"
            )
        overlap = class_ids[item["class"]] & set(ids)
        if overlap:
            raise RemoteZipIndexError(
                f"record IDs occur in multiple {item['class']} shards: "
                f"{sorted(overlap)[:5]}"
            )
        class_ids[item["class"]].update(ids)

    expected_counts = {"phishing": 5151, "legitimate": 5244}
    for klass, expected in expected_counts.items():
        if len(class_ids[klass]) != expected:
            raise RemoteZipIndexError(
                f"{klass} shard index covers {len(class_ids[klass])} unique records; "
                f"expected {expected}"
            )
    return {klass: len(ids) for klass, ids in class_ids.items()}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Index Zenodo 8041387 ZIP member IDs using HTTP Range requests only."
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("ml/data/manifests/zenodo-8041387-full-files.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    try:
        inventory = load_json(args.inventory)
        archive_items = [
            item for item in inventory.get("files", [])
            if item.get("kind") == "archive"
        ]
        if len(archive_items) != 22:
            raise RemoteZipIndexError(
                f"expected 22 archive shards in inventory, found {len(archive_items)}"
            )

        partial = args.output.with_name(args.output.name + ".partial")
        cached_by_name = {}
        if args.resume:
            source = args.output if args.output.exists() else partial
            if source.exists():
                cached = load_json(source)
                if cached.get("schema_version") == INDEX_SCHEMA:
                    cached_by_name = {
                        entry["name"]: entry
                        for entry in cached.get("shards", [])
                        if isinstance(entry, dict) and "name" in entry
                    }

        entries = []
        total_cd_bytes = 0

        ordered = sorted(
            archive_items,
            key=lambda item: (item["class"], int(item["start"]), item["name"]),
        )
        for position, item in enumerate(ordered, start=1):
            name = item["name"]
            cached = cached_by_name.get(name)
            if cached and valid_cached(item, cached):
                entry = cached
                print(f"[{position}/{len(ordered)}] reusing indexed {name}")
            else:
                print(f"[{position}/{len(ordered)}] indexing {name} via HTTP Range...")
                remote = index_remote_zenodo_archive(
                    record_id=str(inventory.get("dataset_id", "zenodo-8041387")).split("-")[-1],
                    filename=name,
                    timeout=args.timeout,
                )
                width = expected_width(item)
                if remote["record_id_count"] != width:
                    raise RemoteZipIndexError(
                        f"{name} exposes {remote['record_id_count']} unique top-level "
                        f"record IDs; filename range requires {width}"
                    )
                entry = {
                    "name": name,
                    "class": item["class"],
                    "range": [item["start"], item["end"]],
                    "md5": item["md5"],
                    "size_display": item.get("size_display"),
                    "size_bytes_estimated": item.get("size_bytes_estimated"),
                    **remote,
                }
                print(
                    f"    records={entry['record_id_count']} "
                    f"members={entry['member_count']} "
                    f"central_directory={entry['central_directory_bytes']} bytes"
                )

            entries.append(entry)
            total_cd_bytes = sum(
                int(row.get("central_directory_bytes", 0))
                for row in entries
            )
            progress = {
                "schema_version": INDEX_SCHEMA,
                "status": "PARTIAL",
                "dataset_id": inventory.get("dataset_id"),
                "record": inventory.get("record"),
                "shards": entries,
                "indexed_shards": len(entries),
                "expected_shards": len(ordered),
                "central_directory_bytes_fetched": total_cd_bytes,
            }
            atomic_write_json(partial, progress)

        coverage = validate_complete(entries, ordered)
        final = {
            "schema_version": INDEX_SCHEMA,
            "status": "PASS",
            "dataset_id": inventory.get("dataset_id"),
            "record": inventory.get("record"),
            "shards": entries,
            "coverage": coverage,
            "indexed_shards": len(entries),
            "central_directory_bytes_fetched": total_cd_bytes,
            "archive_body_downloaded": False,
            "method": "HTTP_RANGE_ZIP_CENTRAL_DIRECTORY",
        }
        atomic_write_json(args.output, final)
        if partial.exists():
            partial.unlink()

    except (RemoteZipIndexError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({
        "status": "PASS",
        "output": str(args.output),
        "indexed_shards": final["indexed_shards"],
        "coverage": final["coverage"],
        "central_directory_bytes_fetched": final["central_directory_bytes_fetched"],
        "archive_body_downloaded": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
