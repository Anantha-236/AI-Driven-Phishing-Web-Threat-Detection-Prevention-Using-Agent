from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Mapping, Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

PLAN_SCHEMA = "stage-b-temporal-coverage-plan-1"
CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+)")
CHUNK_SIZE = 8 * 1024 * 1024
REPORT_EVERY = 256 * 1024 * 1024


class DownloadError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def zenodo_url(record_id: str, filename: str) -> str:
    return (
        f"https://zenodo.org/records/{record_id}/files/"
        f"{quote(filename, safe='')}?download=1"
    )


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_range(url: str, offset: int, *, timeout: int):
    req = Request(
        url,
        headers={
            "Range": f"bytes={offset}-",
            "User-Agent": "capstone-stage-b-research-downloader/1.0",
            "Accept-Encoding": "identity",
        },
    )
    response = urlopen(req, timeout=timeout)
    status = getattr(response, "status", response.getcode())
    if status != 206:
        response.close()
        raise DownloadError(
            f"server did not honor byte-range download for {url}: status={status}; "
            "refusing full-body fallback"
        )

    content_range = response.headers.get("Content-Range", "").strip()
    match = CONTENT_RANGE_RE.fullmatch(content_range)
    if not match:
        response.close()
        raise DownloadError(
            f"invalid Content-Range for {url}: {content_range!r}"
        )

    start, end, total = map(int, match.groups())
    if start != offset:
        response.close()
        raise DownloadError(
            f"resume offset mismatch for {url}: requested {offset}, server returned {start}"
        )
    if end < start or total <= end:
        response.close()
        raise DownloadError(
            f"invalid returned byte range for {url}: {start}-{end}/{total}"
        )
    return response, total


def download_one(
    *,
    record_id: str,
    filename: str,
    expected_md5: str,
    destination: Path,
    timeout: int,
    retries: int,
) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    final_path = destination / filename
    part_path = destination / f"{filename}.part"
    url = zenodo_url(record_id, filename)

    if final_path.exists():
        actual = md5_file(final_path)
        if actual == expected_md5:
            return {
                "name": filename,
                "status": "REUSED_VERIFIED",
                "path": str(final_path),
                "bytes": final_path.stat().st_size,
                "md5": actual,
            }
        final_path.unlink()

    attempts = 0
    total: int | None = None

    while True:
        offset = part_path.stat().st_size if part_path.exists() else 0

        if total is not None and offset == total:
            break
        if total is not None and offset > total:
            raise DownloadError(
                f"partial file for {filename} is larger than remote object: "
                f"{offset} > {total}"
            )

        try:
            response, observed_total = open_range(url, offset, timeout=timeout)
            if total is None:
                total = observed_total
            elif total != observed_total:
                response.close()
                raise DownloadError(
                    f"remote size changed while downloading {filename}: "
                    f"{total} -> {observed_total}"
                )

            mode = "ab" if offset else "wb"
            written_since_report = 0
            with response, part_path.open(mode) as out:
                while True:
                    block = response.read(CHUNK_SIZE)
                    if not block:
                        break
                    out.write(block)
                    written_since_report += len(block)
                    if written_since_report >= REPORT_EVERY:
                        current = out.tell()
                        percent = (current / total * 100.0) if total else 0.0
                        print(
                            f"    {filename}: {current / 1_000_000_000:.3f} / "
                            f"{total / 1_000_000_000:.3f} GB ({percent:.1f}%)",
                            flush=True,
                        )
                        written_since_report = 0

            current = part_path.stat().st_size
            if current == total:
                break
            if current > total:
                raise DownloadError(
                    f"download exceeded expected remote size for {filename}"
                )

            # A short clean read is treated as retryable; continue from disk.
            attempts += 1
            if attempts > retries:
                raise DownloadError(
                    f"incomplete response for {filename} after {retries} retries: "
                    f"{current}/{total} bytes"
                )
            time.sleep(min(2 ** attempts, 15))

        except HTTPError as exc:
            if exc.code == 416 and total is not None and offset == total:
                break
            attempts += 1
            if attempts > retries:
                raise DownloadError(
                    f"HTTP error downloading {filename}: {exc.code} {exc.reason}"
                ) from exc
            print(
                f"    retry {attempts}/{retries} after HTTP {exc.code}; "
                f"resume offset={offset}",
                flush=True,
            )
            time.sleep(min(2 ** attempts, 15))
        except (URLError, TimeoutError, ConnectionError, OSError) as exc:
            attempts += 1
            if attempts > retries:
                raise DownloadError(
                    f"network/file error downloading {filename}: {exc}"
                ) from exc
            print(
                f"    retry {attempts}/{retries} after {type(exc).__name__}; "
                f"resume offset={offset}",
                flush=True,
            )
            time.sleep(min(2 ** attempts, 15))

    if total is None:
        raise DownloadError(f"could not determine remote size for {filename}")

    actual_size = part_path.stat().st_size
    if actual_size != total:
        raise DownloadError(
            f"size verification failed for {filename}: "
            f"local={actual_size}, remote={total}"
        )

    print(f"    verifying MD5 for {filename}...", flush=True)
    actual_md5 = md5_file(part_path)
    if actual_md5.lower() != expected_md5.lower():
        raise DownloadError(
            f"MD5 verification failed for {filename}: "
            f"expected={expected_md5.lower()}, actual={actual_md5.lower()}"
        )

    part_path.replace(final_path)
    return {
        "name": filename,
        "status": "DOWNLOADED_VERIFIED",
        "path": str(final_path),
        "bytes": total,
        "md5": actual_md5.lower(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Range-safe resumable downloader for a Stage B Task 19 shard plan."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--record-id", default="8041387")
    parser.add_argument("--acknowledge-large-download", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=8)
    args = parser.parse_args()

    try:
        plan = load_json(args.plan)
        if plan.get("schema_version") != PLAN_SCHEMA or plan.get("status") != "PASS":
            raise DownloadError(
                "plan is not a PASS stage-b-temporal-coverage-plan-1 artifact"
            )

        downloads = plan.get("download_recommendations")
        if not isinstance(downloads, list):
            raise DownloadError("plan download_recommendations must be a list")

        total_estimated = sum(
            int(row.get("size_bytes_estimated", 0))
            for row in downloads
            if isinstance(row, Mapping)
        )
        print(f"Planned archive downloads: {len(downloads)}")
        print(
            f"Estimated additional size: "
            f"{total_estimated / 1_000_000_000:.3f} GB (planning estimate)"
        )
        print(f"Destination: {args.destination}")

        if not downloads:
            print("No additional downloads required.")
            return 0

        if not args.acknowledge_large_download:
            raise DownloadError(
                "large download not started; pass --acknowledge-large-download"
            )

        results = []
        for index, row in enumerate(downloads, start=1):
            if not isinstance(row, Mapping):
                raise DownloadError("invalid download recommendation")
            filename = row.get("name")
            expected_md5 = row.get("md5")
            if not isinstance(filename, str) or not filename.endswith(".zip"):
                raise DownloadError(f"invalid planned archive name: {filename!r}")
            if not isinstance(expected_md5, str) or not re.fullmatch(
                r"[0-9a-fA-F]{32}", expected_md5
            ):
                raise DownloadError(f"invalid planned MD5 for {filename}")

            print(f"[{index}/{len(downloads)}] {filename}", flush=True)
            result = download_one(
                record_id=args.record_id,
                filename=filename,
                expected_md5=expected_md5.lower(),
                destination=args.destination,
                timeout=args.timeout,
                retries=args.retries,
            )
            print(
                f"    {result['status']} "
                f"{result['bytes'] / 1_000_000_000:.3f} GB "
                f"md5={result['md5']}",
                flush=True,
            )
            results.append(result)

        report = {
            "status": "PASS",
            "transport": "HTTP_RANGE_RESUMABLE",
            "full_body_fallback_allowed": False,
            "downloads": results,
            "verified_files": len(results),
            "bytes": sum(int(row["bytes"]) for row in results),
        }
        print(json.dumps(report, indent=2))
        return 0

    except (DownloadError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
