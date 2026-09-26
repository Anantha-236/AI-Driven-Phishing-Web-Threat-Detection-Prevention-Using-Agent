"""Exact Zenodo shard indexing via ZIP central-directory HTTP range reads.

This module never downloads an archive body. It requires HTTP byte-range
support and fetches only:
1. one byte to learn the remote object size;
2. the ZIP end-of-central-directory tail;
3. the central-directory byte range.

The central directory is enough to recover top-level 24-hex record IDs.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct
from typing import Any, Mapping, Protocol
from urllib.parse import quote
from urllib.request import Request, urlopen

INDEX_SCHEMA = "stage-b-zenodo-shard-index-1"
RECORD_ID_RE = re.compile(r"(?:^|[/\\\\])([0-9a-fA-F]{24})(?:[/\\\\]|$)")
EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
CD_SIGNATURE = b"PK\x01\x02"
MAX_EOCD_SEARCH = 131_072
MAX_CENTRAL_DIRECTORY_BYTES = 128 * 1024 * 1024


class RemoteZipIndexError(RuntimeError):
    pass


class RangeReader(Protocol):
    def size(self) -> int: ...
    def read(self, start: int, end: int) -> bytes: ...


class HttpRangeReader:
    def __init__(self, url: str, *, timeout: int = 90) -> None:
        self.url = url
        self.timeout = timeout
        self._size: int | None = None

    def _request(self, start: int, end: int):
        req = Request(
            self.url,
            headers={
                "Range": f"bytes={start}-{end}",
                "User-Agent": "capstone-stage-b-research-indexer/1.0",
                "Accept-Encoding": "identity",
            },
        )
        response = urlopen(req, timeout=self.timeout)
        status = getattr(response, "status", response.getcode())
        if status != 206:
            response.close()
            raise RemoteZipIndexError(
                f"server ignored HTTP Range for {self.url}: status={status}; "
                "refusing to download archive body"
            )
        content_range = response.headers.get("Content-Range", "")
        match = re.fullmatch(r"bytes\s+(\d+)-(\d+)/(\d+)", content_range.strip())
        if not match:
            response.close()
            raise RemoteZipIndexError(
                f"invalid Content-Range for {self.url}: {content_range!r}"
            )
        actual_start, actual_end, total = map(int, match.groups())
        if actual_start != start or actual_end != end:
            response.close()
            raise RemoteZipIndexError(
                f"unexpected returned range for {self.url}: "
                f"{actual_start}-{actual_end}, requested {start}-{end}"
            )
        return response, total

    def size(self) -> int:
        if self._size is not None:
            return self._size
        response, total = self._request(0, 0)
        try:
            body = response.read(2)
        finally:
            response.close()
        if len(body) != 1:
            raise RemoteZipIndexError("range size probe did not return exactly one byte")
        self._size = total
        return total

    def read(self, start: int, end: int) -> bytes:
        if start < 0 or end < start:
            raise RemoteZipIndexError(f"invalid range {start}-{end}")
        total = self.size()
        if end >= total:
            raise RemoteZipIndexError(
                f"requested range {start}-{end} exceeds remote size {total}"
            )
        response, returned_total = self._request(start, end)
        if returned_total != total:
            response.close()
            raise RemoteZipIndexError("remote object size changed during indexing")
        try:
            body = response.read((end - start) + 2)
        finally:
            response.close()
        expected = end - start + 1
        if len(body) != expected:
            raise RemoteZipIndexError(
                f"short range read: expected {expected} bytes, got {len(body)}"
            )
        return body


@dataclass(frozen=True)
class CentralDirectoryInfo:
    entries: int
    size: int
    offset: int
    zip64: bool = False


def _validate_directory_info(
    *,
    entries: int,
    size: int,
    offset: int,
    total_size: int,
    zip64: bool,
) -> CentralDirectoryInfo:
    if entries <= 0:
        raise RemoteZipIndexError("central directory has no entries")
    if size <= 0 or size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise RemoteZipIndexError(
            f"central directory size {size} exceeds safety limit"
        )
    if offset < 0 or offset + size > total_size:
        raise RemoteZipIndexError("central directory range is outside remote object")
    return CentralDirectoryInfo(
        entries=entries,
        size=size,
        offset=offset,
        zip64=zip64,
    )


def _parse_zip64_eocd(
    reader: RangeReader,
    *,
    locator: bytes,
    locator_absolute_offset: int,
    total_size: int,
) -> CentralDirectoryInfo:
    if len(locator) != 20:
        raise RemoteZipIndexError("truncated ZIP64 EOCD locator")
    signature, disk_with_record, record_offset, total_disks = struct.unpack(
        "<4sLQL", locator
    )
    if signature != ZIP64_LOCATOR_SIGNATURE:
        raise RemoteZipIndexError("ZIP64 EOCD locator signature not found")
    if disk_with_record != 0 or total_disks != 1:
        raise RemoteZipIndexError("multi-disk ZIP64 archives are unsupported")
    if record_offset < 0 or record_offset + 56 > total_size:
        raise RemoteZipIndexError("ZIP64 EOCD record range is outside remote object")

    header = reader.read(record_offset, record_offset + 55)
    if len(header) != 56:
        raise RemoteZipIndexError("truncated ZIP64 EOCD record")
    (
        record_signature,
        record_size,
        _version_made_by,
        _version_needed,
        disk_number,
        cd_disk_number,
        disk_entries,
        total_entries,
        cd_size,
        cd_offset,
    ) = struct.unpack("<4sQ2H2L4Q", header)

    if record_signature != ZIP64_EOCD_SIGNATURE:
        raise RemoteZipIndexError("invalid ZIP64 EOCD record signature")
    if record_size < 44:
        raise RemoteZipIndexError(
            f"invalid ZIP64 EOCD record size: {record_size}"
        )
    record_end = record_offset + 12 + record_size
    if record_end != locator_absolute_offset:
        raise RemoteZipIndexError(
            "ZIP64 EOCD record does not terminate at its locator; "
            "refusing ambiguous archive layout"
        )
    if disk_number != 0 or cd_disk_number != 0:
        raise RemoteZipIndexError("multi-disk ZIP64 archives are unsupported")
    if disk_entries != total_entries:
        raise RemoteZipIndexError("multi-disk ZIP64 entry counts are unsupported")

    return _validate_directory_info(
        entries=int(total_entries),
        size=int(cd_size),
        offset=int(cd_offset),
        total_size=total_size,
        zip64=True,
    )


def _parse_eocd(
    reader: RangeReader,
    tail: bytes,
    *,
    tail_start: int,
    total_size: int,
) -> CentralDirectoryInfo:
    pos = tail.rfind(EOCD_SIGNATURE)
    if pos < 0:
        raise RemoteZipIndexError("ZIP end-of-central-directory signature not found")
    if pos + 22 > len(tail):
        raise RemoteZipIndexError("truncated ZIP EOCD")

    (
        signature,
        disk_number,
        cd_disk_number,
        disk_entries,
        total_entries,
        cd_size,
        cd_offset,
        comment_length,
    ) = struct.unpack_from("<4s4H2LH", tail, pos)

    if signature != EOCD_SIGNATURE:
        raise RemoteZipIndexError("invalid EOCD signature")
    if pos + 22 + comment_length != len(tail):
        raise RemoteZipIndexError(
            "EOCD does not terminate at end of archive; refusing ambiguous ZIP tail"
        )
    if disk_number != 0 or cd_disk_number != 0:
        raise RemoteZipIndexError("multi-disk ZIP archives are unsupported")

    uses_zip64 = (
        disk_entries == 0xFFFF
        or total_entries == 0xFFFF
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
    )
    if uses_zip64:
        if pos < 20:
            raise RemoteZipIndexError("ZIP64 EOCD locator is missing before classic EOCD")
        locator = tail[pos - 20:pos]
        locator_absolute_offset = tail_start + pos - 20
        return _parse_zip64_eocd(
            reader,
            locator=locator,
            locator_absolute_offset=locator_absolute_offset,
            total_size=total_size,
        )

    if disk_entries != total_entries:
        raise RemoteZipIndexError("multi-disk ZIP entry counts are unsupported")
    return _validate_directory_info(
        entries=int(total_entries),
        size=int(cd_size),
        offset=int(cd_offset),
        total_size=total_size,
        zip64=False,
    )


def _decode_member_name(raw: bytes, flags: int) -> str:
    encoding = "utf-8" if flags & 0x800 else "cp437"
    return raw.decode(encoding, errors="replace")


def parse_central_directory(blob: bytes, expected_entries: int) -> dict[str, Any]:
    pos = 0
    entry_count = 0
    record_ids: set[str] = set()
    malformed_names = 0
    non_record_members = 0

    while pos < len(blob):
        if pos + 46 > len(blob):
            raise RemoteZipIndexError("truncated central-directory entry")
        if blob[pos:pos + 4] != CD_SIGNATURE:
            raise RemoteZipIndexError(
                f"unexpected central-directory signature at offset {pos}"
            )

        flags = struct.unpack_from("<H", blob, pos + 8)[0]
        name_length = struct.unpack_from("<H", blob, pos + 28)[0]
        extra_length = struct.unpack_from("<H", blob, pos + 30)[0]
        comment_length = struct.unpack_from("<H", blob, pos + 32)[0]
        end = pos + 46 + name_length + extra_length + comment_length
        if end > len(blob):
            raise RemoteZipIndexError("central-directory entry extends past buffer")

        raw_name = blob[pos + 46:pos + 46 + name_length]
        try:
            name = _decode_member_name(raw_name, flags)
        except Exception:
            malformed_names += 1
            pos = end
            entry_count += 1
            continue

        match = RECORD_ID_RE.search(name)
        if match:
            record_ids.add(match.group(1).lower())
        else:
            non_record_members += 1

        entry_count += 1
        pos = end

    if entry_count != expected_entries:
        raise RemoteZipIndexError(
            f"central-directory entry count mismatch: parsed={entry_count}, "
            f"EOCD={expected_entries}"
        )
    return {
        "member_count": entry_count,
        "record_ids": sorted(record_ids),
        "record_id_count": len(record_ids),
        "malformed_names": malformed_names,
        "non_record_members": non_record_members,
    }


def index_zip_from_reader(reader: RangeReader) -> dict[str, Any]:
    total_size = reader.size()
    tail_size = min(total_size, MAX_EOCD_SEARCH)
    tail_start = total_size - tail_size
    tail = reader.read(tail_start, total_size - 1)
    info = _parse_eocd(
        reader, tail, tail_start=tail_start, total_size=total_size
    )
    cd = reader.read(info.offset, info.offset + info.size - 1)
    result = parse_central_directory(cd, info.entries)
    result.update({
        "remote_size_bytes": total_size,
        "central_directory_bytes": info.size,
        "central_directory_entries": info.entries,
        "zip64": info.zip64,
    })
    return result


def zenodo_download_url(record_id: str, filename: str) -> str:
    return (
        f"https://zenodo.org/records/{record_id}/files/"
        f"{quote(filename, safe='')}?download=1"
    )


def index_remote_zenodo_archive(
    *,
    record_id: str,
    filename: str,
    timeout: int = 90,
) -> dict[str, Any]:
    url = zenodo_download_url(record_id, filename)
    reader = HttpRangeReader(url, timeout=timeout)
    result = index_zip_from_reader(reader)
    result["filename"] = filename
    return result


def atomic_write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
