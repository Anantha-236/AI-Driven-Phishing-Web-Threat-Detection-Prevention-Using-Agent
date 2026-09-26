from __future__ import annotations

from io import BytesIO
import struct
import zipfile

from ml.data.stage_b_remote_zip_index import index_zip_from_reader


class BytesRangeReader:
    def __init__(self, data: bytes):
        self.data = data

    def size(self) -> int:
        return len(self.data)

    def read(self, start: int, end: int) -> bytes:
        return self.data[start:end + 1]


def _standard_zip() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("64042704845bed3cfa5ef610/index.html", "<html>a</html>")
        archive.writestr("64042939845bed3cfa5ef619/page.htm", "<html>b</html>")
    return buffer.getvalue()


def _force_zip64_directory(raw: bytes) -> bytes:
    eocd_pos = raw.rfind(b"PK\x05\x06")
    assert eocd_pos >= 0
    (
        _signature,
        disk_number,
        cd_disk_number,
        disk_entries,
        total_entries,
        cd_size,
        cd_offset,
        comment_length,
    ) = struct.unpack_from("<4s4H2LH", raw, eocd_pos)
    assert disk_number == cd_disk_number == 0
    assert comment_length == 0

    body = raw[:eocd_pos]
    zip64_offset = len(body)
    zip64_eocd = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        disk_entries,
        total_entries,
        cd_size,
        cd_offset,
    )
    locator = struct.pack(
        "<4sLQL",
        b"PK\x06\x07",
        0,
        zip64_offset,
        1,
    )
    classic = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return body + zip64_eocd + locator + classic


def test_zip64_eocd_indexes_same_central_directory_without_body_fallback():
    result = index_zip_from_reader(BytesRangeReader(_force_zip64_directory(_standard_zip())))
    assert result["zip64"] is True
    assert result["record_id_count"] == 2
    assert result["record_ids"] == [
        "64042704845bed3cfa5ef610",
        "64042939845bed3cfa5ef619",
    ]
    assert result["central_directory_entries"] == 2


def test_classic_zip_still_reports_non_zip64():
    result = index_zip_from_reader(BytesRangeReader(_standard_zip()))
    assert result["zip64"] is False
    assert result["record_id_count"] == 2
