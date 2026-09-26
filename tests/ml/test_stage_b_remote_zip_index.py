from __future__ import annotations

from io import BytesIO
import zipfile

import pytest

from ml.data.stage_b_remote_zip_index import (
    RemoteZipIndexError,
    index_zip_from_reader,
)


class BytesRangeReader:
    def __init__(self, data: bytes):
        self.data = data

    def size(self) -> int:
        return len(self.data)

    def read(self, start: int, end: int) -> bytes:
        return self.data[start:end + 1]


def make_zip() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("64042704845bed3cfa5ef610/index.html", "<html>a</html>")
        z.writestr("64042704845bed3cfa5ef610/assets/app.js", "x")
        z.writestr("64042939845bed3cfa5ef619/page.htm", "<html>b</html>")
        z.writestr("README.txt", "ignored")
    return buffer.getvalue()


def test_indexes_unique_record_ids_from_zip_central_directory_only():
    result = index_zip_from_reader(BytesRangeReader(make_zip()))
    assert result["record_id_count"] == 2
    assert result["record_ids"] == [
        "64042704845bed3cfa5ef610",
        "64042939845bed3cfa5ef619",
    ]
    assert result["member_count"] == 4
    assert result["central_directory_bytes"] > 0


def test_rejects_non_zip_tail():
    with pytest.raises(RemoteZipIndexError):
        index_zip_from_reader(BytesRangeReader(b"not a zip archive"))
