from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.download_stage_b_planned_shards import md5_file, zenodo_url


def test_zenodo_url_uses_public_record_file_endpoint():
    url = zenodo_url("8041387", "not-phishing_1001-1500.zip")
    assert url == (
        "https://zenodo.org/records/8041387/files/"
        "not-phishing_1001-1500.zip?download=1"
    )


def test_md5_file_streams_file(tmp_path: Path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abc" * 1000)
    assert md5_file(path) == hashlib.md5(b"abc" * 1000).hexdigest()
