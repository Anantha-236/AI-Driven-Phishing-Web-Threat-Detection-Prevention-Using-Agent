from __future__ import annotations

import csv
from pathlib import Path

from ml.data.stage_b_zenodo8041387 import read_csv


def test_read_csv_accepts_metadata_fields_larger_than_python_default_limit(tmp_path: Path):
    csv_path = tmp_path / 'large-field.csv'
    oversized = 'x' * 200_000

    with csv_path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=['id', 'url', 'date', 'large_metadata'],
        )
        writer.writeheader()
        writer.writerow({
            'id': '1',
            'url': 'https://example.test/login',
            'date': '2026-01-01',
            'large_metadata': oversized,
        })

    headers, rows = read_csv(csv_path)

    assert headers == ['id', 'url', 'date', 'large_metadata']
    assert len(rows) == 1
    assert len(rows[0]['large_metadata']) == 200_000
