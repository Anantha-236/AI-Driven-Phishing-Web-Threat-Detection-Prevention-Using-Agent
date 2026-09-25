from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ml.data.stage_b_zenodo8041387 import (
    Zenodo8041387AdapterError,
    adapt_class,
    build_raw_plan,
    common_time_window,
    conservative_domain_group,
    discover_html,
    parse_observed_at,
    select_pilot,
    sha256_file,
)


def write_csv(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def make_class(root: Path, csv_path: Path, label: int, count=16):
    rows = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(1, count + 1):
        folder = root / f"{i:04d}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "index.html").write_text(
            f"<html><body><form><input type=password></form>{i}</body></html>",
            encoding="utf-8",
        )
        row = {
            "id": str(i),
            "url": f"https://sub{i}.site{i}.example/login",
            "discovered_at": (base + timedelta(days=i)).isoformat(),
        }
        if label == 1:
            row["target_brand"] = f"Brand {i}"
        rows.append(row)
    write_csv(csv_path, rows)


def test_domain_group_reduces_subdomain():
    assert conservative_domain_group("https://login.accounts.example.com/x") == "example.com"


def test_dates_are_normalized_to_utc():
    assert parse_observed_at("2026-01-02") == "2026-01-02T00:00:00Z"


def test_archive_adapter_resolves_common_columns_and_never_needs_raw_url_output(tmp_path: Path):
    root = tmp_path / "phishing_0001-0016"
    csv_path = tmp_path / "phishing.csv"
    make_class(root, csv_path, 1)
    records, report = adapt_class(root, csv_path, label=1, brand_aliases={})
    assert len(records) == 16
    assert report["resolved_columns"]["brand"] == "target_brand"
    assert records[0].brand_group == "brand-1"
    assert not hasattr(records[0], "url")


def test_discovers_index_html_as_primary_capture(tmp_path: Path):
    root = tmp_path / "phishing_0001-0001"
    sample = root / "0001"
    sample.mkdir(parents=True)
    (sample / "other.html").write_text("x" * 100, encoding="utf-8")
    (sample / "index.html").write_text("index", encoding="utf-8")
    result = discover_html(root)
    assert result[1].source_path.name == "index.html"


def test_pilot_selection_requires_brand_and_domain_diversity(tmp_path: Path):
    root_p = tmp_path / "p_0001-0016"
    root_l = tmp_path / "l_0001-0016"
    csv_p = tmp_path / "p.csv"
    csv_l = tmp_path / "l.csv"
    make_class(root_p, csv_p, 1)
    make_class(root_l, csv_l, 0)
    phishing, _ = adapt_class(root_p, csv_p, label=1, brand_aliases={})
    legitimate, _ = adapt_class(root_l, csv_l, label=0, brand_aliases={})
    start, end = common_time_window(phishing, legitimate)
    assert len(select_pilot(phishing, count=8, start=start, end=end, max_brand_share=0.5)) == 8
    assert len(select_pilot(legitimate, count=8, start=start, end=end, max_brand_share=0.5)) == 8


def test_raw_plan_contains_no_source_urls(tmp_path: Path):
    root_p = tmp_path / "p_0001-0016"
    root_l = tmp_path / "l_0001-0016"
    csv_p = tmp_path / "p.csv"
    csv_l = tmp_path / "l.csv"
    make_class(root_p, csv_p, 1)
    make_class(root_l, csv_l, 0)
    phishing, _ = adapt_class(root_p, csv_p, label=1, brand_aliases={})
    legitimate, _ = adapt_class(root_l, csv_l, label=0, brand_aliases={})
    start, end = common_time_window(phishing, legitimate)
    p = select_pilot(phishing, count=8, start=start, end=end, max_brand_share=0.5)
    l = select_pilot(legitimate, count=8, start=start, end=end, max_brand_share=0.5)
    plan, report = build_raw_plan(
        p, l,
        output_archive_root=tmp_path / "archive",
        metadata_hashes={"p": sha256_file(csv_p), "l": sha256_file(csv_l)},
        wait_ms=500,
        license_reference="test research terms",
        created_at="2026-09-25T00:00:00Z",
    )
    rendered = str(plan)
    assert "https://sub" not in rendered
    assert len(plan["items"]) == 16
    assert report["selected"]["total"] == 16


def test_missing_required_phishing_brand_fails_closed(tmp_path: Path):
    root = tmp_path / "p_0001-0008"
    root.mkdir()
    rows = []
    for i in range(1, 9):
        d = root / f"{i:04d}"
        d.mkdir()
        (d / "index.html").write_text("x", encoding="utf-8")
        rows.append({"id": i, "url": f"https://{i}.example", "date": "2026-01-01"})
    csv_path = tmp_path / "p.csv"
    write_csv(csv_path, rows)
    with pytest.raises(Zenodo8041387AdapterError, match="target brand"):
        adapt_class(root, csv_path, label=1, brand_aliases={})
