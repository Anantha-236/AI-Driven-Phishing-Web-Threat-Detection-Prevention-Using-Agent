from __future__ import annotations
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from ml.data.stage_b_zenodo8041387 import adapt_class, discover_html, resolve_columns

def _write_csv(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer=csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)

def _oid(i:int)->str: return f"{i:024x}"

def test_real_columns_prefer_domain_scan_date_and_brands():
    c=resolve_columns(["_id","assets_downloaded","brands","domain","folder_path","scan_date","url"], label=1)
    assert (c.id,c.url,c.date,c.brand)==("_id","domain","scan_date","brands")

def test_24hex_directory_collapses_multiple_html_to_one_record(tmp_path: Path):
    root=tmp_path/"phishing_5001-5151"; oid="64042704845bed3cfa5ef610"; d=root/oid; d.mkdir(parents=True)
    (d/"index.html").write_text("main",encoding="utf-8"); a=d/"assets"; a.mkdir(); (a/"fragment.html").write_text("fragment",encoding="utf-8")
    result=discover_html(root); assert list(result)==[oid]; assert result[oid].source_path.name=="index.html"

def test_real_id_metadata_join_uses_object_id(tmp_path: Path):
    root=tmp_path/"phishing_5001-5151"; csv_path=tmp_path/"phishing.csv"; rows=[]; base=datetime(2026,1,1,tzinfo=timezone.utc)
    for i in range(1,9):
        oid=_oid(i); d=root/oid; d.mkdir(parents=True); (d/"index.html").write_text(f"<html>{i}</html>",encoding="utf-8")
        rows.append({"_id":oid,"brands":f"Brand {i}","domain":f"sub{i}.site{i}.example","folder_path":oid,"scan_date":(base+timedelta(days=i)).isoformat(),"url":f"https://sub{i}.site{i}.example/login"})
    _write_csv(csv_path,rows); records,report=adapt_class(root,csv_path,label=1,brand_aliases={})
    assert len(records)==8; assert report["archive_record_ids_detected"]==8; assert report["matched_metadata_records"]==8
