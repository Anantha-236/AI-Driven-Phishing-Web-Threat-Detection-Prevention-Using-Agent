
from __future__ import annotations
from io import BytesIO
import hashlib
from pathlib import Path
import zipfile
import pytest
from ml.data.stage_c_corpus_inspection import StageCCorpusInspectionError, inspect_development_corpus, inspect_index_sql, inspect_nested_zip_bytes

def nz(files):
    b=BytesIO()
    with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as z:
        for n,c in files.items(): z.writestr(n,c)
    return b.getvalue()

def fixture(tmp_path):
    index=b"""CREATE TABLE `index` (
`rec_id` int NOT NULL,
`url` text NOT NULL,
`website` varchar(50) NOT NULL,
`result` int NOT NULL,
`created_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY (`rec_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;
INSERT INTO `index` (`rec_id`,`url`,`website`,`result`,`created_date`) VALUES
(1,'https://a.test/x?a=1;still-url','1001.html',1,'2021-01-01 00:00:00'),
(2,'https://b.test/?x=&amp;y=2','1002.html',0,'2021-01-02 00:00:00');
"""
    p1=nz({"1001.html":b"a"})
    p2=nz({"1002.html":b"b","orphan.html":b"x"})
    outer=tmp_path/"n96ncsr5g4-1.zip"
    with zipfile.ZipFile(outer,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("n96ncsr5g4-1/index.sql",index)
        z.writestr("n96ncsr5g4-1/dataset/dataset_part_1.zip",p1)
        z.writestr("n96ncsr5g4-1/dataset/dataset_part_2.zip",p2)
    members=[]
    with zipfile.ZipFile(outer) as z:
        for info in z.infolist():
            payload=z.read(info)
            members.append({"name":info.filename,"sha256":hashlib.sha256(payload).hexdigest()})
    seal={"schema_version":"stage-c-public-download-local-seal-1","status":"PASS","stage":"C","role":"DEVELOPMENT","verification_mode":"PUBLIC_DOWNLOAD_LOCAL_SEAL","model_training_authorized":False,"extraction_authorized":False,"final_holdout_touched":False,"source":{"doi":"10.17632/n96ncsr5g4.1","version":1},"archive":{"filename":outer.name,"size_bytes":outer.stat().st_size,"sha256":"f"*64},"members":members,"member_set_sha256":"e"*64}
    return outer,seal

def test_create_table_options_do_not_swallow_inserts():
    r=inspect_index_sql(b"CREATE TABLE `index` (`rec_id` int, `created_date` datetime) ENGINE=InnoDB; INSERT INTO `index` (`rec_id`,`created_date`) VALUES (1,'2021-01-01');")
    assert [x["name"] for x in r["tables"][0]["columns"]]==["rec_id","created_date"]
    assert "ENGINE=InnoDB" in r["tables"][0]["table_options"]

def test_semicolon_inside_url_does_not_truncate_insert():
    r=inspect_index_sql(b"CREATE TABLE x (`id` int, `url` text); INSERT INTO x (`id`,`url`) VALUES (1,'https://a/?x=1;z=2'),(2,'https://b');")
    assert r["insert_summary"]["total_insert_rows"]==2

def test_dataset_semantics():
    r=inspect_index_sql(b"CREATE TABLE `index` (`rec_id` int,`url` text,`website` varchar(50),`result` int,`created_date` datetime);")
    assert r["semantic_column_candidates"]=={"record_id":["rec_id"],"url":["url"],"label":["result"],"html_or_path":["website"],"time":["created_date"]}

def test_nested_html_basenames():
    r=inspect_nested_zip_bytes("x.zip",nz({"1001.html":b"a","dir/1002.html":b"b"}))
    assert r["html_files"]==2 and r["unique_html_basenames"]==2

def test_reconciliation(tmp_path):
    path,seal=fixture(tmp_path)
    r=inspect_development_corpus(archive_path=path,seal=seal)
    rec=r["reconciliation"]
    assert rec["metadata_rows"]==2
    assert rec["class_counts"]=={"0":1,"1":1}
    assert rec["metadata_missing_html_count"]==0
    assert rec["archive_extra_html_count"]==1

def test_privacy_safe_report(tmp_path):
    path,seal=fixture(tmp_path)
    rendered=repr(inspect_development_corpus(archive_path=path,seal=seal))
    assert "https://a.test" not in rendered
    assert "orphan.html" not in rendered

def test_changed_hash_rejected(tmp_path):
    path,seal=fixture(tmp_path)
    seal["members"]=[dict(x) for x in seal["members"]]
    next(x for x in seal["members"] if x["name"].endswith("dataset_part_1.zip"))["sha256"]="0"*64
    with pytest.raises(StageCCorpusInspectionError,match="hash differs"):
        inspect_development_corpus(archive_path=path,seal=seal)

def test_training_guard_false(tmp_path):
    path,seal=fixture(tmp_path); seal["model_training_authorized"]=True
    with pytest.raises(StageCCorpusInspectionError,match="guard mismatch"):
        inspect_development_corpus(archive_path=path,seal=seal)
