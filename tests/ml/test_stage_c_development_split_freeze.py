
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import pytest
import ml.data.stage_c_development_split_freeze as mod
from ml.data.stage_c_development_split_freeze import StageCSplitFreezeError, freeze_development_split, frozen_write_json

def row(i,label,date,digest,oversized=False):
    return {"sample_id":f"s{i}","rec_id":i,"url":f"https://x/{i}","website":f"{i}.html","label":label,
            "created_date":date,"nested_archive":"x.zip","member_name":f"{i}.html","html_size_bytes":10,
            "html_crc32":"00000000","html_sha256":digest,"oversized_over_12_mib":oversized}

def tiny():
    records=[
        row(1,0,"2021-01-01 00:00:00","a"*64),
        row(2,0,"2021-01-02 00:00:00","a"*64),
        row(3,1,"2021-02-01 00:00:00","b"*64),
        row(4,0,"2021-02-02 00:00:00","b"*64),
        row(5,1,"2021-03-01 00:00:00","c"*64),
        row(6,0,"2021-04-01 00:00:00","d"*64),
        row(7,1,"2021-05-01 00:00:00","e"*64),
        row(8,0,"2021-06-01 00:00:00","f"*64,True),
        row(9,1,"2021-07-01 00:00:00","g"*64),
        row(10,0,"2021-08-01 00:00:00","h"*64),
    ]
    index={"schema_version":"stage-c-development-record-index-1","status":"PASS","deployment_authorized":False,
           "model_training_authorized":False,"feature_extraction_authorized":False,"final_holdout_touched":False,
           "record_count":10,"class_counts":{"legitimate":6,"phishing":4},"record_set_sha256":"1"*64,"records":records}
    task6={"schema_version":"stage-c-development-record-index-report-1","status":"PASS","deployment_authorized":False,
           "final_holdout_touched":False,"record_count":10,"record_set_sha256":"1"*64,"index_evidence_sha256":"2"*64}
    return index,task6

def patch_guards(monkeypatch):
    monkeypatch.setattr(mod,"_require_inputs",lambda *a,**k:None)
    from collections import defaultdict
    from ml.data.stage_c_duplicate_split_feasibility import canonical_hash
    def tiny_audit(idx):
        by=defaultdict(list)
        for r in idx["records"]: by[r["html_sha256"]].append(r)
        cross={h:rs for h,rs in by.items() if len({x["label"] for x in rs})>1}
        ids={r["sample_id"] for rs in cross.values() for r in rs}
        ids|={r["sample_id"] for r in idx["records"] if r["oversized_over_12_mib"]}
        return {"quarantine_sample_set_sha256":canonical_hash(sorted(ids)),"quarantine_union_count":len(ids)},ids
    monkeypatch.setattr(mod,"build_duplicate_audit",tiny_audit)

def fixture(monkeypatch):
    index,task6=tiny()
    patch_guards(monkeypatch)
    a,q=mod.build_duplicate_audit(index)
    audit={"schema_version":"stage-c-development-duplicate-audit-1","status":"PASS","deployment_authorized":False,
           "final_holdout_touched":False,"record_count":10,"audit_evidence_sha256":"3"*64,
           "quarantine_sample_set_sha256":a["quarantine_sample_set_sha256"],"quarantine_union_count":a["quarantine_union_count"]}
    feas={"schema_version":"stage-c-development-temporal-feasibility-1","status":"PASS","deployment_authorized":False,
          "final_holdout_touched":False,"input_record_count":10,"feasibility":"STRICT_FORWARD_ARTIFACT_GROUP_SPLIT_FEASIBLE",
          "next_gate":"FREEZE_STAGE_C_DEVELOPMENT_SPLIT_CONTRACT","feasibility_evidence_sha256":"4"*64,
          "recommended_candidate":{"rank":1,"planning_floors_satisfied":True,
            "first_cutoff":"2021-03-15 00:00:00","second_cutoff":"2021-06-15 00:00:00",
            "partitions":{"train":{"total":3,"legitimate":2,"phishing":1},
                          "selection":{"total":2,"legitimate":1,"phishing":1},
                          "calibration":{"total":2,"legitimate":1,"phishing":1}},
            "bridge_quarantine":{"total":0,"legitimate":0,"phishing":0},
            "score":{"planning_floor_deficit":0,"bridge_fraction":0.0,"target_fraction_absolute_error":0.1}}}
    return index,task6,audit,feas

def test_freeze_exact_partitions(monkeypatch):
    index,t6,a,f=fixture(monkeypatch)
    c,m,q=freeze_development_split(index=index,task6_report=t6,audit=a,feasibility=f)
    assert m["partition_counts"]["train"]=={"total":3,"legitimate":2,"phishing":1}
    assert m["partition_counts"]["selection"]=={"total":2,"legitimate":1,"phishing":1}
    assert m["partition_counts"]["calibration"]=={"total":2,"legitimate":1,"phishing":1}
    assert q["initial_quarantine"]["count"]==3
    assert q["chronology_bridge_quarantine"]["count"]==0
    assert c["artifact_isolation"]["all_zero"] is True

def test_quarantine_reasons(monkeypatch):
    index,t6,a,f=fixture(monkeypatch)
    _,_,q=freeze_development_split(index=index,task6_report=t6,audit=a,feasibility=f)
    reasons={x["sample_id"]:x["reasons"] for x in q["initial_quarantine"]["entries"]}
    assert "CROSS_LABEL_EXACT_HTML_GROUP" in reasons["s3"]
    assert "CROSS_LABEL_EXACT_HTML_GROUP" in reasons["s4"]
    assert "OVERSIZED_CANONICAL_HTML_OVER_12_MIB" in reasons["s8"]

def test_artifact_sets_disjoint(monkeypatch):
    index,t6,a,f=fixture(monkeypatch)
    c,m,_=freeze_development_split(index=index,task6_report=t6,audit=a,feasibility=f)
    assert c["artifact_isolation"]["all_zero"] is True

def test_count_mismatch_fails(monkeypatch):
    index,t6,a,f=fixture(monkeypatch)
    f=deepcopy(f); f["recommended_candidate"]["partitions"]["selection"]["total"]=999
    with pytest.raises(StageCSplitFreezeError,match="selection"):
        freeze_development_split(index=index,task6_report=t6,audit=a,feasibility=f)

def test_frozen_write_idempotent(tmp_path):
    p=tmp_path/"x.json"
    assert frozen_write_json(p,{"x":1})=="CREATED"
    assert frozen_write_json(p,{"x":1})=="EXISTING_MATCH"
    with pytest.raises(StageCSplitFreezeError):
        frozen_write_json(p,{"x":2})

def test_production_guard_requires_80k():
    idx={"schema_version":"stage-c-development-record-index-1","status":"PASS","deployment_authorized":False,
         "final_holdout_touched":False,"model_training_authorized":False,"feature_extraction_authorized":False,
         "record_count":10,"record_set_sha256":"x"}
    rep={"schema_version":"stage-c-development-record-index-report-1","status":"PASS","deployment_authorized":False,
         "final_holdout_touched":False,"record_count":10,"record_set_sha256":"x"}
    aud={"schema_version":"stage-c-development-duplicate-audit-1","status":"PASS","deployment_authorized":False,
         "final_holdout_touched":False,"record_count":10}
    feas={"schema_version":"stage-c-development-temporal-feasibility-1","status":"PASS","deployment_authorized":False,
          "final_holdout_touched":False,"input_record_count":10,"feasibility":"STRICT_FORWARD_ARTIFACT_GROUP_SPLIT_FEASIBLE",
          "next_gate":"FREEZE_STAGE_C_DEVELOPMENT_SPLIT_CONTRACT",
          "recommended_candidate":{"rank":1,"planning_floors_satisfied":True,"score":{"planning_floor_deficit":0}}}
    with pytest.raises(StageCSplitFreezeError,match="record count"):
        mod._require_inputs(idx,rep,aud,feas)

def test_no_training_dependency():
    src=Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src and "predict_proba" not in src and ".fit(" not in src

def test_no_final_holdout_reference():
    src=Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src and "fmbs4kp9wz" not in src
