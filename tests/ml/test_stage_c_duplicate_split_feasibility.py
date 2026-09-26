
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import pytest

from ml.data.stage_c_duplicate_split_feasibility import (
    StageCSplitFeasibilityError,
    analyze_temporal_feasibility,
    build_artifact_groups,
    build_duplicate_audit,
    evaluate_cutoffs,
    _require_inputs,
)

def record(sample_id, rec_id, label, date, digest, oversized=False):
    return {
        "sample_id": sample_id,
        "rec_id": rec_id,
        "url": f"https://x/{rec_id}",
        "website": f"{rec_id}.html",
        "label": label,
        "created_date": date,
        "nested_archive": "x.zip",
        "member_name": f"{rec_id}.html",
        "html_size_bytes": 10,
        "html_crc32": "00000000",
        "html_sha256": digest,
        "oversized_over_12_mib": oversized,
    }

def tiny_index():
    rows = [
        record("s1",1,0,"2021-01-01 00:00:00","a"*64),
        record("s2",2,0,"2021-01-02 00:00:00","a"*64),
        record("s3",3,1,"2021-01-03 00:00:00","b"*64),
        record("s4",4,0,"2021-01-04 00:00:00","b"*64), # cross-label with s3
        record("s5",5,1,"2021-02-01 00:00:00","c"*64),
        record("s6",6,0,"2021-03-01 00:00:00","d"*64),
        record("s7",7,1,"2021-04-01 00:00:00","e"*64, oversized=True),
        record("s8",8,0,"2021-05-01 00:00:00","f"*64),
        record("s9",9,1,"2021-06-01 00:00:00","g"*64),
        record("s10",10,0,"2021-07-01 00:00:00","h"*64),
    ]
    return {
        "schema_version":"stage-c-development-record-index-1",
        "status":"PASS","stage":"C","role":"DEVELOPMENT",
        "research_only":True,"deployment_authorized":False,
        "model_training_authorized":False,"feature_extraction_authorized":False,
        "final_holdout_touched":False,
        "record_count":len(rows),
        "class_counts":{"legitimate":6,"phishing":4},
        "records":rows,
    }

def policy():
    return {
        "schema_version":"stage-c-development-split-planning-policy-1",
        "stage":"C","research_only":True,"deployment_authorized":False,
        "chronology":{
            "target_record_fractions":{"train":0.6,"selection":0.2,"calibration":0.2},
            "candidate_quantile_grid":{
                "first_cutoff_min":0.3,"first_cutoff_max":0.5,"first_cutoff_step":0.1,
                "second_cutoff_min":0.6,"second_cutoff_max":0.8,"second_cutoff_step":0.1
            }
        },
        "planning_floors":{
            "selection":{"legitimate":0,"phishing":0},
            "calibration":{"legitimate":0,"phishing":0},
        }
    }

def test_cross_label_and_oversized_quarantine():
    audit, ids = build_duplicate_audit(tiny_index())
    assert audit["duplicate_artifacts"]["groups"] == 2
    assert audit["cross_label_duplicate_artifacts"]["groups"] == 1
    assert audit["cross_label_duplicate_artifacts"]["samples"] == 2
    assert audit["oversized_sample_count"] == 1
    assert ids == {"s3","s4","s7"}
    assert audit["eligible_sample_count"] == 7

def test_same_label_duplicate_stays_one_group():
    idx=tiny_index()
    _, q=build_duplicate_audit(idx)
    groups=build_artifact_groups(idx,q)
    a=next(x for x in groups if x["artifact_sha256"]=="a"*64)
    assert a["samples"]==2
    assert a["label"]==0

def test_bridge_quarantine_when_artifact_spans_cutoff():
    from datetime import datetime
    idx=tiny_index()
    _, q=build_duplicate_audit(idx)
    groups=build_artifact_groups(idx,q)
    result=evaluate_cutoffs(
        groups,
        datetime.fromisoformat("2021-01-01 12:00:00"),
        datetime.fromisoformat("2021-05-15 00:00:00"),
    )
    assert result["bridge_quarantine"]["legitimate"] == 2

def test_temporal_analysis_returns_recommendation():
    idx=tiny_index()
    audit,q=build_duplicate_audit(idx)
    out=analyze_temporal_feasibility(index=idx,quarantine_ids=q,audit=audit,policy=policy(),max_results=5)
    assert out["status"]=="PASS"
    assert out["candidate_pairs_examined"]>0
    assert out["recommended_candidate"] is not None
    assert len(out["top_candidates"])<=5

def test_no_cross_label_group_survives_quarantine():
    idx=tiny_index()
    audit,q=build_duplicate_audit(idx)
    groups=build_artifact_groups(idx,q)
    assert all(len({g["label"]})==1 for g in groups)

def test_input_guard_rejects_training_authorization():
    idx={
        "schema_version":"stage-c-development-record-index-1","status":"PASS",
        "record_count":80000,"class_counts":{"legitimate":50000,"phishing":30000},
        "deployment_authorized":False,"model_training_authorized":True,
        "feature_extraction_authorized":False,"final_holdout_touched":False,
    }
    report={
        "schema_version":"stage-c-development-record-index-report-1","status":"PASS",
        "record_count":80000,"deployment_authorized":False,
    }
    with pytest.raises(StageCSplitFeasibilityError, match="training"):
        _require_inputs(idx,report,policy())

def test_audit_does_not_emit_raw_urls():
    audit,_=build_duplicate_audit(tiny_index())
    assert "https://x/" not in repr(audit)

def test_module_has_no_training_dependency():
    import ml.data.stage_c_duplicate_split_feasibility as mod
    src=Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src
