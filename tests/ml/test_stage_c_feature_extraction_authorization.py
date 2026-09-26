from pathlib import Path
import json, pytest
import ml.data.stage_c_feature_extraction_authorization as mod
from ml.data.stage_c_feature_extraction_authorization import StageCFeatureAuthorizationError

def test_frozen_write(tmp_path):
    p=tmp_path/"x.json"
    assert mod.frozen_write_json(p,{"a":1})=="CREATED"
    assert mod.frozen_write_json(p,{"a":1})=="EXISTING_MATCH"
    with pytest.raises(StageCFeatureAuthorizationError): mod.frozen_write_json(p,{"a":2})

def test_contract_guard_rejects_changed_count():
    c={"schema_version":"stage-c-development-split-contract-1","status":"PASS","stage":"C",
       "protocol_id":"low-fpr-generalization-v1","research_only":True,"deployment_authorized":False,
       "feature_extraction_authorized":False,"model_training_authorized":False,"final_holdout_touched":False,
       "next_gate":"REGISTER_STAGE_C_DEVELOPMENT_SPLIT_AND_AUTHORIZE_FEATURE_EXTRACTION",
       "artifact_isolation":{"all_zero":True},"cutoffs":{"strict_forward":True},
       "counts":{"input":80000,"total_supervised_development":1,"total_quarantined":6223}}
    with pytest.raises(StageCFeatureAuthorizationError): mod._require_split_contract(c)

def test_manifest_identity_guard():
    m={"schema_version":"stage-c-development-split-manifest-1","status":"PASS","stage":"C","role":"DEVELOPMENT",
       "research_only":True,"deployment_authorized":False,"feature_extraction_authorized":False,
       "model_training_authorized":False,"final_holdout_touched":False,"manifest_sha256":"x"}
    c={"partition_manifest_sha256":"y"}
    with pytest.raises(StageCFeatureAuthorizationError): mod._require_split_manifest(m,c)

def test_artifact_overlap_detected():
    m={"partitions":{
        "train":[{"sample_id":"a","html_sha256":"1"*64,"label":0}],
        "selection":[{"sample_id":"b","html_sha256":"1"*64,"label":1}],
        "calibration":[]}}
    with pytest.raises(StageCFeatureAuthorizationError): mod._audit_rows(m)

def test_sample_overlap_detected():
    m={"partitions":{
        "train":[{"sample_id":"a","html_sha256":"1"*64,"label":0}],
        "selection":[{"sample_id":"a","html_sha256":"2"*64,"label":1}],
        "calibration":[]}}
    with pytest.raises(StageCFeatureAuthorizationError): mod._audit_rows(m)

def test_no_training_dependency():
    src=Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in src and "predict_proba" not in src and ".fit(" not in src

def test_feature_count_constant():
    assert len(mod.EXPECTED_CONTEXT_FEATURES)==27

def test_no_final_holdout_reference():
    src=Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "compphish" not in src and "fmbs4kp9wz" not in src
