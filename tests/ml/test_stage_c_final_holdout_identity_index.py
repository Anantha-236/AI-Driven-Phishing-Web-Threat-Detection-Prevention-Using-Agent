from pathlib import Path
import pytest
import ml.data.stage_c_final_holdout_identity_index as mod
from ml.data.stage_c_final_holdout_identity_index import StageCFinalHoldoutIdentityIndexError

def test_schema_and_task28_hashes_are_frozen():
    assert mod.INDEX_SCHEMA=='stage-c-final-holdout-identity-index-1'; assert mod.REPORT_SCHEMA=='stage-c-final-holdout-mapping-schema-report-1'; assert mod.EXPECTED_TASK28_SEAL_SHA256=='bfd50f0ded9819f8212c285e4a9821834b3c67beff79d56cdc8c43d1c602199a'
def test_artifact_hashes_are_frozen():
    assert mod.EXPECTED_HTML_SHA256=='12440e4f911fabf4ec2c712ae014cb43e638e9a6adc6c7c6a506a8a7df24fcf7'; assert mod.EXPECTED_MAPPING_SHA256=='e6dda6a21d925f8aba36090f295b08e9808a5dfe8dd3276bf8cd82022855f14a'
def test_resolve_standard_headers(): assert mod._resolve_columns(['serial_number','URL','label'])=={'serial':0,'url':1,'label':2}
def test_resolve_optional_html(): assert mod._resolve_columns(['serial no','url','HTML File','class'])=={'serial':0,'url':1,'html':2,'label':3}
def test_ambiguous_url_fails():
    with pytest.raises(StageCFinalHoldoutIdentityIndexError,match='exactly one url'): mod._resolve_columns(['serial','url','website','label'])
@pytest.mark.parametrize(('v','e'),[('1',('1',1)),('001',('1',1)),('15.0',('15',15)),('ABC',('abc',None))])
def test_serial_normalization(v,e): assert mod._normalize_serial(v)==e
@pytest.mark.parametrize(('v','e'),[('0',0),('legitimate',0),('benign',0),('1',1),('phishing',1),('malicious',1)])
def test_label_normalization(v,e): assert mod._parse_label(v)==e
def test_bad_label_fails():
    with pytest.raises(StageCFinalHoldoutIdentityIndexError,match='unsupported'): mod._parse_label('unknown')
def test_url_normalization():
    n,h=mod._normalize_url('HTTPS://Example.COM:443/login?q=1#frag'); assert n=='https://example.com/login?q=1'; assert h=='example.com'
def test_url_without_scheme():
    n,h=mod._normalize_url('Example.com/login'); assert n=='http://example.com/login'; assert h=='example.com'
def test_sample_id(): assert mod._sample_id('12',12)=='mendeley-fmbs4kp9wz-v3:00012'
def test_safe_member_names(): assert mod._safe_member_name('All_HTML/1.txt') is True and mod._safe_member_name('../1.txt') is False
def test_no_feature_extraction_or_scoring():
    s=Path(mod.__file__).read_text(); assert 'predict_proba' not in s; assert '.fit(' not in s; assert "'html_features_extracted':False" in s; assert "'model_scoring_performed':False" in s
def test_raw_urls_not_persisted():
    s=Path(mod.__file__).read_text(); assert "'raw_urls_persisted':False" in s; assert "'normalized_url_sha256'" in s; assert "'hostname_sha256'" in s
def test_next_gate_contamination(): assert 'AUDIT_STAGE_C_FINAL_HOLDOUT_CONTAMINATION_AGAINST_' in Path(mod.__file__).read_text()
def test_frozen_write(tmp_path):
    p=tmp_path/'x.json'; assert mod.frozen_write_json(p,{'x':1})=='CREATED'; assert mod.frozen_write_json(p,{'x':1})=='EXISTING_MATCH'
    with pytest.raises(StageCFinalHoldoutIdentityIndexError,match='non-identical'): mod.frozen_write_json(p,{'x':2})
