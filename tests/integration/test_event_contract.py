"""Run: python -m pytest tests/integration/test_event_contract.py -q"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.events import EventBatch, origin_only
from backend.app import handle_request
from backend.models import ObservationRequest
from backend.main import app
from backend.database import db_instance

def event():
    return dict(schema_version='1.1.0', session_id=str(uuid.uuid4()), tab_id=991,
                document_id='a' * 32, frame_id=0, parent_frame_id=-1, event_seq=1,
                event_type='FIELD_DISCOVERED', sensitive_type='OTP', field_id='e-1', form_id='f-2',
                frame_origin='https://example.test', timestamp_ms=1, received_ms=2,
                trust='ISOLATED_CONTENT_SCRIPT', confidence=1.0)

def test_origin_and_unknown_fields_rejected_without_echo():
    client = TestClient(app)
    valid = event()
    assert EventBatch.model_validate({'events': [valid]})
    for field, value in [('frame_origin', 'https://user:AUDIT_CANARY@example.test'),
                         ('target_origin', 'https://example.test/path?token=AUDIT_CANARY'),
                         ('destination_origin', 'https://example.test/#AUDIT_CANARY'),
                         ('sensitive_type', 'AUDIT_CANARY'), ('value', 'AUDIT_CANARY'),
                         ('request_type', 'AUDIT_CANARY')]:
        bad = deepcopy(valid); bad[field] = value
        response = client.post('/api/v1/events/batch', json={'events': [bad]})
        assert response.status_code == 422
        assert 'AUDIT_CANARY' not in response.text

def test_idempotent_event_storage_and_readback():
    client = TestClient(app)
    valid = event()
    payload = {'events': [valid]}
    try:
        for _ in range(2):
            response = client.post('/api/v1/events/batch', json=payload)
            assert response.status_code == 201
            assert response.json()['isStored']
        with db_instance.get_connection() as conn:
            rows = conn.execute('SELECT event FROM events_sanitized WHERE session_id = %s', (valid['session_id'],)).fetchall()
            assert len(rows) == 1
            assert rows[0][0]['sensitive_type'] == 'OTP'
        changed = dict(valid); changed['sensitive_type'] = 'PASSWORD'
        conflict = client.post('/api/v1/events/batch', json={'events': [changed]})
        assert conflict.status_code == 409
    finally:
        with db_instance.get_connection() as conn:
            conn.execute('DELETE FROM events_sanitized WHERE session_id = %s', (valid['session_id'],))
            conn.commit()

def test_database_failure_is_not_reported_as_stored(monkeypatch):
    def unavailable():
        raise RuntimeError('AUDIT_CANARY')
    monkeypatch.setattr(db_instance, 'get_connection', unavailable)
    response = TestClient(app).post('/api/v1/events/batch', json={'events': [event()]})
    assert response.status_code == 503
    assert 'AUDIT_CANARY' not in response.text


def observation():
    return dict(collectionId='coll-mabcdef0-1', timestamp=1,
                page=dict(id='page-1', url='https://example.test', domain='example.test', isHTTPS=True))


def test_metadata_responses_ignore_database_only_columns(monkeypatch):
    model = dict(model_id='m', version='1', model_type='test', sha256_hash='0' * 64,
                 is_active=True, created_at=datetime.now(timezone.utc))
    profile = dict(service_id='s', service_name='S', category='test', domains=[],
                   declared_behavior=None, created_at=datetime.now(timezone.utc))
    monkeypatch.setattr(db_instance, 'get_active_model', lambda: model)
    monkeypatch.setattr(db_instance, 'get_service_profile', lambda _: profile)
    client = TestClient(app)
    for path in ['/api/v1/models/current', '/api/v1/services/s']:
        response = client.get(path)
        assert response.status_code == 200
        assert 'created_at' not in response.json()
        code, body = handle_request('GET', path)
        assert code == 200
        assert json.loads(json.dumps(body)) == response.json()


def test_observation_entry_points_store_same_validated_defaults_and_report_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(db_instance, 'store_observation', lambda **row: calls.append(row) or True)
    payload = observation()
    payload['page']['privacyPolicyUrl'] = None
    client = TestClient(app)
    assert client.post('/api/v1/observations', json=payload).status_code == 201
    code, body = handle_request('POST', '/api/v1/observations', json.dumps(payload).encode())
    assert code == 201 and body['isStored'] is True
    assert len(calls) == 2
    for row in calls:
        row.pop('observation_id')
    assert calls[0] == calls[1]
    monkeypatch.setattr(db_instance, 'store_observation', lambda **_: False)
    assert client.post('/api/v1/observations', json=payload).status_code == 503
    code, body = handle_request('POST', '/api/v1/observations', json.dumps(payload).encode())
    assert code == 503 and 'ACCEPTED' not in json.dumps(body)


def test_observation_entry_points_reject_free_text_and_coercion_without_storage_or_echo(monkeypatch):
    def unexpected_store(**_):
        pytest.fail('Rejected input reached storage')
    monkeypatch.setattr(db_instance, 'store_observation', unexpected_store)
    client = TestClient(app)
    cases = [('collectionId', 'AUDIT_CANARY'), ('deviceId', 'AUDIT_CANARY'),
             ('devicePlatform', 'AUDIT_CANARY'), ('page.domain', 'AUDIT_CANARY'),
             ('page.url', 'https://user:AUDIT_CANARY@example.test'),
             ('page.title', 'AUDIT_CANARY'), ('page.isHTTPS', 'false')]
    for key, value in cases:
        bad = observation()
        if key.startswith('page.'):
            bad['page'][key.split('.')[1]] = value
        else:
            bad[key] = value
        response = client.post('/api/v1/observations', json=bad)
        assert response.status_code == 422, key
        assert 'AUDIT_CANARY' not in response.text
        code, body = handle_request('POST', '/api/v1/observations', json.dumps(bad).encode())
        assert code == 422, key
        assert 'AUDIT_CANARY' not in json.dumps(body)


def test_canonical_origins_and_browser_document_ids():
    for value, domain in [('https://example.test', 'example.test'),
                          ('http://localhost:41731', 'localhost'),
                          ('http://127.0.0.1:41731', '127.0.0.1'),
                          ('https://[::1]:8443', '[::1]'),
                          ('https://xn--bcher-kva.example', 'xn--bcher-kva.example')]:
        assert origin_only(value) == value
        payload = observation()
        payload['page'].update(url=value, domain=domain)
        payload['deviceId'] = str(uuid.uuid4())
        assert ObservationRequest.model_validate(payload)
    for value in ['https://user:secret@example.test', 'https://example.test/',
                  'https://EXAMPLE.test', 'https://example.test:443',
                  'https://example.test:65536', 'https://example.test/path',
                  'https://127.1', 'https://2130706433', 'https://0177.0.0.1',
                  'https://0x7f.0.0.1', 'https://127.0.0.1.', 'https://example.123',
                  'https://[fe80::1%25eth0]', 'https://foo_bar.example', 'https://foo!bar.example',
                  'https://example.test?token=secret', 'https://example.test#secret']:
        with pytest.raises(ValueError):
            origin_only(value)
    valid = event()
    valid['document_id'] = 'FFA24D7BAE4BC266FE59D0A27C595C46'
    assert EventBatch.model_validate({'events': [valid]})
    valid['session_id'] = '-' * 36
    with pytest.raises(ValueError):
        EventBatch.model_validate({'events': [valid]})


def test_context_categories_reject_text_and_inconsistent_provenance():
    e = event()
    e.update(event_type='PAGE_CONTEXT_OBSERVED', page_purpose='LOGIN', purpose_source='STATIC_SEMANTICS')
    assert EventBatch.model_validate({'events': [e]}).events[0].page_purpose == 'LOGIN'
    for fields in [dict(page_purpose='SECRET_CONTEXT_SENTINEL'), dict(purpose_source='SECRET_CONTEXT_SENTINEL'),
                   dict(page_purpose='UNKNOWN'), dict(event_type='FIELD_DISCOVERED'), dict(page_text='SECRET_CONTEXT_SENTINEL')]:
        response = TestClient(app).post('/api/v1/events/batch', json={'events': [dict(e, **fields)]})
        assert response.status_code == 422
        assert 'SECRET_CONTEXT_SENTINEL' not in response.text


def test_local_context_report_roundtrip_and_enum_only_privacy():
    from backend.events import AgentRequest, run_ml_agent
    e = event()
    e.update(event_type='DOCUMENT_STARTED', frame_id=0, frame_origin='https://example.test', document_id='a'*32)
    report = run_ml_agent(AgentRequest(events=[e])).model_dump()
    report.update(decision_source='LOCAL_ML_AGENT', agent_version='local-context-agent-1', context_feature_version='context-features-1',
                  contextual_parameters=[0.0]*25 + [0.5, 1.0], model_calibrated=False,
                  purpose=dict(value='LOGIN', evidence_status='INFERRED', confidence='MEDIUM', basis=['STATIC_SEMANTIC_CATEGORY'], limitations=['PAGE_CLAIM_NOT_INDEPENDENTLY_VERIFIED']),
                  positive_evidence=['REQUEST_MATCHES_APPARENT_PURPOSE'], contradictions=[],
                  evidence_completeness=dict(level='PARTIAL', score=0.6, observed=['DOCUMENT_START','APPARENT_PURPOSE','DOCUMENT_CORRELATION'], missing=['FIELD_SCAN','SENSITIVE_DESTINATIONS']))
    client = TestClient(app)
    response = client.post('/api/v1/assessments', json=report)
    assert response.status_code == 201 and response.json()['isStored'] is True
    with db_instance.get_connection() as conn:
        row = conn.execute('SELECT report FROM assessments_sanitized WHERE session_id=%s AND tab_id=%s AND event_seq=%s', (e['session_id'], e['tab_id'], e['event_seq'])).fetchone()
    assert row[0] == report
    for fields in [dict(positive_evidence=['CONTEXT_SECRET_SENTINEL']), dict(contradictions=['CONTEXT_SECRET_SENTINEL']),
                   dict(purpose=dict(report['purpose'], title='CONTEXT_SECRET_SENTINEL')), dict(contextual_parameters=[0.0]*26),
                   dict(contextual_parameters=[-1.0]*27), dict(evidence_completeness=dict(report['evidence_completeness'], observed=['CONTEXT_SECRET_SENTINEL']))]:
        response = client.post('/api/v1/assessments', json=dict(report, **fields))
        assert response.status_code == 422
        assert 'CONTEXT_SECRET_SENTINEL' not in response.text


def test_security_report_rejects_secrets_and_invalid_feature_parameters(monkeypatch):
    from backend.events import SecurityReport
    valid = dict(schema_version='event-report-1', analysis_version='event-analysis-1', policy_version='evidence-policy-1',
                 session_id=str(uuid.uuid4()), tab_id=1, document_id='a'*32, event_seq=1, timestamp_ms=1,
                 page_origin='https://example.test', destinations=[], threatLevel='insufficient_evidence', risk='UNKNOWN',
                 confidence='LOW', confidence_kind='uncalibrated_evidence_coverage', action='ALLOW', outcome='DECISION_ONLY',
                 requestedDataTypes=[], evidence=[], model_id='unavailable', model_score=None, model_provenance='UNAVAILABLE',
                 unknowns=['MODEL_UNCALIBRATED'], flat_parameters=[0.0]*14, relationship_parameters=[0.0]*22, analysis_latency_ms=1.0)
    assert SecurityReport.model_validate(valid)
    valid['identity'] = {'status': 'UNKNOWN', 'service': None}
    valid['form_destinations'] = [dict(document_id='a'*32, frame_id=0, form_id='f-1', page_origin='https://example.test',
                                      target_origin='https://destination.test', status='UNVERIFIED_CROSS_ORIGIN', sensitive_types=['PASSWORD'], event_seq=1)]
    assert SecurityReport.model_validate(valid)
    def unexpected_connection():
        pytest.fail('Invalid report reached the database')
    monkeypatch.setattr(db_instance, 'get_connection', unexpected_connection)
    for field, value in [('password', 'REPORT_SENTINEL'), ('destinations', ['https://example.test/?token=REPORT_SENTINEL']),
                         ('model_id', 'REPORT_SENTINEL'), ('flat_parameters', [float('inf')]*14),
                         ('evidence', [{'code': 'REPORT_SENTINEL', 'event_seqs': [1], 'evidence_status': 'OBSERVED'}]),
                         ('identity', {'status': 'UNKNOWN', 'service': 'REPORT_SENTINEL'}),
                         ('form_destinations', [dict(valid['form_destinations'][0], target_origin='https://destination.test/?token=REPORT_SENTINEL')]),
                         ('form_destinations', [dict(valid['form_destinations'][0], value='REPORT_SENTINEL')])]:
        bad = dict(valid); bad[field] = value
        if field == 'flat_parameters':
            with pytest.raises(ValueError): SecurityReport.model_validate(bad)
        else:
            response = TestClient(app).post('/api/v1/assessments', json=bad)
            assert response.status_code == 422
            assert 'REPORT_SENTINEL' not in response.text


def test_backend_agent_features_and_model_match_frozen_browser_training_exports():
    from pathlib import Path
    import math
    from backend.events import AgentRequest, run_ml_agent
    root = Path(__file__).resolve().parents[2]
    path = root / '.runtime/event-model-training-dataset.json'
    if not path.exists():
        pytest.skip('Exact controlled training traces are a separately shared local artifact')
    data = json.loads(path.read_text())
    model = json.loads((root / 'browser-extension/assets/event-model.json').read_text())
    for row in data['episodes']:
        report = run_ml_agent(AgentRequest(events=row['events']))
        assert report.flat_parameters == row['representations']['flat_vector']
        assert report.relationship_parameters == row['representations']['relationship_vector']
        vector = report.flat_parameters if model['representation'] == 'flat' else report.relationship_parameters
        z = model['intercept'] + sum((v-m)/s*c for v,m,s,c in zip(vector,model['mean'],model['scale'],model['coefficients']))
        assert report.model_score == pytest.approx(1/(1+math.exp(-z)), abs=1e-12)
        assert report.decision_source == 'BACKEND_ML_AGENT'


def test_agent_api_rejects_injected_verdicts_mixed_streams_and_secret_fields():
    from copy import deepcopy
    e = event()
    e.update(event_type='DOCUMENT_STARTED', frame_id=0, frame_origin='https://example.test', document_id='a'*32)
    valid = {'events': [e], 'incomplete': False}
    client = TestClient(app)
    for bad in [dict(valid, action='BLOCK'), dict(valid, value='AGENT_SENTINEL'),
                {'events': [dict(e, target_origin='https://example.test/?token=AGENT_SENTINEL')]},
                {'events': [e, dict(e, event_seq=e['event_seq']+1, tab_id=e['tab_id']+1)]}, {'events': [e,e]}]:
        response = client.post('/api/v1/agent/assess', json=deepcopy(bad))
        assert response.status_code == 422
        assert 'AGENT_SENTINEL' not in response.text
    response = client.post('/api/v1/agent/assess', json=valid)
    assert response.status_code == 200
    result = response.json()
    assert result['isStored'] is True
    report = result['report']
    assert report['decision_source'] == 'BACKEND_ML_AGENT'
    assert report['action'] == 'ALLOW'
    assert report['threatLevel'] == 'insufficient_evidence'
    with db_instance.get_connection() as conn:
        row = conn.execute('SELECT report FROM assessments_sanitized WHERE session_id=%s AND tab_id=%s AND event_seq=%s',
                           (e['session_id'],e['tab_id'],e['event_seq'])).fetchone()
    assert row[0] == report


def test_agent_returns_decision_without_fabricating_storage_success(monkeypatch):
    def unavailable(): raise RuntimeError('Controlled outage')
    monkeypatch.setattr(db_instance, 'get_connection', unavailable)
    e = event()
    e.update(event_type='DOCUMENT_STARTED', frame_id=0, frame_origin='https://example.test', document_id='a'*32)
    response = TestClient(app).post('/api/v1/agent/assess', json={'events':[e]})
    assert response.status_code == 200
    assert response.json()['isStored'] is False
    assert response.json()['report']['decision_source'] == 'BACKEND_ML_AGENT'


def test_ml_can_escalate_evidence_to_confirmation_but_never_blocks_from_score_alone(monkeypatch):
    from pathlib import Path
    from backend.events import AgentRequest, run_ml_agent
    base = event()
    base.update(sensitive_type=None, field_id=None, form_id=None, frame_origin='https://example.test')
    rows = []
    for i, details in enumerate([
        dict(event_type='DOCUMENT_STARTED'),
        dict(event_type='FIELD_DISCOVERED', sensitive_type='PASSWORD', field_id='e-1', form_id='f-1'),
        dict(event_type='FORM_TARGET_OBSERVED', form_id='f-1', target_origin='https://example.test'),
        dict(event_type='SENSITIVE_INTERACTION', sensitive_type='PASSWORD', field_id='e-1', form_id='f-1'),
        dict(event_type='FORM_TARGET_OBSERVED', form_id='f-1', target_origin='https://unverified.test'),
    ]): rows.append(dict(base, **details, event_seq=i+1, timestamp_ms=i+1, received_ms=i+2))
    native_read = Path.read_bytes
    raw_model = json.loads(native_read(Path('browser-extension/assets/event-model.json')))
    raw_model['coefficients'] = [0]*14
    raw_model['representation'] = 'flat'
    raw_model['intercept'] = -20
    monkeypatch.setattr(Path, 'read_bytes', lambda path: json.dumps(raw_model).encode() if path.name == 'event-model.json' else native_read(path))
    assert run_ml_agent(AgentRequest(events=rows)).action == 'WARN'
    raw_model['intercept'] = 20
    escalated = run_ml_agent(AgentRequest(events=rows))
    assert escalated.action == 'CONFIRM'
    assert 'ML_ESCALATED_CONFIRMATION' in escalated.decision_reasons
    assert run_ml_agent(AgentRequest(events=rows[:3])).action == 'ALLOW'
    assert run_ml_agent(AgentRequest(events=rows, incomplete=True)).action == 'WARN'
