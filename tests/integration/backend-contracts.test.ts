import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";

function runPythonCheck(script: string) {
  const result = spawnSync("python", ["-c", script], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      PYTHONPATH: process.cwd(),
    },
  });

  if (result.error) {
    throw result.error;
  }

  return {
    status: result.status ?? 1,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

describe("CAPSTONE-1 backend contracts", () => {
  it("accepts sanitized observation payloads and persists the privacy-safe record", () => {
    const result = runPythonCheck(`
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import db_instance

client = TestClient(app)
health = client.get('/api/v1/health')
assert health.status_code == 200, health.text

before = db_instance.get_connection().cursor()
before.execute('SELECT COUNT(*) FROM observations')
before_count = before.fetchone()[0]
before.close()

payload = {
    'schemaVersion': '3.0.0',
    'collectionId': 'coll-integration-001',
    'timestamp': 1730000000,
    'deviceId': '11111111-1111-4111-8111-111111111111',
    'devicePlatform': '',
    'page': {
        'id': 'page-1',
        'url': 'https://accounts.example.com',
        'domain': 'accounts.example.com',
        'title': '',
        'formIds': ['form-1'],
        'scriptCount': 1,
        'isHTTPS': True,
        'privacyPolicyUrl': 'https://example.com',
        'termsUrl': 'https://example.com',
    },
    'forms': [{
        'id': 'form-1',
        'action': 'https://accounts.example.com',
        'isCrossDomain': False,
        'method': 'POST',
        'inputIds': ['email', 'password', 'otp'],
        'hasPasswordField': True,
        'hasOtpField': True,
        'autocompleteAttributes': [],
        'detectedDataTypes': ['EMAIL', 'PASSWORD', 'OTP'],
        'target': ''
    }],
    'inputs': [
        {'id': 'email', 'inputType': 'email', 'name': '', 'idAttribute': '', 'autocomplete': '', 'isPassword': False, 'isOtp': False, 'detectedDataTypes': ['EMAIL'], 'isRequired': True},
        {'id': 'password', 'inputType': 'password', 'name': '', 'idAttribute': '', 'autocomplete': '', 'isPassword': True, 'isOtp': False, 'detectedDataTypes': ['PASSWORD'], 'isRequired': True},
        {'id': 'otp', 'inputType': 'text', 'name': '', 'idAttribute': '', 'autocomplete': '', 'isPassword': False, 'isOtp': True, 'detectedDataTypes': ['OTP'], 'isRequired': True}
    ],
    'scripts': [{'id': 'script-1', 'src': 'https://cdn.example.com', 'isInline': False, 'isCrossDomain': True}],
    'requests': [{'id': 'request-1', 'url': 'https://accounts.example.com', 'method': 'POST', 'isCrossDomain': False}],
    'requestedDataTypes': ['EMAIL', 'PASSWORD', 'OTP'],
    'threatLevel': 'malicious',
    'modelScore': 0.95,
    'policyAction': 'BLOCK'
}

response = client.post('/api/v1/observations', json=payload)
assert response.status_code == 201, response.text
body = response.json()
assert body['status'] == 'ACCEPTED'
assert body['requestedDataTypes'] == ['EMAIL', 'PASSWORD', 'OTP']
assert body['isStored'] is True

conn = db_instance.get_connection()
cur = conn.cursor()
cur.execute("SELECT observation_id, collection_id, page_domain, form_count, input_count, requested_data_types, threat_level, model_score, policy_action FROM observations WHERE collection_id = %s ORDER BY observed_at DESC LIMIT 1", ('coll-integration-001',))
row = cur.fetchone()
assert row is not None, 'Observation was not persisted'
assert row[3] == 1
assert row[4] == 3
assert 'EMAIL' in row[5]
assert 'PASSWORD' in row[5]
assert 'OTP' in row[5]
assert row[6] == 'malicious'
assert row[7] == 0.95
assert row[8] == 'BLOCK'
cur.close(); conn.close()
print('INTEGRATION_ACCEPTED=PASS')
`);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("INTEGRATION_ACCEPTED=PASS");
  }, 20000);

  it("rejects privacy-unsafe payloads before they reach PostgreSQL", () => {
    const result = runPythonCheck(`
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import db_instance

client = TestClient(app)
conn = db_instance.get_connection(); cur = conn.cursor(); cur.execute('SELECT COUNT(*) FROM observations'); before = cur.fetchone()[0]; cur.close(); conn.close()

payload = {
    'schemaVersion': '3.0.0',
    'collectionId': 'coll-integration-002',
    'timestamp': 1730000001,
    'deviceId': '22222222-2222-4222-8222-222222222222',
    'devicePlatform': '',
    'page': {
        'id': 'page-2',
        'url': 'https://example.com',
        'domain': 'example.com',
        'title': '',
        'formIds': ['form-2'],
        'scriptCount': 0,
        'isHTTPS': True,
        'privacyPolicyUrl': '',
        'termsUrl': '',
    },
    'forms': [{
        'id': 'form-2',
        'action': 'https://example.com',
        'isCrossDomain': False,
        'method': 'POST',
        'inputIds': ['field-1'],
        'hasPasswordField': False,
        'hasOtpField': False,
        'autocompleteAttributes': [],
        'detectedDataTypes': ['USERNAME'],
        'target': ''
    }],
    'inputs': [{
        'id': 'field-1',
        'inputType': 'text',
        'name': '',
        'idAttribute': '',
        'autocomplete': '',
        'isPassword': False,
        'isOtp': False,
        'detectedDataTypes': ['USERNAME'],
        'isRequired': False,
        'value': 'sensitive-secret'
    }],
    'scripts': [],
    'requests': [],
    'requestedDataTypes': ['USERNAME'],
    'threatLevel': 'benign',
    'modelScore': 0.15,
    'policyAction': 'ALLOW'
}

response = client.post('/api/v1/observations', json=payload)
assert response.status_code in (400, 422), response.text
conn = db_instance.get_connection(); cur = conn.cursor(); cur.execute('SELECT COUNT(*) FROM observations'); after = cur.fetchone()[0]; cur.close(); conn.close()
assert after == before, 'Unsafe payload should not be stored'
print('INTEGRATION_PRIVACY_REJECT=PASS')
`);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("INTEGRATION_PRIVACY_REJECT=PASS");
  }, 20000);
});
