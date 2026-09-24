import sys
import json
sys.path.insert(0, '.')
from backend.database import db_instance

conn = db_instance.get_connection()
cur = conn.cursor()
cur.execute("SELECT observation_id, collection_id, device_id, device_platform, page_domain, page_url_sanitized, form_count, input_count, requested_data_types, privacy_policy_url, terms_url, threat_level, model_score, policy_action FROM observations ORDER BY observed_at DESC LIMIT 5")
rows = cur.fetchall()
result = [
    {
        'observation_id': r[0],
        'collection_id': r[1],
        'device_id': r[2],
        'device_platform': r[3],
        'page_domain': r[4],
        'page_url_sanitized': r[5],
        'form_count': r[6],
        'input_count': r[7],
        'requested_data_types': r[8],
        'privacy_policy_url': r[9],
        'terms_url': r[10],
        'threat_level': r[11],
        'model_score': r[12],
        'policy_action': r[13],
    }
    for r in rows
]
print(json.dumps(result, default=str))
cur.close()
conn.close()
