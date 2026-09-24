import os
os.environ['PYTHONPATH'] = '.'
from backend.database import db_instance

try:
    conn = db_instance.get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM observations')
    count = cursor.fetchone()[0]
    print(f'OBSERVATION_COUNT_BEFORE={count}')

    # Get a sample if exists
    cursor.execute('SELECT observation_id, form_count, input_count, requested_data_types FROM observations ORDER BY observed_at DESC LIMIT 1')
    sample = cursor.fetchone()
    if sample:
        print(f'LATEST_SAMPLE={sample}')

    cursor.close()
    conn.close()
except Exception as e:
    print(f'ERROR={e}')
