import sys
sys.path.insert(0, '.')
from backend.database import db_instance

conn = db_instance.get_connection()
cur = conn.cursor()
statements = [
    "ALTER TABLE observations ADD COLUMN IF NOT EXISTS device_id VARCHAR(128) NOT NULL DEFAULT 'device-unknown'",
    "ALTER TABLE observations ADD COLUMN IF NOT EXISTS device_platform VARCHAR(128) DEFAULT ''",
    "ALTER TABLE observations ADD COLUMN IF NOT EXISTS privacy_policy_url TEXT DEFAULT ''",
    "ALTER TABLE observations ADD COLUMN IF NOT EXISTS terms_url TEXT DEFAULT ''",
]

for stmt in statements:
    try:
        cur.execute(stmt)
        print('OK:', stmt)
    except Exception as e:
        print('ERR:', stmt, e)

conn.commit()
cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'observations' ORDER BY ordinal_position")
print(cur.fetchall())
cur.close()
conn.close()
