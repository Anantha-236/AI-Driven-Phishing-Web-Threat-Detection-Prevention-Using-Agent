import sys
sys.path.insert(0, '.')
from backend.database import db_instance

conn = db_instance.get_connection()
cur = conn.cursor()
cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'observations' ORDER BY ordinal_position")
print(cur.fetchall())
cur.close()
conn.close()
