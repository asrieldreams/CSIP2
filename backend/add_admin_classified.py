# Run ONCE: python backend/add_admin_classified.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    try:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN admin_classified TINYINT(1) DEFAULT 0
        """)
        print("✅ admin_classified column added")
    except Exception as e:
        print(f"⏭️  {e}")
conn.commit()
conn.close()
print("✅ Done!")