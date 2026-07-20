# Run ONCE: python backend/add_rejection_count.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    try:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN rejection_count INT DEFAULT 0
        """)
        print("✅ rejection_count column added")
    except Exception as e:
        print(f"⏭️  {e}")
conn.commit()
conn.close()
print("✅ Done!")