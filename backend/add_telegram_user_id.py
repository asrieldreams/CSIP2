# Run ONCE: python backend/add_telegram_user_id.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    try:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN telegram_user_id BIGINT DEFAULT NULL
        """)
        print("✅ telegram_user_id column added")
    except Exception as e:
        print(f"⏭️  {e}")
conn.commit()
conn.close()
print("✅ Done!")