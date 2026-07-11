# ============================================================
#  Clear ALL audit log entries and start fresh
#  python backend/clear_audit.py
# ============================================================
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    cursor.execute("DELETE FROM audit_log")
conn.commit()
print("✅ audit_log table cleared")

with conn.cursor() as cursor:
    cursor.execute("SELECT COUNT(*) as c FROM audit_log")
    count = cursor.fetchone()['c']
print(f"✅ Remaining entries: {count}")
conn.close()