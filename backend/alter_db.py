# ============================================================
#  CSIP2 — Run this to add new columns to reports table
#  python backend/alter_db.py
# ============================================================
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()

columns = [
    ("severity",      "ALTER TABLE reports ADD COLUMN severity ENUM('low','medium','high') DEFAULT 'medium'"),
    ("platform",      "ALTER TABLE reports ADD COLUMN platform VARCHAR(50) DEFAULT NULL"),
    ("amount_lost",   "ALTER TABLE reports ADD COLUMN amount_lost DECIMAL(10,2) DEFAULT NULL"),
    ("incident_date", "ALTER TABLE reports ADD COLUMN incident_date DATE DEFAULT NULL"),
]

with conn.cursor() as cursor:
    for col_name, sql in columns:
        try:
            cursor.execute(sql)
            print(f"✅ Added column: {col_name}")
        except Exception as e:
            if "Duplicate column" in str(e):
                print(f"⏭️  Column already exists: {col_name}")
            else:
                print(f"❌ Error adding {col_name}: {e}")

    conn.commit()

    # Verify
    cursor.execute("DESCRIBE reports")
    rows = cursor.fetchall()
    print("\n📋 Current reports table columns:")
    for r in rows:
        print(f"  {r['Field']:20} {r['Type']}")

conn.close()
print("\nDone!")