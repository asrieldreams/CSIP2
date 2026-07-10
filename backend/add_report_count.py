# ============================================================
#  CSIP2 — Add report_count column to reports table
#  Run once: python backend/add_report_count.py
# ============================================================
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN report_count INT DEFAULT 1")
        conn.commit()
        print("✅ Added report_count column")
    except Exception as e:
        if "Duplicate column" in str(e):
            print("⏭️  report_count column already exists")
        else:
            print(f"❌ Error: {e}")

    # Set existing approved reports to count based on how many times same indicator appears
    cursor.execute("""
        UPDATE reports r1
        JOIN (
            SELECT indicator, COUNT(*) as cnt
            FROM reports
            GROUP BY indicator
        ) r2 ON r1.indicator = r2.indicator
        SET r1.report_count = r2.cnt
    """)
    conn.commit()
    print("✅ Updated report counts for existing reports")

    cursor.execute("DESCRIBE reports")
    print("\n📋 reports table now has:")
    for row in cursor.fetchall():
        if row['Field'] in ('report_count', 'indicator', 'status'):
            print(f"  {row['Field']:20} {row['Type']}")

conn.close()
print("\nDone!")