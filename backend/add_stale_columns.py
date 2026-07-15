# ============================================================
#  Run ONCE to add stale-tracking columns
#  python backend/add_stale_columns.py
# ============================================================
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    # Track when the URL was last actively reported
    try:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN last_reported_at DATETIME DEFAULT NULL
        """)
        print("✅ last_reported_at added")
    except Exception as e:
        print(f"⏭️  last_reported_at: {e}")

    # Track reachability check results
    try:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN reachability VARCHAR(20) DEFAULT 'unknown'
        """)
        print("✅ reachability added")
    except Exception as e:
        print(f"⏭️  reachability: {e}")

    # Track when last reachability check was done
    try:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN last_checked_at DATETIME DEFAULT NULL
        """)
        print("✅ last_checked_at added")
    except Exception as e:
        print(f"⏭️  last_checked_at: {e}")

    # Set last_reported_at to submitted_at for existing records
    cursor.execute("""
        UPDATE reports
        SET last_reported_at = submitted_at
        WHERE last_reported_at IS NULL
    """)
    print("✅ Backfilled last_reported_at from submitted_at")

conn.commit()
conn.close()
print("\n✅ Migration complete!")