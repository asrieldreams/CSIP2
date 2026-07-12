# ============================================================
#  Run ONCE to add admin_locked + false_report_count columns
#  python backend/add_admin_lock.py
# ============================================================
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    # admin_locked: community votes cannot demote this
    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN admin_locked TINYINT(1) DEFAULT 0")
        print("✅ admin_locked column added")
    except Exception as e:
        print(f"⏭️  admin_locked: {e}")

    # false_report_count: how many people said "not a scam"
    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN false_report_count INT DEFAULT 0")
        print("✅ false_report_count column added")
    except Exception as e:
        print(f"⏭️  false_report_count: {e}")

    # Add false_report type to report_votes
    try:
        cursor.execute("ALTER TABLE report_votes ADD COLUMN vote_type VARCHAR(20) DEFAULT 'report'")
        print("✅ vote_type column added to report_votes")
    except Exception as e:
        print(f"⏭️  vote_type: {e}")

conn.commit()
conn.close()
print("\n✅ Migration complete!")