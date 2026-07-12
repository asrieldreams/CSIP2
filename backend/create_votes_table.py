# ============================================================
#  Run ONCE to create the report_votes table
#  python backend/create_votes_table.py
# ============================================================
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_votes (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            report_id   INT NOT NULL,
            scam_type   VARCHAR(50),
            severity    VARCHAR(10),
            source      VARCHAR(50) DEFAULT 'unknown',
            ip_address  VARCHAR(45),
            voted_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_report_id (report_id)
        )
    """)
conn.commit()
print("✅ report_votes table created")

with conn.cursor() as cursor:
    cursor.execute("SELECT COUNT(*) as c FROM report_votes")
    print(f"✅ Current votes: {cursor.fetchone()['c']}")
conn.close()