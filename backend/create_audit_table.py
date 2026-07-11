# ============================================================
#  Run this ONCE to create the audit_log table
#  python backend/create_audit_table.py
# ============================================================
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            admin_id    INT,
            admin_name  VARCHAR(100) NOT NULL DEFAULT 'System',
            action      VARCHAR(50)  NOT NULL,
            target_type VARCHAR(50),
            target_id   INT,
            target_ref  VARCHAR(100),
            detail      VARCHAR(255),
            ip_address  VARCHAR(45),
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
conn.commit()
print("✅ audit_log table created (or already exists)")

# Verify
with conn.cursor() as cursor:
    cursor.execute("SELECT COUNT(*) as c FROM audit_log")
    count = cursor.fetchone()['c']
    print(f"✅ Current entries in audit_log: {count}")

conn.close()