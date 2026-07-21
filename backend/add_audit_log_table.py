# Run ONCE: python backend/add_audit_log_table.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as c:
    try:
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                action      VARCHAR(100) NOT NULL,
                target      VARCHAR(100),
                target_id   INT,
                target_type VARCHAR(50) DEFAULT 'report',
                detail      TEXT,
                admin_name  VARCHAR(100) DEFAULT 'Admin',
                ip_address  VARCHAR(45),
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_action    (action),
                INDEX idx_admin     (admin_name),
                INDEX idx_created   (created_at)
            )
        """)
        print("✅ audit_logs table created")
    except Exception as e:
        print(f"⚠️  {e}")
conn.commit()
conn.close()
print("Done!")