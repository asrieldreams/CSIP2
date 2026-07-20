# python backend/add_test_blacklist.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()
with conn.cursor() as c:
    c.execute(
        "INSERT INTO reports "
        "(indicator_type, indicator, scam_type, description, "
        " source, status, list_type, severity, report_count) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        ("url", "http://group-scam-test.com",
         "Phishing", "Group chat auto-scan test",
         "test", "approved", "blacklist", "high", 5)
    )
conn.commit()
conn.close()
print("✅ http://group-scam-test.com is now blacklisted")
print("Post this in the group: group-scam-test.com")