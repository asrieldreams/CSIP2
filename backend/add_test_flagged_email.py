# python backend/add_test_flagged_email.py
# Adds a FLAGGED (suspected/whitelist) email for testing the amber banner
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

TEST_EMAIL  = 'flagged-sender@suspicious.com'   # change to any email you want to test

conn = get_connection()
with conn.cursor() as c:
    # Check if already exists
    c.execute("SELECT id FROM reports WHERE indicator = %s", (TEST_EMAIL,))
    existing = c.fetchone()

    if existing:
        c.execute(
            "UPDATE reports SET status='approved', list_type='whitelist' WHERE indicator=%s",
            (TEST_EMAIL,)
        )
        print(f"✅ Updated to whitelist: {TEST_EMAIL}")
    else:
        c.execute(
            "INSERT INTO reports "
            "(indicator_type, indicator, scam_type, description, "
            " source, status, list_type, severity, report_count) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            ('email', TEST_EMAIL, 'Phishing',
             'Test flagged email for extension testing',
             'test', 'approved', 'whitelist', 'medium', 2)
        )
        print(f"✅ Added as suspected/flagged: {TEST_EMAIL}")

conn.commit()
conn.close()
print(f"\nNow send yourself an email FROM {TEST_EMAIL}")
print("(or open Gmail and look for an email from that address)")
print("The ⚠️ FLAGGED SENDER amber banner should appear!")
print("\nCleanup when done:")
print(f"DELETE FROM reports WHERE indicator='{TEST_EMAIL}';")