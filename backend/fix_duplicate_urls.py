"""
Run this ONCE to merge duplicate URL records caused by look.com vs http://look.com

python backend/fix_duplicate_urls.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

conn = get_connection()

with conn.cursor() as c:
    # Find all pairs where one is bare domain and one has http://
    c.execute("""
        SELECT r1.id as bare_id, r1.indicator as bare_url,
               r2.id as http_id, r2.indicator as http_url,
               r2.report_count, r2.status
        FROM reports r1
        JOIN reports r2
          ON (CONCAT('http://', r1.indicator) = r2.indicator
           OR CONCAT('https://', r1.indicator) = r2.indicator
           OR CONCAT('http://www.', r1.indicator) = r2.indicator)
        WHERE r1.indicator NOT LIKE 'http%'
          AND r2.indicator LIKE 'http%'
    """)
    pairs = c.fetchall()

if not pairs:
    print("✅ No bare-domain duplicates found!")
else:
    print(f"Found {len(pairs)} duplicate pair(s):")
    for p in pairs:
        print(f"  bare: {p['bare_url']} (id={p['bare_id']})  <->  http: {p['http_url']} (id={p['http_id']})")

    for p in pairs:
        # Keep whichever has http:// (normalised), merge report counts
        keep_id   = p['http_id']
        remove_id = p['bare_id']
        new_count = max(1, (p['report_count'] or 1))

        with conn.cursor() as c:
            # Update report count to reflect combined reports
            c.execute("""
                UPDATE reports
                SET report_count = %s
                WHERE id = %s
            """, (new_count + 1, keep_id))

            # Remove the bare-domain duplicate
            c.execute("DELETE FROM reports WHERE id = %s", (remove_id,))

        print(f"  ✅ Merged {p['bare_url']} → kept http record id={keep_id}")

    conn.commit()
    print("\nDone! Re-check admin dashboard.")

conn.close()