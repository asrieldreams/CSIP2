# ============================================================
#  Test: Rejected report re-reporting logic
#  python backend/test_rejection.py
# ============================================================
import sys, os, requests
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

API = 'http://localhost:5000'
URL = 'http://rejection-test-csip2.com'

def report(desc="Test report"):
    r = requests.post(f'{API}/report', json={
        'indicator_type': 'url',
        'indicator':      URL,
        'scam_type':      'Phishing',
        'description':    desc,
        'source':         'telegram',
        'severity':       'high',
        'platform':       'Website',
    }, timeout=30)
    return r.status_code, r.json()

def get_record():
    conn = get_connection()
    with conn.cursor() as c:
        c.execute(
            "SELECT id, status, admin_classified, rejection_count, report_count "
            "FROM reports WHERE indicator = %s",
            (URL,)
        )
        rows = c.fetchall()
    conn.close()
    return rows

def admin_reject(report_id):
    """Simulate admin clicking Remove in dashboard."""
    conn = get_connection()
    with conn.cursor() as c:
        c.execute(
            "UPDATE reports SET status='rejected', admin_classified=1, "
            "rejection_count=COALESCE(rejection_count,0)+1, report_count=0 "
            "WHERE id=%s",
            (report_id,)
        )
    conn.commit()
    conn.close()

def cleanup():
    conn = get_connection()
    with conn.cursor() as c:
        c.execute("DELETE FROM reports WHERE indicator=%s", (URL,))
    conn.commit()
    conn.close()

print("=" * 55)
print("CSIP2 Rejection Re-reporting Test")
print("=" * 55)

# ── Test 1: Normal report + admin reject + re-report ────────
print("\n--- Test 1: Admin-reviewed rejection blocks re-reporting ---")
cleanup()

status, resp = report("First legitimate report")
print(f"Report 1: HTTP {status} — {resp.get('message','')[:40]}")
rows = get_record()
report_id = rows[0]['id']
print(f"DB: status={rows[0]['status']}, id={report_id}")

# Admin rejects it
admin_reject(report_id)
print(f"\nAdmin rejected report {report_id} (admin_classified=1)")

# Someone tries to re-report
status2, resp2 = report("Re-reporting same URL")
print(f"\nRe-report attempt: HTTP {status2}")
if status2 == 409:
    print(f"✅ BLOCKED correctly: {resp2.get('error','')[:70]}")
else:
    print(f"❌ Should be 409 but got {status2}: {resp2}")

# ── Test 2: Non-admin rejection allows re-reporting ─────────
print("\n--- Test 2: Non-admin rejection allows one re-report ---")
cleanup()

conn = get_connection()
with conn.cursor() as c:
    # Insert a rejected report WITHOUT admin_classified
    c.execute(
        "INSERT INTO reports "
        "(indicator_type,indicator,scam_type,description,source,status,severity,rejection_count) "
        "VALUES ('url',%s,'Phishing','Old rejected','test','rejected','medium',0)",
        (URL,)
    )
conn.commit()
conn.close()
rows = get_record()
print(f"Created non-admin-rejected record: id={rows[0]['id']}, "
      f"admin_classified={rows[0]['admin_classified']}")

status3, resp3 = report("Someone else reports same URL")
print(f"\nRe-report: HTTP {status3}")
if status3 == 201 and resp3.get('reactivated'):
    print(f"✅ REACTIVATED correctly: {resp3.get('message','')[:50]}")
elif status3 == 201:
    print(f"✅ Accepted (new record): {resp3.get('message','')[:50]}")
else:
    print(f"❌ Unexpected: {status3} {resp3}")

rows = get_record()
print(f"DB after re-report: {rows}")

# ── Test 3: 3x rejected without admin → permanently locked ──
print("\n--- Test 3: Rejected 3x auto-locks ---")
cleanup()

conn = get_connection()
with conn.cursor() as c:
    # Insert with rejection_count=2 (would be blocked on 3rd)
    c.execute(
        "INSERT INTO reports "
        "(indicator_type,indicator,scam_type,description,source,status,severity,"
        "rejection_count,admin_classified) "
        "VALUES ('url',%s,'Phishing','Spam report','test','rejected','low',2,0)",
        (URL,)
    )
conn.commit()
conn.close()
rows = get_record()
print(f"Created record with rejection_count=2: id={rows[0]['id']}")

status4, resp4 = report("Fake person re-reporting again")
print(f"\n3rd re-report attempt: HTTP {status4}")
if status4 == 409:
    print(f"✅ PERMANENTLY BLOCKED: {resp4.get('error','')[:70]}")
else:
    print(f"❌ Should be 409 but got: {status4} {resp4}")

# ── Cleanup ──────────────────────────────────────────────────
cleanup()
print("\n✅ Test data cleaned up")
print("=" * 55)