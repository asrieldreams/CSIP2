# ============================================================
#  CSIP2 Spike Alert Live Test
#  Run while backend AND bot are both running:
#
#  Terminal 1: python backend/app.py
#  Terminal 2: python bot/main.py
#  Terminal 3: python backend/test_spike_live.py
# ============================================================
import sys, time, requests

API = 'http://localhost:5000'
URL = 'http://spike-test-csip2-live.com'

print("=" * 55)
print("CSIP2 Spike Alert Live Test")
print("=" * 55)

# Step 1: Backend health
try:
    r = requests.get(f'{API}/health', timeout=5)
    print(f"\n✅ Backend running\n")
except Exception as e:
    print(f"\n❌ Backend not running: {e}")
    sys.exit(1)

# Step 2: Clear old test data
print(f"Clearing old test data...")
try:
    sys.path.insert(0, 'backend')
    from db import get_connection
    conn = get_connection()
    with conn.cursor() as c:
        c.execute("DELETE FROM reports WHERE indicator = %s", (URL,))
        c.execute("DELETE FROM report_votes WHERE report_id NOT IN (SELECT id FROM reports)")
    conn.commit()
    print("✅ Done\n")
except Exception as e:
    print(f"⚠️  {e}\n")

# Step 3: Submit 3 reports (30s timeout — Aiven cloud DB is slow)
print(f"Submitting 3 reports of {URL}...")
print("(Using 30s timeout — cloud DB can be slow)\n")
payload = {
    'indicator_type': 'url',
    'indicator':      URL,
    'scam_type':      'Phishing',
    'description':    'Spike test',
    'source':         'telegram',
    'severity':       'high',
    'platform':       'Website',
}

for i in range(3):
    try:
        r = requests.post(f'{API}/report', json=payload, timeout=30)
        d = r.json()
        msg = d.get('message', d.get('error', '?'))[:50]
        print(f"  Report {i+1}/3: HTTP {r.status_code} — {msg}")
    except Exception as e:
        print(f"  Report {i+1}/3: ❌ {e}")
    time.sleep(1)

# Step 4: Wait longer for Aiven background threads
print(f"\nWaiting 15s for background threads (Aiven is slow)...")
time.sleep(15)

# Step 5: Check notifications
print("\n--- /api/admin/notifications ---")
r = requests.get(f'{API}/api/admin/notifications', timeout=10)
data   = r.json()
notifs = data.get('notifications', [])
unread = data.get('unread', 0)

print(f"Total: {len(notifs)}  |  Unread: {unread}")

if notifs:
    n = notifs[0]
    print(f"\n🚨 Spike alert found!")
    print(f"   {n['icon']} {n['indicator']}")
    print(f"   {n['count']} reports in {n['minutes_span']} min · {n['scam_type']}")
    print(f"   Age: {n.get('age_minutes', 0)} min ago")
    print(f"\n✅ Dashboard bell → red badge within 30s")
    print(f"✅ Telegram DM     → within 30s")
else:
    print("\n⚠️  No notification yet — wait 15 more seconds then check again:")
    print("   python -c \"")
    print("   import requests")
    print("   r = requests.get('http://localhost:5000/api/admin/notifications')")
    print("   print(r.json())\"")

# Step 6: Cleanup
print("\nCleaning up...")
try:
    conn = get_connection()
    with conn.cursor() as c:
        c.execute("DELETE FROM reports WHERE indicator = %s", (URL,))
    conn.commit()
    print("✅ Done")
except Exception as e:
    print(f"⚠️  {e}")

print("\n" + "=" * 55)
print("Backend terminal should show:")
print("  [spike] Alert queued: http://spike-test-csip2-live.com")
print("Bot terminal should show:")
print("  [spike-poller] ✅ Alert sent: ...")
print("=" * 55)