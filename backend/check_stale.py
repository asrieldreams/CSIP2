# ============================================================
#  CSIP2 — Stale URL Checker
#  python backend/check_stale.py
#
#  Checks all blacklisted URLs:
#  - If unreachable AND no new reports in 90 days
#    → auto-downgrade to SUSPECTED
#    → alert admin via console (add bot notification if needed)
#
#  Run manually or via cron:
#  0 3 * * 0 python /path/to/backend/check_stale.py  (every Sunday 3am)
# ============================================================

import sys, os, requests, threading
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(__file__))
from db import get_connection

# ── Config ────────────────────────────────────────────────
STALE_DAYS       = 90    # days since last report before eligible for downgrade
CHECK_TIMEOUT    = 5     # seconds per URL reachability check
MAX_THREADS      = 10    # concurrent checks
DOWNGRADE_LABEL  = 'whitelist'  # downgrade to suspected

# ── Helpers ───────────────────────────────────────────────
def is_url(indicator):
    return indicator.startswith('http://') or indicator.startswith('https://')

def check_reachable(url):
    """Returns True if URL responds with any HTTP response (even 4xx)."""
    try:
        r = requests.head(url, timeout=CHECK_TIMEOUT, allow_redirects=True,
                          headers={'User-Agent': 'Mozilla/5.0'})
        return True  # Any response = server is alive
    except requests.exceptions.SSLError:
        return True  # SSL errors mean server exists
    except requests.exceptions.TooManyRedirects:
        return True  # Redirect loop = server exists
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout):
        # Try GET as fallback (some servers reject HEAD)
        try:
            r = requests.get(url, timeout=CHECK_TIMEOUT, allow_redirects=True,
                             headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
            r.close()
            return True
        except Exception:
            return False
    except Exception:
        return False

def log_action(conn, report_id, indicator, action, detail):
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO audit_log
                    (admin_name, action, target_type, target_id, target_ref, detail)
                VALUES ('System', %s, 'report', %s, %s, %s)
            """, (action, report_id, f"SS-{str(report_id).zfill(5)}", detail))
        conn.commit()
    except Exception as e:
        print(f"  [audit] {e}")

# ── Main ──────────────────────────────────────────────────
def run():
    print(f"\n{'='*55}")
    print(f"CSIP2 Stale URL Checker — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*55}")
    print(f"Config: stale after {STALE_DAYS} days, timeout {CHECK_TIMEOUT}s\n")

    conn     = get_connection()
    cutoff   = datetime.utcnow() - timedelta(days=STALE_DAYS)
    now      = datetime.utcnow()

    # Fetch all blacklisted URL indicators
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT id, indicator, indicator_type,
                   scam_type, submitted_at,
                   COALESCE(last_reported_at, submitted_at) as last_reported_at,
                   COALESCE(report_count, 1) as report_count,
                   admin_locked
            FROM reports
            WHERE status = 'approved'
              AND list_type = 'blacklist'
              AND indicator_type = 'url'
            ORDER BY submitted_at ASC
        """)
        blacklisted = cursor.fetchall()

    print(f"Found {len(blacklisted)} blacklisted URLs to check\n")
    if not blacklisted:
        print("Nothing to check. Exiting.")
        return

    # ── Check reachability concurrently ────────────────────
    results = {}
    lock     = threading.Lock()

    def worker(row):
        url       = row['indicator']
        reachable = check_reachable(url)
        with lock:
            results[row['id']] = reachable
        status = "✅ ALIVE" if reachable else "💀 DOWN"
        print(f"  {status}  {url[:55]}")

    threads = []
    for row in blacklisted:
        t = threading.Thread(target=worker, args=(row,))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_THREADS:
            for t in threads: t.join()
            threads = []
    for t in threads: t.join()

    # ── Process results ────────────────────────────────────
    print(f"\n{'─'*55}")
    print("Processing results...\n")

    downgraded     = []
    still_active   = []
    recently_reported = []

    for row in blacklisted:
        report_id   = row['id']
        indicator   = row['indicator']
        reachable   = results.get(report_id, True)
        last_report = row['last_reported_at']
        locked      = row.get('admin_locked', 0)

        # Convert last_report to datetime if needed
        if isinstance(last_report, str):
            try:
                last_report = datetime.strptime(last_report, '%Y-%m-%d %H:%M:%S')
            except Exception:
                last_report = now

        is_stale = (last_report < cutoff)

        # Update reachability in DB
        reach_status = 'reachable' if reachable else 'unreachable'
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE reports
                SET reachability = %s, last_checked_at = %s
                WHERE id = %s
            """, (reach_status, now, report_id))
        conn.commit()

        # ── Decision logic ─────────────────────────────────
        if locked:
            # Admin-locked → immune, never auto-downgrade
            print(f"  🔒 LOCKED    {indicator[:50]} — skipped (admin-locked)")
            still_active.append(indicator)
            continue

        if not reachable and is_stale:
            # Unreachable + no recent reports → downgrade
            days_since = (now - last_report).days
            print(f"  ⬇️  DOWNGRADE {indicator[:50]}")
            print(f"             Last report: {days_since} days ago | Status: DOWN")

            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE reports
                    SET status = 'approved', list_type = 'whitelist'
                    WHERE id = %s
                """, (report_id,))
            conn.commit()

            log_action(
                conn, report_id, indicator,
                'Auto-Downgraded',
                f"URL unreachable + no reports for {days_since} days → suspected"
            )
            downgraded.append({'id': report_id, 'url': indicator, 'days': days_since})

        elif not reachable and not is_stale:
            # Down but recently reported → keep, flag for monitoring
            days_since = (now - last_report).days
            print(f"  ⏳ MONITOR   {indicator[:50]}")
            print(f"             Down but reported {days_since} days ago — keeping")
            recently_reported.append(indicator)

        else:
            # Reachable — keep blacklisted
            still_active.append(indicator)

    # ── Summary ────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"SUMMARY")
    print(f"{'='*55}")
    print(f"  Total checked:    {len(blacklisted)}")
    print(f"  Still active:     {len(still_active)}")
    print(f"  Recently reported (down): {len(recently_reported)}")
    print(f"  Auto-downgraded:  {len(downgraded)}")

    if downgraded:
        print(f"\n⬇️  Downgraded to SUSPECTED:")
        for d in downgraded:
            print(f"  • SS-{str(d['id']).zfill(5)} — {d['url']} ({d['days']} days inactive)")
        print(f"\n💡 Admin: review these in the Suspected tab of the dashboard")
        print(f"   If they're truly gone, reject them. If they come back, re-confirm.")
    else:
        print(f"\n✅ No stale URLs found — all blacklisted URLs are active")

    print(f"\nCompleted at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    conn.close()

if __name__ == '__main__':
    run()