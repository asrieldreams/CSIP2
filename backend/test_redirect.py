# ============================================================
#  Test: URL redirect following in /check
#  python backend/test_redirect.py
# ============================================================
import sys, requests
sys.path.insert(0, 'backend')

API = 'http://localhost:5000'

def check(url):
    r = requests.get(f'{API}/check', params={'url': url}, timeout=15)
    return r.json()

def add_blacklist(url):
    from db import get_connection
    conn = get_connection()
    with conn.cursor() as c:
        c.execute(
            "INSERT INTO reports "
            "(indicator_type,indicator,scam_type,description,"
            "source,status,list_type,severity,report_count) "
            "VALUES (%s,%s,'Phishing','Redirect test','test','approved','blacklist','high',5)",
            ('url', url)
        )
    conn.commit()
    conn.close()
    print(f"✅ Blacklisted: {url}")

def cleanup(url):
    from db import get_connection
    conn = get_connection()
    with conn.cursor() as c:
        c.execute("DELETE FROM reports WHERE indicator=%s", (url,))
    conn.commit()
    conn.close()

print("=" * 55)
print("CSIP2 URL Redirect Check Test")
print("=" * 55)

# ── Test 1: Direct blacklist (no redirect needed) ────────────
print("\n--- Test 1: Direct blacklist check ---")
add_blacklist('http://direct-scam-test.com')
result = check('http://direct-scam-test.com')
print(f"Status:   {result.get('status')}")
print(f"Redirect: {result.get('redirect', False)}")
if result.get('status') == 'blacklist':
    print("✅ Direct blacklist works")
else:
    print(f"❌ Unexpected: {result}")
cleanup('http://direct-scam-test.com')

# ── Test 2: Real redirect via httpbin ────────────────────────
print("\n--- Test 2: URL that redirects to blacklisted site ---")
# httpbin.org/redirect-to redirects to any URL you specify
# We blacklist the DESTINATION, check the SHORTENER
destination = 'http://fake-redirect-destination.com'
add_blacklist(destination)

# httpbin redirects to the destination
shortener = f'https://httpbin.org/redirect-to?url={destination}'
print(f"Checking shortener: {shortener[:60]}...")
print(f"(redirects to:      {destination})")
print("Following redirect (may take 3-5s)...")

result2 = check(shortener)
print(f"\nStatus:    {result2.get('status')}")
print(f"Redirect:  {result2.get('redirect', False)}")
print(f"Final URL: {result2.get('final_url', 'N/A')}")

if result2.get('status') == 'blacklist' and result2.get('redirect'):
    print("✅ Redirect detection WORKS!")
    print(f"   Shortener was clean but redirects to blacklisted site")
elif result2.get('status') == 'clean':
    print("❌ Redirect NOT detected — check backend logs for [check:redir]")
else:
    print(f"Result: {result2}")

cleanup(destination)

# ── Test 3: Clean URL (no redirect) ─────────────────────────
print("\n--- Test 3: Clean URL with no redirect ---")
result3 = check('http://google.com')
print(f"Status: {result3.get('status')}")
print(f"Redirect: {result3.get('redirect', False)}")
if result3.get('status') == 'clean':
    print("✅ Clean URLs still return clean")
else:
    print(f"Result: {result3}")

print("\n" + "=" * 55)
print("Watch backend terminal for:")
print("  [check:redir] URL → final_url")
print("=" * 55)