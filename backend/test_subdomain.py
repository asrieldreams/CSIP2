# ============================================================
#  Run this to verify subdomain matching with YOUR real DB
#  python backend/test_subdomain.py
# ============================================================
import sys, os, requests
sys.path.insert(0, os.path.dirname(__file__))

API = 'http://localhost:5000'

def check(url):
    try:
        r = requests.get(f'{API}/check', params={'url': url}, timeout=5)
        d = r.json()
        return d.get('status', 'error')
    except Exception as e:
        return f'error: {e}'

print("\n=== Subdomain Direction Test (Live DB) ===\n")

# Test 1: if phishing.legitimate-bank.com was reported
# parent should be CLEAN
tests = [
    # (url_to_check, expected_behavior)
    ("http://legitimate-bank.com",            "should be CLEAN (parent of any subdomain scam)"),
    ("http://phishing.legitimate-bank.com",   "would be BLACKLISTED if reported"),
    ("http://fake-dbs.com",                   "BLACKLISTED if you reported this"),
    ("http://app.fake-dbs.com",               "BLACKLISTED (child of fake-dbs.com)"),
    ("http://fake-dbs.com.evil.com",          "CLEAN (evil.com owns this, not fake-dbs.com)"),
    ("http://notfake-dbs.com",                "CLEAN (different domain entirely)"),
]

for url, note in tests:
    result = check(url)
    icon   = '🚨' if result == 'blacklist' else '⚠️' if result == 'whitelist' else '✅' if result == 'clean' else '⏳'
    print(f"{icon} {result.upper():12} {url}")
    print(f"   ↳ {note}\n")

print("="*45)
print("✅ If CLEAN for parent domains and BLACKLISTED only for reported")
print("   subdomains/children → your logic is correct!")