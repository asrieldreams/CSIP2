import requests
import time  # ← add this

API = 'http://127.0.0.1:5000'

reports = [
    { 'indicator_type': 'url',   'indicator': 'http://fake-dbs.com',          'scam_type': 'Phishing',        'description': 'Fake DBS login page stealing credentials.',        'source': 'website' },
    { 'indicator_type': 'url',   'indicator': 'http://myinfo-verify-sg.com',   'scam_type': 'Phishing',        'description': 'Fake Singpass page stealing NRIC and password.',   'source': 'website' },
    { 'indicator_type': 'url',   'indicator': 'http://shopee-lucky-draw.xyz',  'scam_type': 'E-Commerce Scam', 'description': 'Fake Shopee lucky draw collecting card details.',  'source': 'telegram' },
    { 'indicator_type': 'url',   'indicator': 'http://grab-promo-2024.com',    'scam_type': 'E-Commerce Scam', 'description': 'Fake Grab promo collecting personal info.',        'source': 'extension' },
    { 'indicator_type': 'url',   'indicator': 'http://sg-lucky-draw.com',      'scam_type': 'E-Commerce Scam', 'description': 'Suspected scam, not yet confirmed.',               'source': 'website' },
    { 'indicator_type': 'url',   'indicator': 'http://investment-sg.net',      'scam_type': 'Investment Scam', 'description': 'Promised 30% crypto returns.',                    'source': 'telegram' },
    { 'indicator_type': 'phone', 'indicator': '+6581234567',                   'scam_type': 'Impersonation',   'description': 'Caller claimed to be SPF officer.',               'source': 'website' },
    { 'indicator_type': 'phone', 'indicator': '+6598765432',                   'scam_type': 'Love Scam',       'description': 'Person on dating app asked for money.',           'source': 'telegram' },
    { 'indicator_type': 'email', 'indicator': 'support@posb-alert-sg.com',     'scam_type': 'Phishing',        'description': 'Fake POSB email saying account suspended.',       'source': 'website' },
]

print("Seeding reports...")
for i, r in enumerate(reports):
    res = requests.post(f'{API}/report', json=r)
    if res.status_code == 201:
        print(f"✅ Added: {r['indicator']}")
    else:
        print(f"❌ Failed: {r['indicator']} — {res.json()}")

    # ← Wait 13 seconds every 4 reports to avoid rate limit
    if (i + 1) % 4 == 0:
        print("⏳ Waiting 65 seconds for rate limit to reset...")
        time.sleep(65)

print("\nDone!")