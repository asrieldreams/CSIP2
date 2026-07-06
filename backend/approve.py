import requests

API = 'http://127.0.0.1:5000'

# Login
login = requests.post(
    f'{API}/admin/login',
    json={'email': 'admin@scamwatch.sg', 'password': 'Admin@1234'},
    headers={'Content-Type': 'application/json'}
)
print("Login:", login.json())

if login.status_code != 200:
    print("❌ Login failed — stopping.")
    exit()

session = login.cookies

# Get all pending reports
pending = requests.get(
    f'{API}/admin/reports?status=pending',
    cookies=session,
    headers={'Content-Type': 'application/json'}
)
print("Pending response:", pending.status_code)
reports = pending.json().get('reports', [])
print(f"\nFound {len(reports)} pending reports\n")

for r in reports:
    indicator = r['indicator']
    list_type = 'whitelist' if 'sg-lucky-draw' in indicator \
                            or 'investment-sg'  in indicator \
                else 'blacklist'

    res = requests.post(
        f'{API}/admin/review',
        cookies=session,
        json={'report_id': r['id'], 'action': 'approve', 'list_type': list_type},
        headers={'Content-Type': 'application/json'}
    )
    print(f"✅ [{list_type}] {indicator} — {res.json()}")

print("\nDone! All reports approved.")