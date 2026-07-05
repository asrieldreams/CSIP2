import requests

API = 'http://127.0.0.1:5000'

# Login with explicit headers
login = requests.post(
    f'{API}/admin/login',
    json={'email': 'admin@csip2.com', 'password': 'Admin@1234'},
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
print("Pending response:", pending.status_code, pending.json())
reports = pending.json().get('reports', [])
print(f"\nFound {len(reports)} pending reports\n")

for r in reports:
    indicator = r['indicator']
    list_type = 'whitelist' if 'sg-lucky-draw' in indicator or 'investment-sg' in indicator else 'blacklist'

    res = requests.post(
        f'{API}/admin/review',
        cookies=session,
        json={'report_id': r['id'], 'action': 'approve', 'list_type': list_type},
        headers={'Content-Type': 'application/json'}
    )
    print(f"✅ [{list_type}] {indicator} — {res.json()}")

print("\nDone!")

async def latest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/latest — Shows the 5 most recent approved scam reports."""
    try:
        response = requests.get(f'{CSIP2_API_BASE}/reports', timeout=5)
        data     = response.json()
        reports  = data.get('reports', [])

        if not reports:
            await update.message.reply_text(
                "📭 No reports in the database yet.\n"
                "Use /report to be the first to report a scam!"
            )
            return

        # Take the 5 most recent
        latest = reports[:5]

        lines = []
        for i, r in enumerate(latest, 1):
            list_type = r.get('list_type')
            badge = '🔴' if list_type == 'blacklist' else '🟡' if list_type == 'whitelist' else '⏳'

            type_icon = '🔗' if r['indicator_type'] == 'url' else \
                        '📞' if r['indicator_type'] == 'phone' else \
                        '📧' if r['indicator_type'] == 'email' else '💬'

            lines.append(
                f"*{i}.* {type_icon} `{r['indicator']}`\n"
                f"   {badge} {r['scam_type']} · 📅 {r['submitted_at'][:10]}"
            )

        await update.message.reply_text(
            "📋 *Latest 5 Scam Reports:*\n\n"
            + "\n\n".join(lines) +
            "\n\n🌐 View full feed: http://csip2.com/feed",
            parse_mode='Markdown'
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )