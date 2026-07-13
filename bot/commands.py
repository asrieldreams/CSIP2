# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — commands.py
#  Owner: Zavier (Security + Bot Commands)
# ============================================================

import re
import time
import os
import requests
from collections import defaultdict
from dotenv import load_dotenv
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import ContextTypes

# ── Load .env ──────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
CSIP2_API_BASE = os.getenv('CSIP2_API_BASE', 'http://127.0.0.1:5000')

# ── Rate Limiting ──────────────────────────────────────────
RATE_LIMIT_MAX    = 5
RATE_LIMIT_WINDOW = 60
user_report_times = defaultdict(list)

def is_rate_limited(user_id: int, username: str = None, first_name: str = None) -> bool:
    now   = time.time()
    times = user_report_times[user_id]
    user_report_times[user_id] = [t for t in times if now - t < RATE_LIMIT_WINDOW]
    if len(user_report_times[user_id]) >= RATE_LIMIT_MAX:
        return True
    user_report_times[user_id].append(now)
    return False


# ── Input Validation ───────────────────────────────────────

def validate_url(url: str) -> bool:
    return bool(re.compile(
        r'^(https?://)([a-zA-Z0-9\-\.]+)(\.[a-zA-Z]{2,})(/.*)?$'
    ).match(url.strip()))

def validate_phone(phone: str) -> bool:
    cleaned = re.sub(r'[\s\-]', '', phone)
    return bool(re.compile(r'^(\+?\d{8,15})$').match(cleaned))

def validate_email(email: str) -> bool:
    return bool(re.compile(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    ).match(email.strip()))

def sanitise_text(text: str) -> str:
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[^\w\s\.,!?\-@:/\(\)\+]', '', text)
    return text.strip()[:500]

def detect_indicator_type(indicator: str) -> str:
    if validate_url(indicator):   return 'url'
    if validate_email(indicator): return 'email'
    if validate_phone(indicator): return 'phone'
    return 'message'


# ── Persistent menu keyboard ───────────────────────────────
def get_main_menu():
    keyboard = [
        [KeyboardButton("🔍 Check"),   KeyboardButton("📢 Report")],
        [KeyboardButton("📋 Latest"),  KeyboardButton("🔎 Search")],
        [KeyboardButton("📊 Status"),  KeyboardButton("📖 History")],
        [KeyboardButton("ℹ️ About"),   KeyboardButton("❓ Help")],
    ]
    return ReplyKeyboardMarkup(
        keyboard, resize_keyboard=True, one_time_keyboard=False
    )


# ── Divider helper ─────────────────────────────────────────
DIVIDER = "━━━━━━━━━━━━━━━━━━━━━━"


# ── API Helpers ────────────────────────────────────────────

def normalize_url(indicator: str) -> str:
    """Add http:// if indicator looks like a URL without protocol."""
    indicator = indicator.strip()
    if indicator.startswith('http://') or indicator.startswith('https://'):
        return indicator
    # Common shortlink/social patterns
    url_patterns = [
        'www.', 'bit.ly/', 't.me/', 'wa.me/', 'tinyurl.com/',
        'goo.gl/', 'tiny.cc/', 'ow.ly/', 'rb.gy/', 'cutt.ly/'
    ]
    for pattern in url_patterns:
        if indicator.lower().startswith(pattern):
            return 'http://' + indicator
    # If it has a TLD-like pattern (has dot, no spaces, not email)
    if '.' in indicator and ' ' not in indicator and '@' not in indicator:
        if not any(c in indicator for c in ['(', ')', '?', '!']):
            return 'http://' + indicator
    return indicator


def check_single_indicator_sync(indicator: str) -> dict:
    """Calls GET /check. Auto-normalizes URLs without http://."""
    indicator = normalize_url(indicator)
    try:
        response = requests.get(
            f'{CSIP2_API_BASE}/check',
            params={'url': indicator},
            timeout=6      # 6 second hard timeout
        )
        if response.status_code == 200:
            return response.json()
        return {'status': 'error', 'message': f'Server returned {response.status_code}'}
    except requests.exceptions.Timeout:
        return {'status': 'error', 'message': 'Request timed out. Is the backend running?'}
    except requests.exceptions.ConnectionError:
        return {'status': 'error', 'message': 'Could not connect to backend. Start with: python backend/app.py'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


def format_check_result(indicator: str, result: dict) -> str:
    status = result.get('status')
    scam_type = result.get('scam_type', 'Unknown')
    description = result.get('description', '')

    if status == 'blacklist':
        count    = result.get('report_count', 1)
        severity = (result.get('severity') or 'high').capitalize()
        sev_icon = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '🔴')
        return (
            f"🚨 *BLACKLISTED — CONFIRMED SCAM*\n"
            f"{DIVIDER}\n"
            f"🔗 `{indicator}`\n\n"
            f"📌 *Scam Type:* {scam_type}\n"
            f"{sev_icon} *Severity:* {severity}\n"
            f"📝 *Details:* {description if description else 'No details available'}\n"
            f"👥 *Reported by:* {count} {'person' if count == 1 else 'people'}\n\n"
            f"⛔ *DO NOT* visit this site or call this number\n"
            f"🚔 Report to SPF at *999* or *scamalert.sg*"
        )
    elif status == 'whitelist':
        count    = result.get('report_count', 1)
        severity = (result.get('severity') or 'medium').capitalize()
        sev_icon = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '🟡')
        return (
            f"⚠️ *SUSPECTED — Community Flagged*\n"
            f"{DIVIDER}\n"
            f"🔗 `{indicator}`\n\n"
            f"📌 *Scam Type:* {scam_type}\n"
            f"{sev_icon} *Severity:* {severity}\n"
            f"📝 *Details:* {description if description else 'No details available'}\n"
            f"👥 *Reported by:* {count} {'person' if count == 1 else 'people'}\n\n"
            f"⚠️ Exercise caution — not yet fully confirmed"
        )

    elif status == 'error':
        msg = result.get('message', 'Could not reach the backend')
        return (
            f"❌ *Check Failed*\n"
            f"{DIVIDER}\n"
            f"🔗 `{indicator}`\n\n"
            f"{msg}\n\n"
            f"Make sure the backend is running:\n"
            f"`python backend/app.py`"
        )

    else:
        # clean — not in database
        return (
            f"✅ *Not Found in Database*\n"
            f"{DIVIDER}\n"
            f"🔗 `{indicator}`\n\n"
            f"No match found in the CSIP2 scam database.\n\n"
            f"💡 Always stay cautious online. If you think this\n"
            f"is a scam, use 📢 *Report* to submit it."
        )


# ── Submit Report ──────────────────────────────────────────

async def submit_report_to_new_api(update, context):
    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', 'Others')
    desc      = context.user_data.get('description', '')
    ind_type  = context.user_data.get('indicator_type', 'message')

    payload = {
        'indicator_type': ind_type,
        'indicator':      indicator,
        'scam_type':      scam_type,
        'description':    desc,
        'source':         'telegram',
        'severity':       context.user_data.get('severity', 'medium'),
        'platform':       context.user_data.get('platform', 'Telegram'),
    }

    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/report',
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        data = response.json()

        if response.status_code == 201:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"✅ *Report Submitted Successfully!*\n"
                     f"{DIVIDER}\n"
                     f"📌 *Indicator:* `{indicator}`\n"
                     f"🏷️ *Type:* {scam_type}\n\n"
                     f"⏳ Our admin team will review it shortly\n"
                     f"🇸🇬 Thank you for helping keep Singapore safe!\n\n"
                     f"💡 Use 📖 *History* to track your reports",
                parse_mode='Markdown',
                reply_markup=get_main_menu()
            )
        elif data.get('duplicate'):
            dup_status     = data.get('status', 'pending')
            count          = int(data.get('report_count', 1))
            promotion_tier = data.get('promotion_tier', '')

            # Status label based on current tier — no internal logic exposed
            if promotion_tier == 'blacklist' or (dup_status == 'approved'):
                status_line = '🔴 This indicator is on our *confirmed scam watchlist*.'
            elif promotion_tier == 'whitelist':
                status_line = '⚠️ This indicator has been *flagged as suspicious* by our community.'
            else:
                status_line = '🔍 This indicator is currently *under community review*.'

            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"✅ *Thank you for your report!*\n"
                     f"{DIVIDER}\n"
                     f"Your report has been recorded.\n\n"
                     f"📌 `{indicator}`\n"
                     f"{status_line}\n"
                     f"👥 *{count}* {'person has' if count==1 else 'people have'} reported this.\n\n"
                     f"Every report helps protect the community. 🛡️",
                parse_mode='Markdown',
                reply_markup=get_main_menu()
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ *Submission Failed*\n"
                     f"{DIVIDER}\n"
                     f"{data.get('error', 'Please try again later.')}",
                parse_mode='Markdown',
                reply_markup=get_main_menu()
            )

    except requests.exceptions.RequestException:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ *Connection Error*\n"
                 f"{DIVIDER}\n"
                 f"Could not reach the server\n"
                 f"Please try again later",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )

    context.user_data.clear()


# ── Bot Command Handlers ───────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.message.from_user.first_name or 'there'
    await update.message.reply_text(
        f"👋 *Hello, {name}!*\n"
        f"{DIVIDER}\n"
        f"Welcome to *CSIP2 Scam Intelligence Bot* 🛡️\n\n"
        f"🔍 *Check* — Verify a URL, phone or email\n"
        f"📢 *Report* — Flag a new scam\n"
        f"📋 *Latest* — Browse recent scam reports\n"
        f"🔎 *Search* — Find specific scams\n"
        f"📊 *Status* — Live database stats\n"
        f"📖 *History* — Your past reports\n\n"
        f"💡 *Pro tip:* Just forward any suspicious\n"
        f"message and I'll scan it automatically!\n"
        f"{DIVIDER}\n"
        f"_Built by TP CDF students — AY24/25_ 🏫",
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"📖 *CSIP2 Bot — Help Guide*\n"
        f"{DIVIDER}\n\n"
        f"🔍 *Check a scam indicator:*\n"
        f"`/check http://suspicious-site.com`\n"
        f"`/check +65 9123 4567`\n"
        f"`/check scam@fake-bank.com`\n\n"
        f"📢 *Report a scam:*\n"
        f"`/report` — Start guided report flow\n\n"
        f"📋 *Browse reports:*\n"
        f"`/latest` — 5 most recent scams\n"
        f"`/search DBS` — Search by keyword\n\n"
        f"📊 *Stats & Info:*\n"
        f"`/status` — Live database counts\n"
        f"`/history` — Your past submissions\n"
        f"`/about` — About this platform\n\n"
        f"{DIVIDER}\n"
        f"💡 Forward any suspicious message —\n"
        f"I'll auto-scan all URLs and phone numbers!\n\n"
        f"⚠️ Max *5 reports per minute* per user",
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"🛡️ *About CSIP2*\n"
        f"{DIVIDER}\n\n"
        f"*Crowdsourced Scam Intelligence Platform 2*\n\n"
        f"We protect Singaporeans from online scams\n"
        f"through community-powered intelligence.\n\n"
        f"📌 *How it works:*\n"
        f"1️⃣ You report suspicious indicators\n"
        f"2️⃣ Admins verify and classify them\n"
        f"3️⃣ *Blacklist* = confirmed scam ⛔\n"
        f"4️⃣ *Whitelist* = suspected scam ⚠️\n"
        f"5️⃣ Browser extension warns users 🔌\n\n"
        f"🤖 *This bot:*\n"
        f"• Real-time scam indicator checking\n"
        f"• Guided scam reporting\n"
        f"• Auto-scan forwarded messages\n"
        f"• Group chat scam detection\n\n"
        f"{DIVIDER}\n"
        f"🏫 Temasek Polytechnic CDF — AY24/25\n"
        f"🌐 csip2.com",
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )


async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            f"🔍 *Check a Scam Indicator*\n"
            f"{DIVIDER}\n\n"
            f"Send what you want to check:\n\n"
            f"🔗 URL:\n`/check http://suspicious-site.com`\n\n"
            f"📞 Phone:\n`/check +65 9123 4567`\n\n"
            f"📧 Email:\n`/check scam@fake-bank.com`",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
        return

    indicator = normalize_url(' '.join(context.args).strip()[:500])

    await update.message.reply_text(
        f"🔍 Checking `{indicator}`...",
        parse_mode='Markdown'
    )

    result = check_single_indicator_sync(indicator)
    await update.message.reply_text(
        format_check_result(indicator, result),
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        response = requests.get(f'{CSIP2_API_BASE}/reports', timeout=5)
        data     = response.json()
        reports  = data.get('reports', [])

        blacklisted = sum(1 for r in reports if r.get('list_type') == 'blacklist')
        whitelisted = sum(1 for r in reports if r.get('list_type') == 'whitelist')
        total       = len(reports)

        scam_counts = {}
        for r in reports:
            t = r.get('scam_type', 'Others')
            scam_counts[t] = scam_counts.get(t, 0) + 1

        breakdown = "\n".join([
            f"   {'🔴' if i == 0 else '🟠' if i == 1 else '🟡'} {k}: *{v}*"
            for i, (k, v) in enumerate(
                sorted(scam_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            )
        ])

        await update.message.reply_text(
            f"📊 *CSIP2 — Live Database Stats*\n"
            f"{DIVIDER}\n\n"
            f"🔴 Blacklisted: *{blacklisted}*\n"
            f"🟡 Whitelisted: *{whitelisted}*\n"
            f"📋 Total Reports: *{total}*\n\n"
            f"🏆 *Top Scam Types:*\n"
            f"{breakdown if breakdown else '   No data yet'}\n\n"
            f"{DIVIDER}\n"
            f"🌐 csip2.com",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            f"❌ *Connection Error*\n"
            f"{DIVIDER}\n"
            f"Could not reach the server\n"
            f"Please try again later",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )


async def latest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        response = requests.get(f'{CSIP2_API_BASE}/reports', timeout=5)
        data     = response.json()
        reports  = data.get('reports', [])

        if not reports:
            await update.message.reply_text(
                f"📭 *No Reports Yet*\n"
                f"{DIVIDER}\n"
                f"Be the first to report a scam!\n"
                f"Use 📢 *Report* to get started",
                parse_mode='Markdown',
                reply_markup=get_main_menu()
            )
            return

        latest = reports[:5]
        lines  = []
        for i, r in enumerate(latest, 1):
            list_type = r.get('list_type')
            badge     = '🔴' if list_type == 'blacklist' else \
                        '🟡' if list_type == 'whitelist' else '⏳'
            type_icon = '🔗' if r['indicator_type'] == 'url'   else \
                        '📞' if r['indicator_type'] == 'phone' else \
                        '📧' if r['indicator_type'] == 'email' else '💬'
            date = r['submitted_at'][:10]
            lines.append(
                f"{badge} *{r['scam_type']}*\n"
                f"   {type_icon} `{r['indicator']}`\n"
                f"   📅 {date}"
            )

        await update.message.reply_text(
            f"📋 *Latest 5 Scam Reports*\n"
            f"{DIVIDER}\n\n"
            + f"\n\n".join(lines) +
            f"\n\n{DIVIDER}\n"
            f"🌐 Full feed at csip2.com",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            f"❌ *Connection Error*\n{DIVIDER}\nPlease try again later",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            f"🔎 *Search Scam Database*\n"
            f"{DIVIDER}\n\n"
            f"Send a keyword to search:\n\n"
            f"`/search DBS`\n"
            f"`/search phishing`\n"
            f"`/search shopee`\n"
            f"`/search +65`",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
        return

    keyword = ' '.join(context.args).strip()
    if len(keyword) < 2:
        await update.message.reply_text(
            "⚠️ Keyword too short. Please use at least 2 characters.",
            reply_markup=get_main_menu()
        )
        return

    await update.message.reply_text(
        f"🔎 Searching for *{keyword}*...", parse_mode='Markdown'
    )

    try:
        response = requests.get(
            f'{CSIP2_API_BASE}/reports',
            params={'keyword': keyword},
            timeout=5
        )
        data    = response.json()
        reports = data.get('reports', [])
        total   = data.get('total', len(reports))

        if not reports:
            await update.message.reply_text(
                f"📭 *No Results Found*\n"
                f"{DIVIDER}\n\n"
                f"No reports match *\"{keyword}\"*\n\n"
                f"💡 Think it's a scam? Use 📢 *Report* to flag it!",
                parse_mode='Markdown',
                reply_markup=get_main_menu()
            )
            return

        shown = reports[:5]
        lines = []
        for i, r in enumerate(shown, 1):
            list_type = r.get('list_type')
            badge     = '🔴' if list_type == 'blacklist' else \
                        '🟡' if list_type == 'whitelist' else '⏳'
            type_icon = '🔗' if r['indicator_type'] == 'url'   else \
                        '📞' if r['indicator_type'] == 'phone' else \
                        '📧' if r['indicator_type'] == 'email' else '💬'
            desc      = r.get('description', '')
            desc_line = f"\n   📝 _{desc[:55]}..._" if len(desc) > 55 \
                        else f"\n   📝 _{desc}_" if desc else ''
            lines.append(
                f"{badge} *{r['scam_type']}*\n"
                f"   {type_icon} `{r['indicator']}`"
                f"{desc_line}"
            )

        more_text = f"\n\n_+{total - 5} more results not shown_" if total > 5 else ''

        await update.message.reply_text(
            f"🔎 *Search: \"{keyword}\"*\n"
            f"{DIVIDER}\n"
            f"Found *{total}* report{'s' if total != 1 else ''}\n\n"
            + "\n\n".join(lines)
            + more_text +
            f"\n\n{DIVIDER}\n"
            f"💡 Use 📢 *Report* to flag something new",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            f"❌ *Connection Error*\n{DIVIDER}\nPlease try again later",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if is_rate_limited(user_id):
        await update.message.reply_text(
            f"⏱️ *Rate Limit Reached*\n"
            f"{DIVIDER}\n"
            f"Max *{RATE_LIMIT_MAX} reports per minute*\n"
            f"Please wait a moment and try again",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
        return

    await update.message.reply_text(
        f"📢 *Submit a Scam Report*\n"
        f"{DIVIDER}\n"
        f"📍 *Step 1 of 6* — Enter Indicator\n\n"
        f"Send the suspicious indicator:\n\n"
        f"🔗 URL: `http://scam-site.com`\n"
        f"📞 Phone: `+65 9123 4567`\n"
        f"📧 Email: `scam@fake-bank.com`\n"
        f"💬 Message: _paste text_\n\n"
        f"_Type /cancel to stop anytime_",
        parse_mode='Markdown'
    )
    return 'WAITING_FOR_INDICATOR'


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text(
        f"❌ *Report Cancelled*\n"
        f"{DIVIDER}\n"
        f"No report was submitted\n"
        f"Tap any button below to continue",
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )
    return -1


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"❓ *Unknown Command*\n"
        f"{DIVIDER}\n"
        f"I don't recognise that command\n"
        f"Tap ❓ *Help* to see what I can do",
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )