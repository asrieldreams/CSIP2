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
    if validate_url(indicator):   return 'url'   # has http://
    if is_valid_url(indicator):   return 'url'   # bare domain like fake-bank.sg
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




def is_valid_url(text: str) -> bool:
    """Check if text looks like a real URL — rejects gibberish, emails, phone numbers."""
    text = text.strip().lower()

    # Reject emails immediately — they have @ and are not URLs
    if '@' in text:
        return False

    # Strip protocol for domain check
    if text.startswith(('http://', 'https://')):
        rest = text.split('://', 1)[1].split('/')[0]
    elif text.startswith('www.'):
        rest = text[4:].split('/')[0]
    else:
        rest = text.split('/')[0]

    # Must have a dot in the domain
    if '.' not in rest:
        return False

    # Split domain into parts
    parts = rest.split('.')
    # TLD must be 2-6 chars (com, sg, edu, co.uk, etc)
    tld = parts[-1].rstrip('/')
    if not (2 <= len(tld) <= 6 and tld.isalpha()):
        return False
    # Domain must have at least 1 char before TLD
    if len(parts[0]) < 1:
        return False
    # No spaces allowed in URL
    if ' ' in text:
        return False
    return True


def is_valid_phone(text: str) -> bool:
    """Check if text looks like a phone number."""
    import re
    digits = re.sub(r'[\s\-\+\(\)]', '', text)
    return digits.isdigit() and 8 <= len(digits) <= 15


def is_valid_email(text: str) -> bool:
    """Check if text looks like an email address."""
    return '@' in text and '.' in text.split('@')[-1] and len(text) > 5


def validate_indicator(indicator: str, ind_type: str) -> tuple[bool, str]:
    """
    Returns (is_valid, error_message).
    Validates all indicator types including rejecting obvious gibberish.
    """
    indicator = indicator.strip()
    if not indicator:
        return False, "Please enter something to report."

    if ind_type == 'url':
        if not is_valid_url(indicator):
            return False, (
                "⚠️ That doesn't look like a valid URL.\n\n"
                "Valid examples:\n"
                "• `http://scam-site.com`\n"
                "• `www.fake-bank.sg`\n"
                "• `bit.ly/scam123`\n\n"
                "For a phone number, use +65 format.\n"
                "For a scam message, paste the full text (20+ characters)."
            )

    elif ind_type == 'phone':
        if not is_valid_phone(indicator):
            return False, (
                "⚠️ That doesn't look like a valid phone number.\n\n"
                "Valid examples:\n"
                "• `+65 9123 4567`\n"
                "• `91234567`"
            )

    elif ind_type == 'email':
        if not is_valid_email(indicator):
            return False, (
                "⚠️ That doesn't look like a valid email.\n\n"
                "Valid example: `scam@fake-bank.com`"
            )

    elif ind_type == 'message':
        # Message type = forwarded scam text — must be meaningful
        # Reject short gibberish like 'gfgfd', 'test', 'abc'
        if len(indicator) < 20:
            # Short input that isn't a URL/phone/email — likely a typo
            return False, (
                "⚠️ That's too short to be a scam report.\n\n"
                "What were you trying to report?\n\n"
                "🔗 *URL/Link* — paste the full link:\n"
                "   Example: `http://scam-site.com`\n\n"
                "📞 *Phone number* — include country code:\n"
                "   Example: `+6591234567`\n\n"
                "📧 *Email* — paste the full address:\n"
                "   Example: `scam@fake-bank.com`\n\n"
                "💬 *Scam message* — paste the full text of the message you received"
            )

    return True, ""

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
        return {'status': 'error', 'message': '⏱️ Request timed out. Backend may be slow or offline.'}
    except requests.exceptions.ConnectionError:
        return {'status': 'error', 'message': '🔌 Backend is offline. Start it with: python backend/app.py'}
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
        fuzzy    = result.get('fuzzy_match', False)
        matched  = result.get('matched_domain', '') or result.get('matched_indicator', '')
        matched  = matched.replace('http://','').replace('https://','').replace('www.','').rstrip('/')
        # Show appropriate domain match note for email vs URL
        if fuzzy and matched:
            if '@' in indicator:
                fuzzy_note = f"\n🌐 *Domain match:* `{matched}` is blacklisted"
            else:
                fuzzy_note = f"\n🔗 *Domain match:* `{matched}` is blacklisted"
        else:
            fuzzy_note = ''
        return (
            f"🚨 *BLACKLISTED — CONFIRMED SCAM*\n"
            f"{DIVIDER}\n"
            f"{'📞' if indicator.replace('+','').replace(' ','').replace('-','').isdigit() else '📧' if '@' in indicator else '🔗'} `{indicator}`{fuzzy_note}\n\n"
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
        # Show appropriate icon based on indicator type
        if indicator.replace('+','').replace(' ','').replace('-','').isdigit():
            ind_icon = '📞'
        elif '@' in indicator:
            ind_icon = '📧'
        else:
            ind_icon = '🔗'
        return (
            f"✅ *Not Found in Database*\n"
            f"{DIVIDER}\n"
            f"{ind_icon} `{indicator}`\n\n"
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

    # Get Telegram user ID for personal history
    user = getattr(update, 'message', None) or getattr(update, 'callback_query', None)
    tg_user_id = None
    if user and hasattr(user, 'from_user') and user.from_user:
        tg_user_id = user.from_user.id
    elif hasattr(update, 'effective_user') and update.effective_user:
        tg_user_id = update.effective_user.id

    payload = {
        'indicator_type':    ind_type,
        'indicator':         indicator,
        'scam_type':         scam_type,
        'description':       desc,
        'source':            'telegram',
        'severity':          context.user_data.get('severity', 'medium'),
        'platform':          context.user_data.get('platform', 'Telegram'),
        'telegram_user_id':  tg_user_id,
    }

    # ── Step 0: Health check FIRST before anything else ─────────
    # If backend is down, stop immediately — don't show false success
    try:
        ping = requests.get(f'{CSIP2_API_BASE}/health', timeout=3)
        if ping.status_code != 200:
            raise Exception(f'Backend returned {ping.status_code}')
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=(
                f"❌ *Backend Offline*\n{DIVIDER}\n\n"
                f"Could not reach the CSIP2 server.\n"
                f"Your report was *not saved*.\n\n"
                f"📌 `{indicator}`\n"
                f"🏷️ Type: {scam_type}\n\n"
                f"Ask admin to start the backend:\n"
                f"`python backend/app.py`\n\n"
                f"Then try 📢 *Report* again."
            ),
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
        context.user_data.clear()
        return

    # ── Step 1: Quick check to get current DB status (fast GET) ────────
    current_status = 'new'
    db_count       = 0
    tier_line      = ''

    try:
        check_result = check_single_indicator_sync(indicator)
        status = check_result.get('status', 'clean')
        db_count = int(check_result.get('report_count', 0))

        if status == 'blacklist':
            tier_line      = '🔴 This indicator is on our *confirmed scam watchlist*.'
            current_status = 'blacklist'
        elif status == 'whitelist':
            tier_line      = '⚠️ This indicator has been *flagged as suspicious* by our community.'
            current_status = 'whitelist'
        elif status == 'pending':
            # Predict tier based on count AFTER this report
            # DO NOT change db_count — count display uses db_count + 1 already
            next_count = db_count + 1
            if next_count >= 3:
                tier_line      = '⚠️ This indicator has been *flagged as suspicious* by our community.'
                current_status = 'whitelist'
            else:
                tier_line      = '🔍 This indicator is currently *under community review*.'
                current_status = 'pending'
    except Exception as e:
        print(f'[check_before_report] {e}')

    # ── Step 2: Show appropriate message immediately ──────────────────
    import threading
    if current_status == 'new' or not tier_line:
        # Brand new report — first person to report this
        msg_text = (
            f"✅ *Report Submitted Successfully!*\n"
            f"{DIVIDER}\n"
            f"📌 *Indicator:* `{indicator}`\n"
            f"🏷️ *Type:* {scam_type}\n\n"
            f"🥇 You're the *first* to report this indicator!\n"
            f"⏳ Our admin team will review it shortly\n"
            f"🇸🇬 Thank you for helping keep Singapore safe!\n\n"
            f"💡 Use 📖 *History* to track your reports"
        )
    else:
        total = db_count + 1  # include current reporter
        count_line = f"\n👥 *{total}* {'person has' if total == 1 else 'people have'} now reported this."

        msg_text = (
            f"✅ *Thank you for your report!*\n"
            f"{DIVIDER}\n"
            f"Your report has been recorded.\n\n"
            f"📌 `{indicator}`\n"
            f"{tier_line}"
            f"{count_line}\n\n"
            f"Every report helps protect the community. 🛡️"
        )

    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=msg_text,
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )

    # ── Step 3: Fire POST /report in background ───────────────────────
    print(f'[report] Sending: type={payload.get("indicator_type")} indicator={payload.get("indicator","")[:40]}')

    def send_to_backend():
        try:
            res = requests.post(
                f'{CSIP2_API_BASE}/report',
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            if res.status_code not in (200, 201):
                print(f'[report:bg] FAILED {res.status_code}: {res.text[:300]}')
            else:
                print(f'[report:bg] OK {res.status_code}: {res.text[:100]}')
        except Exception as e:
            print(f'[report:bg] EXCEPTION: {e}')

    threading.Thread(target=send_to_backend, daemon=True).start()

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