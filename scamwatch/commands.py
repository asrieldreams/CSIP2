# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — commands.py
#  Owner: Zavier (Security + Bot Commands)
#  Updated: Uses new scamwatch API (/api/scams, /api/scanner/check)
# ============================================================

import re
import time
import os
import requests
from collections import defaultdict
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ContextTypes

# ── Load .env ──────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
CSIP2_API_BASE = os.getenv('CSIP2_API_BASE', 'http://127.0.0.1:5000/api')

# ── Scam type mapping ──────────────────────────────────────
SCAM_TYPE_MAP = {
    'Phishing':        'phishing',
    'E-Commerce Scam': 'ecommerce',
    'Impersonation':   'impersonation',
    'Love Scam':       'love',
    'Investment Scam': 'investment',
    'SMS Scam':        'sms',
    'Job Scam':        'job',
    'Others':          'other',
}

SCAM_TYPE_LABELS = {v: k for k, v in SCAM_TYPE_MAP.items()}


# ============================================================
#  RATE LIMITING — in-memory (max 5 reports per 60 seconds)
# ============================================================

RATE_LIMIT_MAX    = 5
RATE_LIMIT_WINDOW = 60
user_report_times = defaultdict(list)

def is_rate_limited(user_id: int, username: str = None, first_name: str = None) -> bool:
    """Returns True if the user has exceeded the rate limit."""
    now   = time.time()
    times = user_report_times[user_id]
    user_report_times[user_id] = [t for t in times if now - t < RATE_LIMIT_WINDOW]
    if len(user_report_times[user_id]) >= RATE_LIMIT_MAX:
        return True
    user_report_times[user_id].append(now)
    return False


# ============================================================
#  INPUT VALIDATION
# ============================================================

def validate_url(url: str) -> bool:
    pattern = re.compile(
        r'^(https?://)'
        r'([a-zA-Z0-9\-\.]+)'
        r'(\.[a-zA-Z]{2,})'
        r'(/.*)?$'
    )
    return bool(pattern.match(url.strip()))


def validate_phone(phone: str) -> bool:
    cleaned = re.sub(r'[\s\-]', '', phone)
    return bool(re.compile(r'^(\+?\d{8,15})$').match(cleaned))


def validate_email(email: str) -> bool:
    return bool(re.compile(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    ).match(email.strip()))


def sanitise_text(text: str) -> str:
    """Strips HTML tags, removes dangerous chars, limits to 500 chars."""
    text = re.sub(r'<[^>]+>', '', text)
    # Keep + sign for phone numbers
    text = re.sub(r'[^\w\s\.,!?\-@:/\(\)\+]', '', text)
    return text.strip()[:500]


def detect_indicator_type(indicator: str) -> str:
    """Auto-detects url, phone, email, or message."""
    if validate_url(indicator):   return 'url'
    if validate_email(indicator): return 'email'
    if validate_phone(indicator): return 'phone'
    return 'message'


# ============================================================
#  SCANNER — calls POST /api/scanner/check
# ============================================================

def check_single_indicator_sync(indicator: str) -> dict:
    """
    Calls POST /api/scanner/check.
    Returns a normalised dict with 'status' key.
    """
    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/scanner/check',
            json={'value': indicator},
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        data = response.json()

        if data.get('is_scam'):
            match = data.get('match') or {}
            scam  = data.get('scam')  or {}
            scam_type_raw = scam.get('type') or match.get('type', 'unknown')
            return {
                'status':      'blacklist',
                'scam_type':   SCAM_TYPE_LABELS.get(scam_type_raw, scam_type_raw.capitalize()),
                'description': scam.get('description') or scam.get('title', ''),
                'report_id':   scam.get('report_id'),
            }
        else:
            return {
                'status':  'clean',
                'message': data.get('message', 'No reports found.'),
            }

    except requests.exceptions.RequestException:
        return {'status': 'error', 'message': 'Could not reach server.'}


def format_check_result(indicator: str, result: dict) -> str:
    """Formats a check result into a Telegram message."""
    status = result.get('status')

    if status == 'blacklist':
        return (
            f"🚨 *CONFIRMED SCAM — Do Not Proceed*\n"
            f"└ `{indicator}`\n"
            f"└ Type: {result.get('scam_type', 'Unknown')}\n"
            f"└ {result.get('description', '')}\n"
            f"└ ⛔ Block and report to SPF!"
        )
    elif status == 'pending':
        return (
            f"⏳ *Under Admin Review*\n"
            f"└ `{indicator}`\n"
            f"└ This has been reported and is awaiting verification"
        )
    elif status == 'clean':
        return (
            f"✅ *No reports found*\n"
            f"└ `{indicator}`\n"
            f"└ Not in our database — stay cautious"
        )
    elif status == 'error':
        return (
            f"⚠️ *Server error*\n"
            f"└ Could not check `{indicator}`\n"
            f"└ Please try again later"
        )
    else:
        return (
            f"🔎 *Under Review*\n"
            f"└ `{indicator}`\n"
            f"└ Reported but not yet verified"
        )


# ============================================================
#  SUBMIT REPORT — POST /api/scams
# ============================================================

async def submit_report_to_new_api(update, context):
    """
    Submits report to POST /api/scams.
    Called from main.py receive_confirmation().
    """
    user      = update.effective_user
    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', 'Others')
    desc      = context.user_data.get('description', '')
    ind_type  = context.user_data.get('indicator_type', 'message')

    api_type = SCAM_TYPE_MAP.get(scam_type, 'other')

    payload = {
        'type':        api_type,
        'title':       f"{scam_type}: {indicator[:80]}",
        'description': desc or f"Reported via Telegram bot: {indicator}",
        'platform':    'Telegram',
        'severity':    'medium',
    }
    if ind_type == 'url':
        payload['url'] = indicator
    elif ind_type == 'phone':
        payload['phone_number'] = indicator

    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/scams',
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        data      = response.json()
        report_id = data.get('report_id')
        duplicate = data.get('duplicate', False)

        if response.status_code in (200, 201):
            if duplicate:
                msg = (
                    f"✅ *Already reported — thank you!*\n\n"
                    f"📋 Report ID: `{report_id}`\n"
                    f"We've updated the report count. 🇸🇬"
                )
            else:
                msg = (
                    f"✅ *Report submitted successfully!*\n\n"
                    f"📋 Report ID: `{report_id}`\n\n"
                    f"Our admin team will review it shortly.\n"
                    f"Thank you for helping keep Singapore safe! 🇸🇬\n\n"
                    f"💡 Use /history to view your past reports."
                )
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=msg, parse_mode='Markdown'
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"⚠️ Submission failed: {data.get('error', 'Unknown error')}"
            )

    except requests.exceptions.RequestException:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="⚠️ Could not reach the server. Please try again later."
        )

    context.user_data.clear()


# ============================================================
#  BOT COMMAND HANDLERS
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/start — Welcome message."""
    await update.message.reply_text(
        "👋 *Welcome to the ScamWatch Bot!*\n\n"
        "Here's what I can do:\n"
        "🔍 /check — Check if a URL/phone/email is a scam\n"
        "📢 /report — Report a new scam\n"
        "📋 /latest — See the 5 most recent scam reports\n"
        "🔎 /search — Search the scam database\n"
        "📊 /status — View database stats\n"
        "📖 /history — Your past reports\n"
        "ℹ️ /about — Learn about ScamWatch\n"
        "📖 /help — Show all commands\n\n"
        "💡 *Tip:* Forward any suspicious message and I'll scan it automatically!\n\n"
        "Stay safe online! 🛡️",
        parse_mode='Markdown'
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/help — Shows list of commands."""
    await update.message.reply_text(
        "📖 *ScamWatch Bot Commands*\n\n"
        "🔍 *Check a scam indicator:*\n"
        "`/check http://suspicious-site.com`\n"
        "`/check +65 9123 4567`\n"
        "`/check scam@fake-bank.com`\n\n"
        "📢 *Report a scam:*\n"
        "`/report` — Guided step-by-step flow\n\n"
        "📋 *Latest scam reports:*\n"
        "`/latest` — See the 5 most recent confirmed scams\n\n"
        "🔎 *Search the database:*\n"
        "`/search DBS` — Search reports by keyword\n\n"
        "📊 *Database stats:*\n"
        "`/status` — Live scam report counts\n\n"
        "📖 *Your history:*\n"
        "`/history` — See your last 5 reports\n\n"
        "ℹ️ *About:*\n"
        "`/about` — Learn what ScamWatch is\n\n"
        "💡 *Auto scan:* Forward any message with a URL or phone number!\n\n"
        "⚠️ *Limits:* Max 5 reports per minute.",
        parse_mode='Markdown'
    )


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/about — Explains what ScamWatch / CSIP2 is."""
    await update.message.reply_text(
        "🛡️ *About ScamWatch (CSIP2)*\n\n"
        "ScamWatch is Singapore's *Crowdsourced Scam Intelligence Platform*.\n\n"
        "We help protect Singaporeans from online scams by letting the community "
        "report and share scam indicators — suspicious URLs, phone numbers, "
        "emails and messages.\n\n"
        "📌 *How it works:*\n"
        "1️⃣ Community members report suspicious indicators\n"
        "2️⃣ Our admin team reviews and verifies reports\n"
        "3️⃣ Verified scams are flagged in the scanner\n"
        "4️⃣ Our browser extension warns you in real-time\n\n"
        "🤖 *This bot lets you:*\n"
        "• Check if something is a known scam\n"
        "• Report new scams directly from Telegram\n"
        "• Auto-scan forwarded suspicious messages\n\n"
        "🏫 Built by Temasek Polytechnic CDF students — AY24/25",
        parse_mode='Markdown'
    )


async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/check <indicator> — Checks a URL, phone, or email."""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide something to check.\n"
            "Example: `/check http://suspicious-site.com`",
            parse_mode='Markdown'
        )
        return

    # Don't sanitise — preserve + signs in phone numbers
    indicator = ' '.join(context.args).strip()[:500]

    await update.message.reply_text(
        f"🔍 Checking `{indicator}`...", parse_mode='Markdown'
    )

    result = check_single_indicator_sync(indicator)
    reply  = format_check_result(indicator, result)
    await update.message.reply_text(reply, parse_mode='Markdown')


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/status — Shows live database stats from /api/scams/stats."""
    try:
        response = requests.get(f'{CSIP2_API_BASE}/scams/stats', timeout=5)
        data     = response.json()

        await update.message.reply_text(
            f"📊 *ScamWatch Database Stats*\n\n"
            f"✅ Verified Reports: {data.get('verified', 0):,}\n"
            f"🔴 High Severity: {data.get('high_severity', 0):,}\n"
            f"📋 Total Reports: {data.get('total', 0):,}\n"
            f"📅 Reported Today: {data.get('today', 0):,}\n\n"
            f"🌐 Website: http://csip2.com",
            parse_mode='Markdown'
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )


async def latest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/latest — Shows the 5 most recent verified scam reports."""
    try:
        response = requests.get(
            f'{CSIP2_API_BASE}/scams',
            params={'per_page': 5, 'sort': 'date_desc'},
            timeout=5
        )
        data  = response.json()
        scams = data.get('data', [])

        if not scams:
            await update.message.reply_text(
                "📭 No reports in the database yet.\n"
                "Use /report to be the first to report a scam!"
            )
            return

        lines = []
        for i, s in enumerate(scams, 1):
            indicator = s.get('url') or s.get('phone_number') or s.get('title', 'Unknown')
            scam_type = SCAM_TYPE_LABELS.get(s.get('type', ''), s.get('type', 'Unknown').capitalize())
            severity  = s.get('severity', 'medium')
            badge     = '🔴' if severity == 'high' else '🟡' if severity == 'medium' else '🟢'
            type_icon = '🔗' if s.get('url') else '📞' if s.get('phone_number') else '💬'
            date      = (s.get('created_at') or '')[:10] or 'Unknown'

            lines.append(
                f"*{i}.* {type_icon} `{indicator}`\n"
                f"   {badge} {scam_type} · 📅 {date}"
            )

        await update.message.reply_text(
            "📋 *Latest 5 Scam Reports:*\n\n"
            + "\n\n".join(lines) +
            "\n\n🌐 View full feed: http://csip2.com",
            parse_mode='Markdown'
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/search <keyword> — Search the scam database."""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide a keyword.\n"
            "Example: `/search DBS`",
            parse_mode='Markdown'
        )
        return

    keyword = ' '.join(context.args).strip()

    if len(keyword) < 2:
        await update.message.reply_text("⚠️ Keyword too short. Please use at least 2 characters.")
        return

    await update.message.reply_text(
        f"🔍 Searching for *{keyword}*...", parse_mode='Markdown'
    )

    try:
        response = requests.get(
            f'{CSIP2_API_BASE}/scams',
            params={'search': keyword, 'per_page': 5},
            timeout=5
        )
        data  = response.json()
        scams = data.get('data', [])
        total = data.get('total', 0)

        if not scams:
            await update.message.reply_text(
                f"📭 No results found for *{keyword}*.\n\n"
                f"💡 If you think this is a scam, use /report to flag it!",
                parse_mode='Markdown'
            )
            return

        lines = []
        for i, s in enumerate(scams, 1):
            indicator = s.get('url') or s.get('phone_number') or s.get('title', 'Unknown')
            scam_type = SCAM_TYPE_LABELS.get(s.get('type', ''), s.get('type', 'Unknown').capitalize())
            severity  = s.get('severity', 'medium')
            badge     = '🔴' if severity == 'high' else '🟡' if severity == 'medium' else '🟢'
            type_icon = '🔗' if s.get('url') else '📞' if s.get('phone_number') else '💬'
            desc      = s.get('description', '')
            desc_line = f"\n   📝 {desc[:60]}..." if len(desc) > 60 \
                        else f"\n   📝 {desc}" if desc else ''
            lines.append(
                f"*{i}.* {type_icon} `{indicator}`\n"
                f"   {badge} {scam_type}"
                f"{desc_line}"
            )

        more_text = f"\n\n_...and {total - 5} more results_" if total > 5 else ''

        await update.message.reply_text(
            f"🔍 *Search results for \"{keyword}\":*\n"
            f"Found *{total}* report{'s' if total != 1 else ''}\n\n"
            + "\n\n".join(lines)
            + more_text +
            "\n\n💡 Use /report to flag something not in our database!",
            parse_mode='Markdown'
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/report — Starts the guided scam report flow."""
    user_id = update.message.from_user.id

    if is_rate_limited(user_id):
        await update.message.reply_text(
            "⚠️ You're submitting too fast. Please wait a minute before reporting again."
        )
        return

    await update.message.reply_text(
        "📢 *Submit a Scam Report*\n\n"
        "Please send me the scam indicator. This can be:\n"
        "• A URL (e.g. http://scam-site.com)\n"
        "• A phone number (e.g. +65 9123 4567)\n"
        "• An email address\n"
        "• A scam message (paste the text)\n\n"
        "Type /cancel to stop at any time.",
        parse_mode='Markdown'
    )
    return 'WAITING_FOR_INDICATOR'


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/cancel — Cancels any ongoing conversation flow."""
    context.user_data.clear()
    await update.message.reply_text(
        "❌ Cancelled. Type /help to see what I can do."
    )
    return -1


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles unrecognised commands."""
    await update.message.reply_text(
        "❓ I don't recognise that command. Type /help to see what I can do."
    )