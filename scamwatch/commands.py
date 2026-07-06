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
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ContextTypes

# ── Load .env ──────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
CSIP2_API_BASE = os.getenv('CSIP2_API_BASE', 'http://127.0.0.1:5000')

# ── Scam type mapping ──────────────────────────────────────
# Maps the bot's display names → new API enum values
SCAM_TYPE_MAP = {
    'Phishing':        'phishing',
    'E-Commerce Scam': 'ecommerce',
    'Impersonation':   'impersonation',
    'Love Scam':       'love',
    'Investment Scam': 'investment',
    'Others':          'other',
}


# ============================================================
#  RATE LIMITING — now backed by DB via /api/bot/rate-limit
#  Falls back to in-memory if the API is unreachable
# ============================================================

def is_rate_limited(user_id: int, username: str = None, first_name: str = None) -> bool:
    """
    Returns True if this Telegram user has exceeded the rate limit.
    Checks the DB via /api/bot/rate-limit — persistent across restarts.
    """
    try:
        # Check current rate limit status
        res = requests.get(
            f'{CSIP2_API_BASE}/api/bot/rate-limit/{user_id}',
            params={'action': 'report'},
            timeout=3
        )
        if res.status_code == 200:
            data = res.json()
            if not data.get('allowed', True):
                return True

        # Record this action
        requests.post(
            f'{CSIP2_API_BASE}/api/bot/rate-limit/{user_id}',
            json={
                'action':     'report',
                'username':   username,
                'first_name': first_name,
            },
            timeout=3
        )
        return False

    except requests.exceptions.RequestException:
        # Fallback: simple in-memory check if API is down
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
    text = re.sub(r'[^\w\s\.,!?\-@:/\(\)]', '', text)
    return text.strip()[:500]


def detect_indicator_type(indicator: str) -> str:
    """Auto-detects url, phone, email, or message."""
    if validate_url(indicator):   return 'url'
    if validate_email(indicator): return 'email'
    if validate_phone(indicator): return 'phone'
    return 'message'


# ============================================================
#  SCANNER — now calls POST /api/scanner/check
#  (previously called GET /check?url=...)
# ============================================================

def check_single_indicator_sync(indicator: str) -> dict:
    """
    Calls the new POST /api/scanner/check endpoint.
    Returns a normalised dict with 'status' key for format_check_result().
    """
    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/api/scanner/check',
            json={'value': indicator},
            timeout=5
        )
        data = response.json()

        # Normalise new API response → old status format
        if data.get('is_scam'):
            scam = data.get('scam') or {}
            return {
                'status':      'blacklist',
                'scam_type':   scam.get('type', 'Unknown'),
                'description': scam.get('description', data.get('message', '')),
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
    elif status == 'whitelist':
        return (
            f"⚠️ *FLAGGED — Proceed With Caution*\n"
            f"└ `{indicator}`\n"
            f"└ Type: {result.get('scam_type', 'Unknown')}\n"
            f"└ {result.get('description', '')}\n"
            f"└ Community flagged — be careful"
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
#  LOG A CHECK TO DB
#  Call this after every check so it shows up in analytics
# ============================================================

def log_check_to_db(telegram_id, indicator, result, source='command',
                    chat_type='private', username=None, first_name=None):
    """Logs a check query to bot_check_logs table via the API."""
    status = result.get('status', 'not_found')
    # Map status to simplified result field
    result_val = 'scam' if status == 'blacklist' else (
                 'flagged' if status == 'whitelist' else 'clean')
    try:
        requests.post(
            f'{CSIP2_API_BASE}/api/bot/log-check',
            json={
                'telegram_id': telegram_id,
                'indicator':   indicator,
                'result':      result_val,
                'source':      source,
                'chat_type':   chat_type,
                'username':    username,
                'first_name':  first_name,
            },
            timeout=3
        )
    except requests.exceptions.RequestException:
        pass  # Non-critical — don't fail the user-facing response


# ============================================================
#  BOT COMMAND HANDLERS
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/start — Welcome message. Also registers the user in the DB."""
    user = update.message.from_user
    # Register user in DB (fire and forget)
    try:
        requests.post(
            f'{CSIP2_API_BASE}/api/bot/user',
            json={
                'telegram_id': user.id,
                'username':    user.username,
                'first_name':  user.first_name,
            },
            timeout=3
        )
    except requests.exceptions.RequestException:
        pass

    await update.message.reply_text(
        "👋 *Welcome to the ScamWatch Bot!*\n\n"
        "Here's what I can do:\n"
        "🔍 /check — Check if a URL/phone/email is a scam\n"
        "📢 /report — Report a new scam\n"
        "📊 /status — View database stats\n"
        "📋 /history — Your past reports\n"
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
        "📋 *Your report history:*\n"
        "`/history` — See your last 5 reports\n\n"
        "📊 *Database stats:*\n"
        "`/status` — Live scam report counts\n\n"
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
    user = update.message.from_user

    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide something to check.\n"
            "Example: `/check http://suspicious-site.com`",
            parse_mode='Markdown'
        )
        return

    indicator = sanitise_text(' '.join(context.args).strip())
    if len(indicator) > 500:
        await update.message.reply_text("⚠️ Input is too long. Please shorten it.")
        return

    await update.message.reply_text(
        f"🔍 Checking `{indicator}`...", parse_mode='Markdown'
    )

    result = check_single_indicator_sync(indicator)
    reply  = format_check_result(indicator, result)
    await update.message.reply_text(reply, parse_mode='Markdown')

    # Log to DB (non-blocking)
    log_check_to_db(
        telegram_id = user.id,
        indicator   = indicator,
        result      = result,
        source      = 'command',
        chat_type   = 'private',
        username    = user.username,
        first_name  = user.first_name,
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/status — Shows live database stats from /api/bot/stats."""
    try:
        response = requests.get(f'{CSIP2_API_BASE}/api/bot/stats', timeout=5)
        data     = response.json()

        await update.message.reply_text(
            f"📊 *ScamWatch Database Stats*\n\n"
            f"🗄️ *Database:*\n"
            f"  • Total reports: {data.get('db_total', 0):,}\n"
            f"  • Verified scams: {data.get('db_verified', 0):,}\n\n"
            f"🤖 *Bot Activity:*\n"
            f"  • Users registered: {data.get('total_users', 0):,}\n"
            f"  • Reports via bot: {data.get('total_reports', 0):,}\n"
            f"  • Checks today: {data.get('checks_today', 0):,}\n"
            f"  • Scam hits today: {data.get('scam_hits_today', 0):,}\n"
            f"  • Active groups: {data.get('active_groups', 0):,}\n\n"
            f"🌐 Website: http://127.0.0.1:5000",
            parse_mode='Markdown'
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )


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


# ============================================================
#  SUBMIT REPORT TO NEW API
#  Called from main.py after user confirms their report.
#  Now POSTs to /api/scams (new backend) instead of /report (old).
# ============================================================

async def submit_report_to_new_api(update, context):
    """
    Submits the report to POST /api/scams and saves to bot_history.
    Called from main.py receive_confirmation().
    """
    user      = update.effective_user
    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', 'Others')   # bot display name
    desc      = context.user_data.get('description', '')
    ind_type  = context.user_data.get('indicator_type', 'message')

    # Map bot scam type → new API enum
    api_type = SCAM_TYPE_MAP.get(scam_type, 'other')

    # Build payload for new /api/scams endpoint
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

    report_id = None
    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/api/scams',
            json=payload,
            timeout=5
        )
        data = response.json()

        if response.status_code in (200, 201):
            report_id = data.get('report_id')
            duplicate = data.get('duplicate', False)

            # Save to bot_history table
            try:
                requests.post(
                    f'{CSIP2_API_BASE}/api/bot/history',
                    json={
                        'telegram_id': user.id,
                        'indicator':   indicator,
                        'scam_type':   scam_type,
                        'report_id':   report_id,
                        'username':    user.username,
                        'first_name':  user.first_name,
                    },
                    timeout=3
                )
            except requests.exceptions.RequestException:
                pass  # Non-critical

            if duplicate:
                msg = (
                    f"✅ *This scam has already been reported!*\n\n"
                    f"Report ID: `{report_id}`\n"
                    f"We've updated the report count. Thank you! 🇸🇬"
                )
            else:
                msg = (
                    f"✅ *Report submitted successfully!*\n\n"
                    f"Report ID: `{report_id}`\n\n"
                    f"Our admin team will review it shortly.\n"
                    f"Thank you for helping keep Singapore safe! 🇸🇬\n\n"
                    f"💡 Use /history to view your past reports."
                )

            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=msg,
                parse_mode='Markdown'
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
    return report_id
