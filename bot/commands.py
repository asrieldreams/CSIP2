# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — commands.py
#  Owner: Zavier (Security + Bot Commands)
# ============================================================

import re
import time
from collections import defaultdict
from telegram import Update
from telegram.ext import ContextTypes

# ── Rate Limiting ──────────────────────────────────────────
# Tracks how many times each Telegram user has submitted a report
# Max 5 reports per 60 seconds per user
RATE_LIMIT_MAX    = 5
RATE_LIMIT_WINDOW = 60   # seconds

# Dictionary: { user_id: [timestamp1, timestamp2, ...] }
user_report_times = defaultdict(list)

def is_rate_limited(user_id: int) -> bool:
    """
    Returns True if the user has exceeded the rate limit.
    Cleans up old timestamps outside the time window.
    """
    now   = time.time()
    times = user_report_times[user_id]

    # Remove timestamps older than the window
    user_report_times[user_id] = [t for t in times if now - t < RATE_LIMIT_WINDOW]

    if len(user_report_times[user_id]) >= RATE_LIMIT_MAX:
        return True

    # Log this request
    user_report_times[user_id].append(now)
    return False


# ── Input Validation ───────────────────────────────────────

def validate_url(url: str) -> bool:
    """Checks if the input looks like a valid URL."""
    pattern = re.compile(
        r'^(https?://)'           # must start with http:// or https://
        r'([a-zA-Z0-9\-\.]+)'    # domain
        r'(\.[a-zA-Z]{2,})'      # TLD (.com, .sg, etc.)
        r'(/.*)?$'                # optional path
    )
    return bool(pattern.match(url.strip()))


def validate_phone(phone: str) -> bool:
    """
    Checks if the input looks like a valid phone number.
    Accepts Singapore numbers (+65 XXXX XXXX) or general formats.
    """
    # Remove spaces and dashes
    cleaned = re.sub(r'[\s\-]', '', phone)
    pattern = re.compile(r'^(\+?\d{8,15})$')
    return bool(pattern.match(cleaned))


def validate_email(email: str) -> bool:
    """Checks if the input looks like a valid email address."""
    pattern = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
    return bool(pattern.match(email.strip()))


def sanitise_text(text: str) -> str:
    """
    Removes potentially dangerous characters from free text input.
    Strips HTML tags and limits length to 500 characters.
    """
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Remove special characters except basic punctuation
    text = re.sub(r'[^\w\s\.,!?\-@:/\(\)]', '', text)
    # Limit length
    return text.strip()[:500]


def detect_indicator_type(indicator: str) -> str:
    """
    Auto-detects whether the input is a URL, phone, email, or message.
    Returns the indicator_type string to send to the API.
    """
    if validate_url(indicator):
        return 'url'
    elif validate_email(indicator):
        return 'email'
    elif validate_phone(indicator):
        return 'phone'
    else:
        return 'message'


# ── Bot Command Handlers ───────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /start — Welcome message shown when user first opens the bot.
    """
    await update.message.reply_text(
        "👋 Welcome to the CSIP2 Scam Intelligence Bot!\n\n"
        "Here's what I can do:\n"
        "🔍 /check <URL/phone/email> — Check if something is a known scam\n"
        "📢 /report — Report a new scam\n"
        "ℹ️ /help — Show this help message\n\n"
        "Stay safe online! 🛡️"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /help — Shows the list of commands.
    """
    await update.message.reply_text(
        "📖 *CSIP2 Bot Commands*\n\n"
        "🔍 *Check a scam indicator:*\n"
        "`/check http://suspicious-site.com`\n"
        "`/check +65 9123 4567`\n"
        "`/check scam@fake-bank.com`\n\n"
        "📢 *Report a scam:*\n"
        "`/report` — I will guide you through the steps\n\n"
        "⚠️ *Limits:* Max 5 reports per minute.\n\n"
        "🌐 Visit our website: http://csip2.com",
        parse_mode='Markdown'
    )


async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /check <indicator> — Checks a URL, phone, or email against the database.
    Delegates the actual API call to Alyosius's database.py
    """
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide something to check.\n"
            "Example: `/check http://suspicious-site.com`",
            parse_mode='Markdown'
        )
        return

    indicator = ' '.join(context.args).strip()

    # Basic length check
    if len(indicator) > 500:
        await update.message.reply_text("⚠️ Input is too long. Please shorten it.")
        return

    # Sanitise the input
    indicator = sanitise_text(indicator)

    # Pass to Alyosius's check function
    from database import check_indicator_api
    await check_indicator_api(update, indicator)


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /report — Starts the guided scam report flow.
    Uses ConversationHandler (see main.py) to walk through steps.
    """
    user_id = update.message.from_user.id

    # Check rate limit first
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

    # Return state for ConversationHandler (defined in main.py)
    return 'WAITING_FOR_INDICATOR'


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /cancel — Cancels any ongoing conversation flow.
    """
    context.user_data.clear()
    await update.message.reply_text("❌ Report cancelled. Type /help to see what I can do.")
    return -1   # ConversationHandler.END


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles any unrecognised command.
    """
    await update.message.reply_text(
        "❓ I don't recognise that command. Type /help to see what I can do."
    )

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /status — Shows live database stats from the CSIP2 API
    """
    try:
        response = requests.get(f'{CSIP2_API_BASE}/reports', timeout=5)
        data     = response.json()
        reports  = data.get('reports', [])

        # Count each type
        blacklisted = sum(1 for r in reports if r.get('list_type') == 'blacklist')
        whitelisted = sum(1 for r in reports if r.get('list_type') == 'whitelist')
        total       = len(reports)

        # Count by scam type
        scam_counts = {}
        for r in reports:
            t = r.get('scam_type', 'Others')
            scam_counts[t] = scam_counts.get(t, 0) + 1

        # Build scam type breakdown
        breakdown = "\n".join([
            f"   • {k}: {v}" 
            for k, v in sorted(scam_counts.items(), key=lambda x: x[1], reverse=True)
        ])

        await update.message.reply_text(
            f"📊 *CSIP2 Database Stats*\n\n"
            f"🔴 Blacklisted: {blacklisted}\n"
            f"🟡 Whitelisted: {whitelisted}\n"
            f"📋 Total Reports: {total}\n\n"
            f"*By Scam Type:*\n{breakdown if breakdown else 'No data yet'}",
            parse_mode='Markdown'
        )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )