# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — main.py
#  Owner: Alyosius (Bot Setup + DB Connection + Alerts)
# ============================================================

import os
import re
import logging
import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ConversationHandler, ContextTypes, filters
)
from commands import (
    start, help_command, check_command,
    report_command, cancel_command, unknown_command,
    is_rate_limited, detect_indicator_type, sanitise_text
)

# ── Logging setup ──────────────────────────────────────────
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ── Config ─────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
TELEGRAM_BOT_TOKEN = os.getenv('BOT_TOKEN')
CSIP2_API_BASE     = os.getenv('CSIP2_API_BASE', 'http://127.0.0.1:5000')

# Conversation states
WAITING_FOR_INDICATOR = 'WAITING_FOR_INDICATOR'
WAITING_FOR_SCAM_TYPE = 'WAITING_FOR_SCAM_TYPE'
WAITING_FOR_DESC      = 'WAITING_FOR_DESC'

SCAM_TYPES = [
    'Phishing',
    'E-Commerce Scam',
    'Impersonation',
    'Love Scam',
    'Investment Scam',
    'Others'
]


# ============================================================
#  FEATURE 1 & 2 — AUTO SCAN FORWARDED MESSAGES
#  Automatically extracts ALL URLs and phone numbers from
#  any message the user forwards or sends to the bot
# ============================================================

def extract_indicators(text: str) -> dict:
    """
    Scans a block of text and extracts all URLs and phone numbers.
    Returns a dict with lists of found indicators.
    """
    # Extract URLs
    url_pattern = re.compile(
        r'(https?://[^\s\)\]\>\"\']+)'
    )
    urls = url_pattern.findall(text)

    # Extract phone numbers (Singapore +65 and general formats)
    phone_pattern = re.compile(
        r'(\+?65[\s\-]?\d{4}[\s\-]?\d{4}|\+?\d{8,15})'
    )
    phones = phone_pattern.findall(text)

    # Clean up phones — remove duplicates and very short matches
    phones = list(set([
        re.sub(r'[\s\-]', '', p)
        for p in phones
        if len(re.sub(r'[\s\-]', '', p)) >= 8
    ]))

    return {
        'urls':   list(set(urls)),    # deduplicate
        'phones': phones
    }


async def check_single_indicator(indicator: str) -> dict:
    """
    Calls the CSIP2 /check API for one indicator.
    Returns the API response dict.
    """
    try:
        response = requests.get(
            f'{CSIP2_API_BASE}/check',
            params={'url': indicator},
            timeout=5
        )
        return response.json()
    except requests.exceptions.RequestException:
        return {'status': 'error', 'message': 'Could not reach server.'}


def format_check_result(indicator: str, result: dict) -> str:
    """
    Formats a single /check result into a readable message.
    """
    status = result.get('status')

    if status == 'blacklist':
        return (
            f"🚨 *BLACKLISTED — Confirmed Scam*\n"
            f"└ `{indicator}`\n"
            f"└ Type: {result.get('scam_type', 'Unknown')}\n"
            f"└ {result.get('description', '')}\n"
            f"└ ⛔ Do NOT proceed!"
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
            f"└ Not in our database"
        )
    else:
        return (
            f"🔎 *Under Review*\n"
            f"└ `{indicator}`\n"
            f"└ Reported but not yet verified"
        )


async def auto_scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    FEATURE 1 & 2 — Triggered when user sends/forwards any text.
    Automatically extracts all URLs and phone numbers and checks them.
    """
    text = update.message.text or update.message.caption or ''

    if not text:
        return

    # Extract all indicators from the message
    found = extract_indicators(text)
    all_indicators = [('url', u) for u in found['urls']] + \
                     [('phone', p) for p in found['phones']]

    # Nothing found — ignore the message silently
    if not all_indicators:
        return

    total = len(all_indicators)
    await update.message.reply_text(
        f"🔍 Found *{total} indicator{'s' if total > 1 else ''}* to check...",
        parse_mode='Markdown'
    )

    # Check each indicator
    results_text = []
    for indicator_type, indicator in all_indicators:
        result = await check_single_indicator(indicator)
        results_text.append(format_check_result(indicator, result))

    # Send all results in one message
    final_message = "\n\n".join(results_text)
    await update.message.reply_text(final_message, parse_mode='Markdown')

    # If any blacklisted or whitelisted found, offer to report more
    statuses = [r.get('status') for _, ind in all_indicators
                for r in [await check_single_indicator(ind)]]

    await update.message.reply_text(
        "💡 *Tip:* If you found a scam not in our database, use /report to flag it!",
        parse_mode='Markdown'
    )


# ============================================================
#  REPORT CONVERSATION FLOW
# ============================================================

async def receive_indicator(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 2 — User sends the scam indicator."""
    user_id   = update.message.from_user.id
    indicator = update.message.text.strip()

    if is_rate_limited(user_id):
        await update.message.reply_text("⚠️ Too many reports. Please wait a minute.")
        return ConversationHandler.END

    if len(indicator) > 500:
        await update.message.reply_text("⚠️ Too long. Please shorten your input.")
        return WAITING_FOR_INDICATOR

    context.user_data['indicator']      = sanitise_text(indicator)
    context.user_data['indicator_type'] = detect_indicator_type(indicator)

    scam_list = "\n".join([f"{i+1}. {s}" for i, s in enumerate(SCAM_TYPES)])
    await update.message.reply_text(
        f"✅ Got it. Now select the scam type by sending the number:\n\n{scam_list}"
    )
    return WAITING_FOR_SCAM_TYPE


async def receive_scam_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 3 — User picks a scam type by number."""
    text = update.message.text.strip()

    if not text.isdigit() or not (1 <= int(text) <= len(SCAM_TYPES)):
        await update.message.reply_text(
            f"⚠️ Please send a number between 1 and {len(SCAM_TYPES)}."
        )
        return WAITING_FOR_SCAM_TYPE

    context.user_data['scam_type'] = SCAM_TYPES[int(text) - 1]

    await update.message.reply_text(
        "📝 Optionally, add a short description of the scam "
        "(e.g. 'Fake DBS login page'). Or send /skip to skip this step."
    )
    return WAITING_FOR_DESC


async def receive_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 4 — User sends optional description, then we submit."""
    desc = update.message.text.strip()

    if desc.lower() == '/skip':
        desc = ''

    context.user_data['description'] = sanitise_text(desc)
    await submit_report_to_api(update, context)
    return ConversationHandler.END


async def skip_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/skip — Skip the description step."""
    context.user_data['description'] = ''
    await submit_report_to_api(update, context)
    return ConversationHandler.END


async def submit_report_to_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Sends the collected report data to Kaden's Flask API."""
    payload = {
        'indicator_type': context.user_data.get('indicator_type'),
        'indicator':      context.user_data.get('indicator'),
        'scam_type':      context.user_data.get('scam_type'),
        'description':    context.user_data.get('description', ''),
        'source':         'telegram'
    }

    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/report', json=payload, timeout=5
        )
        if response.status_code == 201:
            await update.message.reply_text(
                "✅ *Report submitted successfully!*\n\n"
                "Our admin team will review it shortly. "
                "Thank you for helping keep Singapore safe! 🇸🇬",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "⚠️ Something went wrong submitting your report. Please try again later."
            )
    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )

    context.user_data.clear()


# ============================================================
#  CHECK INDICATOR — called by Zavier's /check command
# ============================================================

async def check_indicator_api(update: Update, indicator: str):
    """
    Queries Kaden's /check endpoint and replies with the result.
    Called from commands.py check_command().
    """
    result = await check_single_indicator(indicator)
    reply  = format_check_result(indicator, result)
    await update.message.reply_text(reply, parse_mode='Markdown')


# ============================================================
#  BOT SETUP — main entry point
# ============================================================

def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    # ── Report conversation flow ───────────────────────────
    report_conv = ConversationHandler(
        entry_points=[CommandHandler('report', report_command)],
        states={
            WAITING_FOR_INDICATOR: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_indicator)
            ],
            WAITING_FOR_SCAM_TYPE: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_scam_type)
            ],
            WAITING_FOR_DESC: [
                CommandHandler('skip', skip_description),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_description)
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel_command)]
    )

    # ── Register all commands ──────────────────────────────
    app.add_handler(CommandHandler('start',  start))
    app.add_handler(CommandHandler('help',   help_command))
    app.add_handler(CommandHandler('check',  check_command))
    app.add_handler(report_conv)
    app.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    # ── FEATURE 1 & 2 — Auto scan any forwarded/sent message ──
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        auto_scan_message
    ))

    print("🤖 CSIP2 Bot is running...")
    app.run_polling()


if __name__ == '__main__':
    main()