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
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ConversationHandler, ContextTypes, filters, CallbackQueryHandler
)
from commands import (
    start, help_command, check_command, about_command,
    report_command, cancel_command, unknown_command, status_command,
    is_rate_limited, detect_indicator_type, sanitise_text,
    check_single_indicator_sync, format_check_result
)

# ── Logging ────────────────────────────────────────────────
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ── Config ─────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
TELEGRAM_BOT_TOKEN = os.getenv('BOT_TOKEN')
CSIP2_API_BASE     = os.getenv('CSIP2_API_BASE', 'http://127.0.0.1:5000')

# ── Conversation states ────────────────────────────────────
WAITING_FOR_INDICATOR = 'WAITING_FOR_INDICATOR'
WAITING_FOR_SCAM_TYPE = 'WAITING_FOR_SCAM_TYPE'
WAITING_FOR_DESC      = 'WAITING_FOR_DESC'
WAITING_FOR_CONFIRM   = 'WAITING_FOR_CONFIRM'

SCAM_TYPES = [
    'Phishing',
    'E-Commerce Scam',
    'Impersonation',
    'Love Scam',
    'Investment Scam',
    'Others'
]


# ============================================================
#  AUTO SCAN — Feature 1 & 2
#  Scans any forwarded message for URLs and phone numbers
# ============================================================

def extract_indicators(text: str) -> dict:
    """Extracts all URLs and phone numbers from a block of text."""
    url_pattern   = re.compile(r'(https?://[^\s\)\]\>\"\']+)')
    phone_pattern = re.compile(r'(\+?65[\s\-]?\d{4}[\s\-]?\d{4}|\+?\d{8,15})')

    urls = list(set(url_pattern.findall(text)))
    phones = list(set([
        re.sub(r'[\s\-]', '', p)
        for p in phone_pattern.findall(text)
        if len(re.sub(r'[\s\-]', '', p)) >= 8
    ]))

    return {'urls': urls, 'phones': phones}


async def auto_scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Triggered on any plain text message — auto scans for indicators."""
    text = update.message.text or update.message.caption or ''
    if not text:
        return

    found = extract_indicators(text)
    all_indicators = [('url', u) for u in found['urls']] + \
                     [('phone', p) for p in found['phones']]

    if not all_indicators:
        return

    total = len(all_indicators)
    await update.message.reply_text(
        f"🔍 Found *{total} indicator{'s' if total > 1 else ''}* — scanning now...",
        parse_mode='Markdown'
    )

    results_text = []
    for _, indicator in all_indicators:
        result = check_single_indicator_sync(indicator)
        results_text.append(format_check_result(indicator, result))

    await update.message.reply_text(
        "\n\n".join(results_text),
        parse_mode='Markdown'
    )

    await update.message.reply_text(
        "💡 *Tip:* Found something not in our database? Use /report to flag it!",
        parse_mode='Markdown'
    )


# ============================================================
#  REPORT CONVERSATION FLOW
#  Step 1: /report
#  Step 2: User sends indicator
#  Step 3: Inline keyboard for scam type
#  Step 4: Optional description
#  Step 5: Confirmation before submit
#  Step 6: Submit to API
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

    keyboard = [
        [
            InlineKeyboardButton("🎣 Phishing",        callback_data='Phishing'),
            InlineKeyboardButton("🛒 E-Commerce Scam", callback_data='E-Commerce Scam'),
        ],
        [
            InlineKeyboardButton("🎭 Impersonation",   callback_data='Impersonation'),
            InlineKeyboardButton("💕 Love Scam",       callback_data='Love Scam'),
        ],
        [
            InlineKeyboardButton("📈 Investment Scam", callback_data='Investment Scam'),
            InlineKeyboardButton("❓ Others",           callback_data='Others'),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "✅ Got it! Now select the scam type:",
        reply_markup=reply_markup
    )
    return WAITING_FOR_SCAM_TYPE


async def receive_scam_type_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 3 — User taps a scam type button."""
    query = update.callback_query
    await query.answer()

    scam_type = query.data
    if scam_type not in SCAM_TYPES:
        await query.edit_message_text("⚠️ Invalid selection. Please try again.")
        return WAITING_FOR_SCAM_TYPE

    context.user_data['scam_type'] = scam_type
    await query.edit_message_text(f"✅ Scam type: *{scam_type}*", parse_mode='Markdown')

    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text="📝 Optionally add a short description (e.g. 'Fake DBS login page').\n"
             "Or send /skip to skip.",
    )
    return WAITING_FOR_DESC


async def receive_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 4 — User sends optional description."""
    desc = update.message.text.strip()
    if desc.lower() == '/skip':
        desc = ''
    context.user_data['description'] = sanitise_text(desc)

    indicator   = context.user_data.get('indicator', '')
    scam_type   = context.user_data.get('scam_type', '')
    description = context.user_data.get('description', '')

    keyboard = [[
        InlineKeyboardButton("✅ Confirm & Submit", callback_data='CONFIRM'),
        InlineKeyboardButton("❌ Cancel",            callback_data='CANCEL'),
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"📋 *Please confirm your report:*\n\n"
        f"🔗 Indicator: `{indicator}`\n"
        f"📌 Type: {scam_type}\n"
        f"📝 Description: {description if description else '_(none)_'}\n\n"
        f"Is this correct?",
        parse_mode='Markdown',
        reply_markup=reply_markup
    )
    return WAITING_FOR_CONFIRM


async def skip_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/skip — Skip description and go straight to confirmation."""
    context.user_data['description'] = ''

    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', '')

    keyboard = [[
        InlineKeyboardButton("✅ Confirm & Submit", callback_data='CONFIRM'),
        InlineKeyboardButton("❌ Cancel",            callback_data='CANCEL'),
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"📋 *Please confirm your report:*\n\n"
        f"🔗 Indicator: `{indicator}`\n"
        f"📌 Type: {scam_type}\n"
        f"📝 Description: _(none)_\n\n"
        f"Is this correct?",
        parse_mode='Markdown',
        reply_markup=reply_markup
    )
    return WAITING_FOR_CONFIRM


async def receive_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 5 — User confirms or cancels."""
    query = update.callback_query
    await query.answer()

    if query.data == 'CANCEL':
        context.user_data.clear()
        await query.edit_message_text("❌ Report cancelled.")
        return ConversationHandler.END

    await query.edit_message_text("⏳ Submitting your report...")
    await submit_report_to_api(update, context)
    return ConversationHandler.END


async def submit_report_to_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 6 — Sends the collected report to Kaden's Flask API."""
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
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="✅ *Report submitted successfully!*\n\n"
                     "Our admin team will review it shortly.\n"
                     "Thank you for helping keep Singapore safe! 🇸🇬",
                parse_mode='Markdown'
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="⚠️ Something went wrong. Please try again later."
            )
    except requests.exceptions.RequestException:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="⚠️ Could not reach the server. Please try again later."
        )

    context.user_data.clear()


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
                CallbackQueryHandler(receive_scam_type_callback)
            ],
            WAITING_FOR_DESC: [
                CommandHandler('skip', skip_description),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_description)
            ],
            WAITING_FOR_CONFIRM: [
                CallbackQueryHandler(receive_confirmation)
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel_command)]
    )

    # ── Register all handlers ──────────────────────────────
    # ORDER MATTERS — report_conv must come before unknown_command
    app.add_handler(CommandHandler('start',  start))
    app.add_handler(CommandHandler('help',   help_command))
    app.add_handler(CommandHandler('check',  check_command))
    app.add_handler(CommandHandler('status', status_command))
    app.add_handler(CommandHandler('about',  about_command))
    app.add_handler(report_conv)
    app.add_handler(MessageHandler(filters.COMMAND, unknown_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, auto_scan_message))

    print("🤖 CSIP2 Bot is running...")
    app.run_polling()


if __name__ == '__main__':
    main()