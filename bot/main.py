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

# ── In-memory history store ────────────────────────────────
# { user_id: [ {indicator, scam_type, submitted_at}, ... ] }
user_history = {}


# ============================================================
#  AUTO SCAN — Feature 1 & 2
# ============================================================

def extract_indicators(text: str) -> dict:
    url_pattern   = re.compile(r'(https?://[^\s\)\]\>\"\']+)')
    phone_pattern = re.compile(r'(\+?65[\s\-]?\d{4}[\s\-]?\d{4}|\+?\d{8,15})')
    urls   = list(set(url_pattern.findall(text)))
    phones = list(set([
        re.sub(r'[\s\-]', '', p)
        for p in phone_pattern.findall(text)
        if len(re.sub(r'[\s\-]', '', p)) >= 8
    ]))
    return {'urls': urls, 'phones': phones}


async def auto_scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Triggered on any plain text — auto scans for indicators."""
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
#  FEATURE: /history
#  Shows the last 5 reports submitted by this user
# ============================================================

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/history — Shows the user's last 5 submitted reports."""
    user_id = update.message.from_user.id
    history = user_history.get(user_id, [])

    if not history:
        await update.message.reply_text(
            "📭 You haven't submitted any reports yet.\n"
            "Use /report to report a scam!"
        )
        return

    # Show last 5 in reverse order (newest first)
    recent = history[-5:][::-1]
    lines  = []
    for i, entry in enumerate(recent, 1):
        lines.append(
            f"*{i}.* `{entry['indicator']}`\n"
            f"   📌 {entry['scam_type']} · 📅 {entry['submitted_at']}"
        )

    await update.message.reply_text(
        f"📋 *Your Last {len(recent)} Report{'s' if len(recent) > 1 else ''}:*\n\n"
        + "\n\n".join(lines),
        parse_mode='Markdown'
    )


# ============================================================
#  FEATURE: Group chat support
#  Bot scans every message in a group for scam indicators
# ============================================================

async def group_scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Scans messages in group chats automatically.
    Only replies if a blacklisted or whitelisted indicator is found.
    Stays silent for clean messages to avoid spam.
    """
    text = update.message.text or update.message.caption or ''
    if not text:
        return

    found = extract_indicators(text)
    all_indicators = [('url', u) for u in found['urls']] + \
                     [('phone', p) for p in found['phones']]

    if not all_indicators:
        return

    flagged = []
    for _, indicator in all_indicators:
        result = check_single_indicator_sync(indicator)
        status = result.get('status')
        if status in ('blacklist', 'whitelist'):
            flagged.append(format_check_result(indicator, result))

    # Only reply if something is flagged — don't spam the group
    if flagged:
        sender = update.message.from_user.first_name or 'Someone'
        await update.message.reply_text(
            f"⚠️ *CSIP2 Scam Alert*\n\n"
            f"{sender} shared a flagged indicator:\n\n"
            + "\n\n".join(flagged) +
            "\n\n🛡️ Stay safe! Use /report to submit new scams.",
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
    await update.message.reply_text(
        "✅ Got it! Now select the scam type:",
        reply_markup=InlineKeyboardMarkup(keyboard)
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

    await update.message.reply_text(
        f"📋 *Please confirm your report:*\n\n"
        f"🔗 Indicator: `{indicator}`\n"
        f"📌 Type: {scam_type}\n"
        f"📝 Description: {description if description else '_(none)_'}\n\n"
        f"Is this correct?",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_CONFIRM


async def skip_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/skip — Skip description, go to confirmation."""
    context.user_data['description'] = ''

    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', '')

    keyboard = [[
        InlineKeyboardButton("✅ Confirm & Submit", callback_data='CONFIRM'),
        InlineKeyboardButton("❌ Cancel",            callback_data='CANCEL'),
    ]]

    await update.message.reply_text(
        f"📋 *Please confirm your report:*\n\n"
        f"🔗 Indicator: `{indicator}`\n"
        f"📌 Type: {scam_type}\n"
        f"📝 Description: _(none)_\n\n"
        f"Is this correct?",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
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
    """Step 6 — Sends report to Kaden's Flask API and saves to history."""
    user_id   = update.effective_user.id
    indicator = context.user_data.get('indicator')
    scam_type = context.user_data.get('scam_type')

    payload = {
        'indicator_type': context.user_data.get('indicator_type'),
        'indicator':      indicator,
        'scam_type':      scam_type,
        'description':    context.user_data.get('description', ''),
        'source':         'telegram'
    }

    try:
        response = requests.post(
            f'{CSIP2_API_BASE}/report', json=payload, timeout=5
        )
        if response.status_code == 201:
            # ── Save to user history ───────────────────────
            from datetime import datetime
            if user_id not in user_history:
                user_history[user_id] = []
            user_history[user_id].append({
                'indicator':    indicator,
                'scam_type':    scam_type,
                'submitted_at': datetime.now().strftime('%d %b %Y %H:%M')
            })

            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="✅ *Report submitted successfully!*\n\n"
                     "Our admin team will review it shortly.\n"
                     "Thank you for helping keep Singapore safe! 🇸🇬\n\n"
                     "💡 Use /history to view your past reports.",
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
    # ORDER MATTERS — specific handlers before catch-all
    app.add_handler(CommandHandler('start',   start))
    app.add_handler(CommandHandler('help',    help_command))
    app.add_handler(CommandHandler('check',   check_command))
    app.add_handler(CommandHandler('status',  status_command))
    app.add_handler(CommandHandler('about',   about_command))
    app.add_handler(CommandHandler('history', history_command))
    app.add_handler(report_conv)
    app.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    # ── Auto scan — private chats only ────────────────────
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND & filters.ChatType.PRIVATE,
        auto_scan_message
    ))

    # ── Group chat scan — groups and supergroups ──────────
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND &
        (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP),
        group_scan_message
    ))

    print("🤖 CSIP2 Bot is running...")
    app.run_polling()


if __name__ == '__main__':
    main()