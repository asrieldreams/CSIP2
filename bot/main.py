# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — main.py
#  Owner: Alyosius
# ============================================================

import os
import re
import logging
import requests
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ConversationHandler, ContextTypes, filters, CallbackQueryHandler
)
from commands import (
    start, help_command, check_command, about_command,
    report_command, cancel_command, unknown_command, status_command,
    latest_command, search_command,
    is_rate_limited, detect_indicator_type, sanitise_text,
    check_single_indicator_sync, format_check_result,
    submit_report_to_new_api, get_main_menu, DIVIDER
)

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
TELEGRAM_BOT_TOKEN = os.getenv('BOT_TOKEN')
CSIP2_API_BASE     = os.getenv('CSIP2_API_BASE', 'http://127.0.0.1:5000')

WAITING_FOR_INDICATOR = 'WAITING_FOR_INDICATOR'
WAITING_FOR_SCAM_TYPE = 'WAITING_FOR_SCAM_TYPE'
WAITING_FOR_DESC      = 'WAITING_FOR_DESC'
WAITING_FOR_CONFIRM   = 'WAITING_FOR_CONFIRM'

SCAM_TYPES = [
    'Phishing', 'E-Commerce Scam', 'Impersonation',
    'Love Scam', 'Investment Scam', 'SMS Scam', 'Job Scam', 'Others'
]

user_history = {}


# ============================================================
#  MENU BUTTON HANDLER
# ============================================================

async def handle_menu_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "🔍 Check":
        await update.message.reply_text(
            f"🔍 *Check a Scam Indicator*\n"
            f"{DIVIDER}\n\n"
            f"Send what you want to check:\n\n"
            f"🔗 `/check http://suspicious-site.com`\n"
            f"📞 `/check +65 9123 4567`\n"
            f"📧 `/check scam@fake-bank.com`",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
    elif text == "📢 Report":
        await report_command(update, context)
    elif text == "📋 Latest":
        await latest_command(update, context)
    elif text == "🔎 Search":
        await update.message.reply_text(
            f"🔎 *Search Scam Database*\n"
            f"{DIVIDER}\n\n"
            f"Send a keyword:\n\n"
            f"`/search DBS`\n"
            f"`/search phishing`\n"
            f"`/search shopee`",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
    elif text == "📊 Status":
        await status_command(update, context)
    elif text == "📖 History":
        await history_command(update, context)
    elif text == "ℹ️ About":
        await about_command(update, context)
    elif text == "❓ Help":
        await help_command(update, context)


# ============================================================
#  AUTO SCAN
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
        f"🔍 *Auto-Scan Activated*\n"
        f"{DIVIDER}\n"
        f"Found *{total} indicator{'s' if total > 1 else ''}* — checking now...",
        parse_mode='Markdown'
    )

    results_text = []
    for _, indicator in all_indicators:
        result = check_single_indicator_sync(indicator)
        results_text.append(format_check_result(indicator, result))

    await update.message.reply_text(
        "\n\n".join(results_text),
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )


# ============================================================
#  /history
# ============================================================

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    history = user_history.get(user_id, [])

    if not history:
        await update.message.reply_text(
            f"📭 *No History Yet*\n"
            f"{DIVIDER}\n\n"
            f"You haven't submitted any reports\n"
            f"Tap 📢 *Report* to get started!",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
        return

    recent = history[-5:][::-1]
    lines  = []
    for i, entry in enumerate(recent, 1):
        lines.append(
            f"*{i}.* 📌 {entry['scam_type']}\n"
            f"   🔗 `{entry['indicator']}`\n"
            f"   📅 {entry['submitted_at']}"
        )

    await update.message.reply_text(
        f"📖 *Your Submission History*\n"
        f"{DIVIDER}\n"
        f"Last *{len(recent)}* report{'s' if len(recent) > 1 else ''}\n\n"
        + "\n\n".join(lines) +
        f"\n\n{DIVIDER}\n"
        f"_All reports are pending admin review_",
        parse_mode='Markdown',
        reply_markup=get_main_menu()
    )


# ============================================================
#  Group chat support
# ============================================================

async def group_scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
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
        if result.get('status') in ('blacklist', 'whitelist'):
            flagged.append(format_check_result(indicator, result))

    if flagged:
        sender = update.message.from_user.first_name or 'Someone'
        await update.message.reply_text(
            f"🚨 *CSIP2 Group Scam Alert*\n"
            f"{DIVIDER}\n"
            f"⚠️ {sender} shared a flagged indicator!\n\n"
            + "\n\n".join(flagged) +
            f"\n\n{DIVIDER}\n"
            f"🛡️ Stay safe! Use /report to submit new scams",
            parse_mode='Markdown'
        )


# ============================================================
#  REPORT CONVERSATION FLOW
# ============================================================

async def receive_indicator(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id   = update.message.from_user.id
    indicator = update.message.text.strip()

    if is_rate_limited(user_id):
        await update.message.reply_text(
            f"⏱️ *Rate Limit Reached*\n{DIVIDER}\nPlease wait a minute",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )
        return ConversationHandler.END

    if len(indicator) > 500:
        await update.message.reply_text("⚠️ Too long. Max 500 characters.")
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
            InlineKeyboardButton("💬 SMS Scam",        callback_data='SMS Scam'),
        ],
        [
            InlineKeyboardButton("💼 Job Scam",        callback_data='Job Scam'),
            InlineKeyboardButton("❓ Others",           callback_data='Others'),
        ],
    ]
    await update.message.reply_text(
        f"📢 *Submit a Scam Report*\n"
        f"{DIVIDER}\n"
        f"📍 *Step 2 of 4* — Select Scam Type\n\n"
        f"✅ Indicator saved: `{sanitise_text(indicator)}`\n\n"
        f"Now tap the scam type below:",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_SCAM_TYPE


async def receive_scam_type_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    scam_type = query.data
    if scam_type not in SCAM_TYPES:
        await query.edit_message_text("⚠️ Invalid selection. Please try again.")
        return WAITING_FOR_SCAM_TYPE

    context.user_data['scam_type'] = scam_type
    await query.edit_message_text(
        f"📢 *Submit a Scam Report*\n"
        f"{DIVIDER}\n"
        f"📍 *Step 2 of 4* — ✅ Done\n\n"
        f"🏷️ Type selected: *{scam_type}*",
        parse_mode='Markdown'
    )

    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f"📢 *Submit a Scam Report*\n"
             f"{DIVIDER}\n"
             f"📍 *Step 3 of 4* — Add Description\n\n"
             f"📝 Optionally describe the scam\n"
             f"e.g. _'Fake DBS login page'_\n\n"
             f"Or send /skip to skip this step",
        parse_mode='Markdown'
    )
    return WAITING_FOR_DESC


async def receive_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    desc = update.message.text.strip()
    # Accept both "/skip" and "skip"
    if desc.lower() in ('/skip', 'skip'):
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
        f"📢 *Submit a Scam Report*\n"
        f"{DIVIDER}\n"
        f"📍 *Step 4 of 4* — Confirm\n\n"
        f"📋 *Review your report:*\n\n"
        f"🔗 `{indicator}`\n"
        f"🏷️ {scam_type}\n"
        f"📝 {description if description else '_No description_'}\n\n"
        f"Is everything correct?",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_CONFIRM


async def skip_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['description'] = ''

    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', '')

    keyboard = [[
        InlineKeyboardButton("✅ Confirm & Submit", callback_data='CONFIRM'),
        InlineKeyboardButton("❌ Cancel",            callback_data='CANCEL'),
    ]]

    await update.message.reply_text(
        f"📢 *Submit a Scam Report*\n"
        f"{DIVIDER}\n"
        f"📍 *Step 4 of 4* — Confirm\n\n"
        f"📋 *Review your report:*\n\n"
        f"🔗 `{indicator}`\n"
        f"🏷️ {scam_type}\n"
        f"📝 _No description_\n\n"
        f"Is everything correct?",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_CONFIRM


async def receive_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == 'CANCEL':
        context.user_data.clear()
        await query.edit_message_text(
            f"❌ *Report Cancelled*\n"
            f"{DIVIDER}\n"
            f"No report was submitted",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    await query.edit_message_text(
        f"⏳ *Submitting your report...*\n"
        f"{DIVIDER}\n"
        f"Please wait a moment",
        parse_mode='Markdown'
    )

    user_id   = update.effective_user.id
    indicator = context.user_data.get('indicator')
    scam_type = context.user_data.get('scam_type')

    await submit_report_to_new_api(update, context)

    if user_id not in user_history:
        user_history[user_id] = []
    user_history[user_id].append({
        'indicator':    indicator,
        'scam_type':    scam_type,
        'submitted_at': datetime.now().strftime('%d %b %Y %H:%M')
    })

    return ConversationHandler.END


# ============================================================
#  BOT SETUP
# ============================================================

def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    report_conv = ConversationHandler(
        entry_points=[
            CommandHandler('report', report_command),
            MessageHandler(filters.Regex(r'^📢 Report$'), report_command)
        ],
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

    app.add_handler(CommandHandler('start',   start))
    app.add_handler(CommandHandler('help',    help_command))
    app.add_handler(CommandHandler('check',   check_command))
    app.add_handler(CommandHandler('status',  status_command))
    app.add_handler(CommandHandler('about',   about_command))
    app.add_handler(CommandHandler('history', history_command))
    app.add_handler(CommandHandler('latest',  latest_command))
    app.add_handler(CommandHandler('search',  search_command))
    app.add_handler(report_conv)
    app.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    # ── Menu buttons ──────────────────────────────────────
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND & filters.ChatType.PRIVATE &
        filters.Regex(
            r'^(🔍 Check|📢 Report|📋 Latest|🔎 Search|📊 Status|📖 History|ℹ️ About|❓ Help)$'
        ),
        handle_menu_button
    ))

    # ── Auto scan private ─────────────────────────────────
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND & filters.ChatType.PRIVATE,
        auto_scan_message
    ))

    # ── Group scan ────────────────────────────────────────
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND &
        (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP),
        group_scan_message
    ))

    print("🤖 CSIP2 Bot is running...")
    app.run_polling()


if __name__ == '__main__':
    main()