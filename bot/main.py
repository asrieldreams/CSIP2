# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — main.py
#  Owner: Alyosius (Bot Setup + DB Connection + Alerts)
# ============================================================

import os
import re
import io
import logging
import requests
from datetime import datetime
from dotenv import load_dotenv
import cv2
import numpy as np
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

# ── Conversation states ────────────────────────────────────
WAITING_FOR_INDICATOR = 'WAITING_FOR_INDICATOR'
WAITING_FOR_SCAM_TYPE = 'WAITING_FOR_SCAM_TYPE'
WAITING_FOR_SEVERITY  = 'WAITING_FOR_SEVERITY'
WAITING_FOR_PLATFORM  = 'WAITING_FOR_PLATFORM'
WAITING_FOR_DESC      = 'WAITING_FOR_DESC'
WAITING_FOR_CONFIRM   = 'WAITING_FOR_CONFIRM'

SCAM_TYPES = [
    'Phishing', 'E-Commerce Scam', 'Impersonation',
    'Love Scam', 'Investment Scam', 'SMS Scam', 'Job Scam', 'Others'
]

SEVERITIES = ['Low', 'Medium', 'High']
PLATFORMS  = ['WhatsApp', 'Telegram', 'SMS / Call', 'Email',
              'Website', 'Facebook', 'Instagram', 'Shopee / Lazada', 'Other']

user_history = {}


# ============================================================
#  QR CODE SCANNER
# ============================================================

async def scan_qr_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles photo/image messages — scans for QR codes."""
    photo    = update.message.photo
    document = update.message.document

    if photo:
        file = await context.bot.get_file(photo[-1].file_id)
    elif document and document.mime_type and document.mime_type.startswith('image/'):
        file = await context.bot.get_file(document.file_id)
    else:
        return

    await update.message.reply_text(
        f"📷 *Scanning for QR codes...*",
        parse_mode='Markdown'
    )

    try:
        file_bytes = await file.download_as_bytearray()
        np_arr     = np.frombuffer(bytes(file_bytes), np.uint8)
        image      = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        # Use OpenCV QR detector
        detector  = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)

        if not data:
            await update.message.reply_text(
                f"❌ *No QR Code Found*\n{DIVIDER}\n\n"
                f"Could not detect a QR code in this image.\n"
                f"Try a clearer photo with better lighting.\n\n"
                f"💡 You can also type `/check http://url.com` directly",
                parse_mode='Markdown',
                reply_markup=get_main_menu()
            )
            return

        qr_data = data.strip()

        if qr_data.startswith('http://') or qr_data.startswith('https://'):
            result     = check_single_indicator_sync(qr_data)
            result_msg = format_check_result(qr_data, result)
        else:
            result_msg = (
                f"📄 *QR Content:*\n"
                f"└ `{qr_data[:100]}`\n"
                f"└ Not a URL — no scam check needed"
            )

        await update.message.reply_text(
            f"📷 *QR Code Scan Complete*\n{DIVIDER}\n"
            f"Found *1* QR code\n\n"
            + result_msg,
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )

    except Exception as e:
        await update.message.reply_text(
            f"⚠️ *Scan Failed*\n{DIVIDER}\n"
            f"Could not process this image.\n"
            f"Try sending a clearer photo.",
            parse_mode='Markdown',
            reply_markup=get_main_menu()
        )


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
        f"🔍 *Auto-Scan Activated*\n{DIVIDER}\n"
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
            f"📭 *No History Yet*\n{DIVIDER}\n"
            f"You haven't submitted any reports\n"
            f"Tap 📢 *Report* to get started!",
            parse_mode='Markdown', reply_markup=get_main_menu()
        )
        return
    recent = history[-5:][::-1]
    lines  = []
    for i, entry in enumerate(recent, 1):
        lines.append(
            f"*{i}.* 📌 {entry['scam_type']}\n"
            f"   🔗 `{entry['indicator']}`\n"
            f"   ⚠️ {entry.get('severity','Medium')} · 📱 {entry.get('platform','Telegram')}\n"
            f"   📅 {entry['submitted_at']}"
        )
    await update.message.reply_text(
        f"📖 *Your Submission History*\n{DIVIDER}\n"
        f"Last *{len(recent)}* report{'s' if len(recent) > 1 else ''}\n\n"
        + "\n\n".join(lines),
        parse_mode='Markdown', reply_markup=get_main_menu()
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
            f"🚨 *CSIP2 Scam Alert*\n{DIVIDER}\n"
            f"⚠️ {sender} shared a flagged indicator!\n\n"
            + "\n\n".join(flagged) +
            f"\n\n{DIVIDER}\n🛡️ Stay safe! Use /report to submit new scams",
            parse_mode='Markdown'
        )


# ============================================================
#  MENU BUTTON HANDLER
# ============================================================

async def handle_menu_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "🔍 Check":
        await update.message.reply_text(
            f"🔍 *Check a Scam Indicator*\n{DIVIDER}\n\n"
            f"Send what you want to check:\n\n"
            f"🔗 `/check http://suspicious-site.com`\n"
            f"📞 `/check +65 9123 4567`\n"
            f"📧 `/check scam@fake-bank.com`\n"
            f"📷 Or send a *QR code photo*!",
            parse_mode='Markdown', reply_markup=get_main_menu()
        )
    elif text == "📢 Report":
        await report_command(update, context)
    elif text == "📋 Latest":
        await latest_command(update, context)
    elif text == "🔎 Search":
        await update.message.reply_text(
            f"🔎 *Search Scam Database*\n{DIVIDER}\n\n"
            f"Send a keyword:\n\n"
            f"`/search DBS`\n`/search phishing`\n`/search shopee`",
            parse_mode='Markdown', reply_markup=get_main_menu()
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
#  REPORT CONVERSATION FLOW — 6 Steps
# ============================================================

async def receive_indicator(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 2 — User sends the scam indicator."""
    user_id   = update.message.from_user.id
    indicator = update.message.text.strip()

    if is_rate_limited(user_id):
        await update.message.reply_text(
            f"⏱️ *Rate Limit Reached*\n{DIVIDER}\nMax 5 reports per minute",
            parse_mode='Markdown', reply_markup=get_main_menu()
        )
        return ConversationHandler.END

    if len(indicator) > 500:
        await update.message.reply_text("⚠️ Too long. Max 500 characters.")
        return WAITING_FOR_INDICATOR

    context.user_data['indicator']      = sanitise_text(indicator)
    context.user_data['indicator_type'] = detect_indicator_type(indicator)

    keyboard = [
        [
            InlineKeyboardButton("🎣 Phishing",        callback_data='type:Phishing'),
            InlineKeyboardButton("🛒 E-Commerce Scam", callback_data='type:E-Commerce Scam'),
        ],
        [
            InlineKeyboardButton("🎭 Impersonation",   callback_data='type:Impersonation'),
            InlineKeyboardButton("💕 Love Scam",       callback_data='type:Love Scam'),
        ],
        [
            InlineKeyboardButton("📈 Investment Scam", callback_data='type:Investment Scam'),
            InlineKeyboardButton("💬 SMS Scam",        callback_data='type:SMS Scam'),
        ],
        [
            InlineKeyboardButton("💼 Job Scam",        callback_data='type:Job Scam'),
            InlineKeyboardButton("❓ Others",           callback_data='type:Others'),
        ],
    ]
    await update.message.reply_text(
        f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
        f"📍 *Step 2 of 6* — Select Scam Type\n\n"
        f"✅ Indicator saved: `{sanitise_text(indicator)}`\n\n"
        f"Now tap the scam type below:",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_SCAM_TYPE


async def receive_scam_type_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 3 — User taps a scam type button."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith('type:'):
        return WAITING_FOR_SCAM_TYPE

    scam_type = data[5:]
    if scam_type not in SCAM_TYPES:
        return WAITING_FOR_SCAM_TYPE

    context.user_data['scam_type'] = scam_type
    await query.edit_message_text(
        f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
        f"📍 *Step 2 of 6* — ✅ Done\n\n"
        f"🏷️ Type selected: *{scam_type}*",
        parse_mode='Markdown'
    )

    keyboard = [[
        InlineKeyboardButton("⚠️ Low",    callback_data='sev:Low'),
        InlineKeyboardButton("🚨 Medium", callback_data='sev:Medium'),
        InlineKeyboardButton("🔴 High",   callback_data='sev:High'),
    ]]
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
             f"📍 *Step 3 of 6* — How Severe Was the Impact?\n\n"
             f"⚠️ Low = No financial loss\n"
             f"🚨 Medium = Attempted loss\n"
             f"🔴 High = Financial loss occurred",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_SEVERITY


async def receive_severity_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 4 — User taps a severity button."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith('sev:'):
        return WAITING_FOR_SEVERITY

    severity  = data[4:]
    sev_emoji = {'Low': '⚠️', 'Medium': '🚨', 'High': '🔴'}.get(severity, '🚨')
    context.user_data['severity'] = severity.lower()

    await query.edit_message_text(
        f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
        f"📍 *Step 3 of 6* — ✅ Done\n\n"
        f"{sev_emoji} Severity: *{severity}*",
        parse_mode='Markdown'
    )

    keyboard = [
        [
            InlineKeyboardButton("📱 WhatsApp",      callback_data='plt:WhatsApp'),
            InlineKeyboardButton("✈️ Telegram",      callback_data='plt:Telegram'),
        ],
        [
            InlineKeyboardButton("📞 SMS / Call",    callback_data='plt:SMS / Call'),
            InlineKeyboardButton("📧 Email",         callback_data='plt:Email'),
        ],
        [
            InlineKeyboardButton("🌐 Website",       callback_data='plt:Website'),
            InlineKeyboardButton("📘 Facebook",      callback_data='plt:Facebook'),
        ],
        [
            InlineKeyboardButton("📸 Instagram",     callback_data='plt:Instagram'),
            InlineKeyboardButton("🛒 Shopee/Lazada", callback_data='plt:Shopee / Lazada'),
        ],
        [
            InlineKeyboardButton("❓ Other",          callback_data='plt:Other'),
            InlineKeyboardButton("⏭️ Skip",          callback_data='plt:Telegram'),
        ],
    ]
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
             f"📍 *Step 4 of 6* — Where Did the Scam Occur?\n\n"
             f"Tap to select platform:",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_PLATFORM


async def receive_platform_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 5 — User taps a platform button."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith('plt:'):
        return WAITING_FOR_PLATFORM

    platform = data[4:]
    context.user_data['platform'] = platform

    await query.edit_message_text(
        f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
        f"📍 *Step 4 of 6* — ✅ Done\n\n"
        f"📱 Platform: *{platform}*",
        parse_mode='Markdown'
    )

    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
             f"📍 *Step 5 of 6* — Add Description\n\n"
             f"📝 Describe what happened\n"
             f"e.g. _'Received a call claiming to be from SPF'_\n\n"
             f"Or send /skip to skip",
        parse_mode='Markdown'
    )
    return WAITING_FOR_DESC


async def receive_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 6 — User sends optional description."""
    desc = update.message.text.strip()
    if desc.lower() in ('/skip', 'skip'):
        desc = ''
    context.user_data['description'] = sanitise_text(desc)

    indicator   = context.user_data.get('indicator', '')
    scam_type   = context.user_data.get('scam_type', '')
    description = context.user_data.get('description', '')
    severity    = context.user_data.get('severity', 'medium')
    platform    = context.user_data.get('platform', 'Telegram')
    sev_emoji   = '🔴' if severity == 'high' else '🚨' if severity == 'medium' else '⚠️'

    keyboard = [[
        InlineKeyboardButton("✅ Confirm & Submit", callback_data='CONFIRM'),
        InlineKeyboardButton("❌ Cancel",            callback_data='CANCEL'),
    ]]

    await update.message.reply_text(
        f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
        f"📍 *Step 6 of 6* — Confirm\n\n"
        f"📋 *Review your report:*\n\n"
        f"🔗 `{indicator}`\n"
        f"🏷️ {scam_type}\n"
        f"{sev_emoji} Severity: {severity.capitalize()}\n"
        f"📱 Platform: {platform}\n"
        f"📝 {description if description else '_(none)_'}\n\n"
        f"Is everything correct?",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_CONFIRM


async def skip_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/skip — Skip description, go to confirmation."""
    context.user_data['description'] = ''

    indicator = context.user_data.get('indicator', '')
    scam_type = context.user_data.get('scam_type', '')
    severity  = context.user_data.get('severity', 'medium')
    platform  = context.user_data.get('platform', 'Telegram')
    sev_emoji = '🔴' if severity == 'high' else '🚨' if severity == 'medium' else '⚠️'

    keyboard = [[
        InlineKeyboardButton("✅ Confirm & Submit", callback_data='CONFIRM'),
        InlineKeyboardButton("❌ Cancel",            callback_data='CANCEL'),
    ]]

    await update.message.reply_text(
        f"📢 *Submit a Scam Report*\n{DIVIDER}\n"
        f"📍 *Step 6 of 6* — Confirm\n\n"
        f"📋 *Review your report:*\n\n"
        f"🔗 `{indicator}`\n"
        f"🏷️ {scam_type}\n"
        f"{sev_emoji} Severity: {severity.capitalize()}\n"
        f"📱 Platform: {platform}\n"
        f"📝 _(none)_\n\n"
        f"Is everything correct?",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_CONFIRM


async def receive_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 7 — User confirms or cancels."""
    query = update.callback_query
    await query.answer()

    if query.data == 'CANCEL':
        context.user_data.clear()
        await query.edit_message_text(
            f"❌ *Report Cancelled*\n{DIVIDER}\nNo report was submitted",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    await query.edit_message_text(
        f"⏳ *Submitting your report...*\n{DIVIDER}\nPlease wait a moment",
        parse_mode='Markdown'
    )

    user_id   = update.effective_user.id
    indicator = context.user_data.get('indicator')
    scam_type = context.user_data.get('scam_type')
    severity  = context.user_data.get('severity', 'medium')
    platform  = context.user_data.get('platform', 'Telegram')

    await submit_report_to_new_api(update, context)

    if user_id not in user_history:
        user_history[user_id] = []
    user_history[user_id].append({
        'indicator':    indicator,
        'scam_type':    scam_type,
        'severity':     severity.capitalize(),
        'platform':     platform,
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
                CallbackQueryHandler(receive_scam_type_callback, pattern='^type:')
            ],
            WAITING_FOR_SEVERITY: [
                CallbackQueryHandler(receive_severity_callback, pattern='^sev:')
            ],
            WAITING_FOR_PLATFORM: [
                CallbackQueryHandler(receive_platform_callback, pattern='^plt:')
            ],
            WAITING_FOR_DESC: [
                CommandHandler('skip', skip_description),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_description)
            ],
            WAITING_FOR_CONFIRM: [
                CallbackQueryHandler(receive_confirmation, pattern='^(CONFIRM|CANCEL)$')
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel_command)]
    )

    # ── Register all handlers ──────────────────────────────
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

    # ── QR code scanner ───────────────────────────────────
    app.add_handler(MessageHandler(
        (filters.PHOTO | filters.Document.IMAGE) & filters.ChatType.PRIVATE,
        scan_qr_code
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