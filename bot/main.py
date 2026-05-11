# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Telegram Bot — main.py
#  Owner: Alyosius (Bot Setup + DB Connection + Alerts)
# ============================================================

import os
import logging
import requests
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
TELEGRAM_BOT_TOKEN = '8518190489:AAFIEgYTs4oI8EEVQ9Pe4pVDMDSQu9cpYY4'   # get from @BotFather on Telegram
CSIP2_API_BASE     = 'http://localhost:5000'  # Kaden's Flask API (change to deployed URL later)

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
#  REPORT CONVERSATION FLOW
#  Step 1: User sends /report
#  Step 2: Bot asks for the indicator (URL/phone/etc.)
#  Step 3: Bot asks for scam type
#  Step 4: Bot asks for optional description
#  Step 5: Bot submits to API and confirms
# ============================================================

async def receive_indicator(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Step 2 — User sends the scam indicator."""
    user_id   = update.message.from_user.id
    indicator = update.message.text.strip()

    # Rate limit check
    if is_rate_limited(user_id):
        await update.message.reply_text("⚠️ Too many reports. Please wait a minute.")
        return ConversationHandler.END

    # Validate length
    if len(indicator) > 500:
        await update.message.reply_text("⚠️ Too long. Please shorten your input.")
        return WAITING_FOR_INDICATOR

    # Save to user session
    context.user_data['indicator']      = sanitise_text(indicator)
    context.user_data['indicator_type'] = detect_indicator_type(indicator)

    # Ask for scam type
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
        response = requests.post(f'{CSIP2_API_BASE}/report', json=payload, timeout=5)

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
    try:
        response = requests.get(
            f'{CSIP2_API_BASE}/check',
            params={'url': indicator},
            timeout=5
        )
        data = response.json()
        status = data.get('status')

        if status == 'blacklist':
            await update.message.reply_text(
                f"🚨 *BLACKLISTED — Confirmed Scam*\n\n"
                f"🔗 `{indicator}`\n"
                f"📌 Type: {data.get('scam_type', 'Unknown')}\n"
                f"📝 {data.get('description', '')}\n\n"
                f"⛔ Do NOT proceed. This has been confirmed as a scam.",
                parse_mode='Markdown'
            )

        elif status == 'whitelist':
            await update.message.reply_text(
                f"⚠️ *FLAGGED — Proceed With Caution*\n\n"
                f"🔗 `{indicator}`\n"
                f"📌 Type: {data.get('scam_type', 'Unknown')}\n"
                f"📝 {data.get('description', '')}\n\n"
                f"This has been flagged by the community but is not yet confirmed. "
                f"Be very careful if you choose to proceed.",
                parse_mode='Markdown'
            )

        elif status == 'clean':
            await update.message.reply_text(
                f"✅ *No reports found*\n\n"
                f"`{indicator}` is not in our database.\n\n"
                f"If you think this is a scam, use /report to flag it!",
                parse_mode='Markdown'
            )

        else:
            await update.message.reply_text(
                f"🔎 `{indicator}` has been reported but is still under admin review.",
                parse_mode='Markdown'
            )

    except requests.exceptions.RequestException:
        await update.message.reply_text(
            "⚠️ Could not reach the server. Please try again later."
        )


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

    print("🤖 CSIP2 Bot is running...")
    app.run_polling()


if __name__ == '__main__':
    main()

