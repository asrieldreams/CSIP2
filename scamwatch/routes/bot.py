from flask import Blueprint, request, jsonify
from extensions import db
from models import (
    BotUser, BotRateLimit, BotHistory, BotCheckLog, BotGroupChat, Scam
)
from datetime import datetime, timedelta

bot_bp = Blueprint('bot', __name__)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER — get or create a BotUser record
# ─────────────────────────────────────────────────────────────────────────────
def get_or_create_user(telegram_id, username=None, first_name=None):
    user = BotUser.query.filter_by(telegram_id=telegram_id).first()
    if not user:
        user = BotUser(
            telegram_id = telegram_id,
            username    = username,
            first_name  = first_name,
        )
        db.session.add(user)
        db.session.flush()
    else:
        # Update name fields if provided
        if username:   user.username   = username
        if first_name: user.first_name = first_name
        user.last_seen = datetime.utcnow()
    return user


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/bot/user
# Register or update a Telegram user.
# Called when a user first interacts with the bot (/start).
#
# Body: { telegram_id, username?, first_name? }
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/user', methods=['POST'])
def register_user():
    data        = request.get_json(silent=True) or {}
    telegram_id = data.get('telegram_id')
    if not telegram_id:
        return jsonify({'error': 'telegram_id is required'}), 400

    user = get_or_create_user(
        telegram_id = int(telegram_id),
        username    = data.get('username'),
        first_name  = data.get('first_name'),
    )
    db.session.commit()
    return jsonify({'success': True, 'user': user.to_dict()}), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/bot/rate-limit/<telegram_id>?action=report
# Check if a user is rate limited for a given action.
# Returns { allowed: true/false, remaining: N, reset_in: N seconds }
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/rate-limit/<int:telegram_id>', methods=['GET'])
def check_rate_limit(telegram_id):
    action     = request.args.get('action', 'report')
    max_count  = 5   # max actions per window
    window_sec = 60  # 1 minute window
    cutoff     = datetime.utcnow() - timedelta(seconds=window_sec)

    recent = BotRateLimit.query.filter(
        BotRateLimit.telegram_id == telegram_id,
        BotRateLimit.action      == action,
        BotRateLimit.actioned_at >= cutoff
    ).all()

    count     = len(recent)
    allowed   = count < max_count
    remaining = max(0, max_count - count)

    # Calculate seconds until oldest entry expires
    reset_in = 0
    if recent:
        oldest   = min(r.actioned_at for r in recent)
        reset_in = max(0, int((oldest + timedelta(seconds=window_sec) - datetime.utcnow()).total_seconds()))

    return jsonify({
        'allowed':   allowed,
        'count':     count,
        'remaining': remaining,
        'reset_in':  reset_in,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/bot/rate-limit/<telegram_id>
# Record an action for rate limiting purposes.
# Body: { action: 'report'|'check', username?, first_name? }
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/rate-limit/<int:telegram_id>', methods=['POST'])
def record_action(telegram_id):
    data   = request.get_json(silent=True) or {}
    action = data.get('action', 'report')

    # Ensure user exists
    get_or_create_user(
        telegram_id = telegram_id,
        username    = data.get('username'),
        first_name  = data.get('first_name'),
    )

    entry = BotRateLimit(telegram_id=telegram_id, action=action)
    db.session.add(entry)
    db.session.commit()
    return jsonify({'success': True}), 201


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/bot/history/<telegram_id>?limit=5
# Get a user's last N submitted reports (for the /history command).
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/history/<int:telegram_id>', methods=['GET'])
def get_history(telegram_id):
    limit   = min(20, int(request.args.get('limit', 5)))
    entries = BotHistory.query.filter_by(telegram_id=telegram_id)\
                .order_by(BotHistory.submitted_at.desc())\
                .limit(limit).all()

    return jsonify({
        'data':  [e.to_dict() for e in entries],
        'total': len(entries),
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/bot/history
# Save a report submission to the user's history.
# Called after a successful POST /api/scams from the bot.
#
# Body: { telegram_id, indicator, scam_type, report_id, username?, first_name? }
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/history', methods=['POST'])
def save_history():
    data        = request.get_json(silent=True) or {}
    telegram_id = data.get('telegram_id')
    indicator   = data.get('indicator')

    if not telegram_id or not indicator:
        return jsonify({'error': 'telegram_id and indicator are required'}), 400

    # Ensure user exists
    get_or_create_user(
        telegram_id = int(telegram_id),
        username    = data.get('username'),
        first_name  = data.get('first_name'),
    )

    # Look up the scam record if report_id provided
    scam_id = None
    if data.get('report_id'):
        scam = Scam.query.filter_by(report_id=data['report_id']).first()
        if scam:
            scam_id = scam.id

    entry = BotHistory(
        telegram_id = int(telegram_id),
        indicator   = indicator,
        scam_type   = data.get('scam_type'),
        scam_id     = scam_id,
        report_id   = data.get('report_id'),
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({'success': True, 'entry': entry.to_dict()}), 201


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/bot/log-check
# Log a /check query or auto-scan result.
#
# Body: {
#   telegram_id?,   (null if group scan with no user context)
#   indicator,
#   result,         'scam' | 'clean' | 'not_found'
#   source,         'command' | 'autoscan'
#   chat_type,      'private' | 'group'
#   username?,
#   first_name?
# }
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/log-check', methods=['POST'])
def log_check():
    data        = request.get_json(silent=True) or {}
    telegram_id = data.get('telegram_id')
    indicator   = data.get('indicator', '').strip()

    if not indicator:
        return jsonify({'error': 'indicator is required'}), 400

    # Register user if telegram_id provided
    if telegram_id:
        get_or_create_user(
            telegram_id = int(telegram_id),
            username    = data.get('username'),
            first_name  = data.get('first_name'),
        )

    log = BotCheckLog(
        telegram_id = int(telegram_id) if telegram_id else None,
        indicator   = indicator,
        result      = data.get('result', 'not_found'),
        source      = data.get('source', 'command'),
        chat_type   = data.get('chat_type', 'private'),
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({'success': True}), 201


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/bot/group
# Register or update a group chat the bot is active in.
# Body: { chat_id, chat_title? }
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/group', methods=['POST'])
def register_group():
    data     = request.get_json(silent=True) or {}
    chat_id  = data.get('chat_id')
    if not chat_id:
        return jsonify({'error': 'chat_id is required'}), 400

    group = BotGroupChat.query.filter_by(chat_id=int(chat_id)).first()
    if not group:
        group = BotGroupChat(
            chat_id    = int(chat_id),
            chat_title = data.get('chat_title'),
            is_active  = True,
        )
        db.session.add(group)
    else:
        group.is_active  = True
        if data.get('chat_title'):
            group.chat_title = data.get('chat_title')

    db.session.commit()
    return jsonify({'success': True, 'group': group.to_dict()}), 200


# ─────────────────────────────────────────────────────────────────────────────
# PATCH /api/bot/group/<chat_id>/alert
# Increment alert count when bot sends a scam alert in a group.
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/group/<int:chat_id>/alert', methods=['PATCH'])
def record_alert(chat_id):
    group = BotGroupChat.query.filter_by(chat_id=chat_id).first()
    if group:
        group.alerts_sent += 1
        group.last_alert   = datetime.utcnow()
        db.session.commit()
    return jsonify({'success': True}), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/bot/stats
# Quick stats for the /status command in the bot.
# ─────────────────────────────────────────────────────────────────────────────
@bot_bp.route('/stats', methods=['GET'])
def bot_stats():
    from models import Scam
    from sqlalchemy import func

    today = datetime.utcnow().date()

    return jsonify({
        'total_users':       BotUser.query.count(),
        'total_reports':     BotHistory.query.count(),
        'total_checks':      BotCheckLog.query.count(),
        'active_groups':     BotGroupChat.query.filter_by(is_active=True).count(),
        'checks_today':      BotCheckLog.query.filter(
                                 func.date(BotCheckLog.checked_at) == today
                             ).count(),
        'scam_hits_today':   BotCheckLog.query.filter(
                                 BotCheckLog.result == 'scam',
                                 func.date(BotCheckLog.checked_at) == today
                             ).count(),
        'db_total':          Scam.query.filter(Scam.status != 'removed').count(),
        'db_verified':       Scam.query.filter_by(status='verified').count(),
    }), 200
