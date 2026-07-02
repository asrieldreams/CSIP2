from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from sqlalchemy import func
from datetime import datetime, timedelta
from extensions import db
from models import (Scam, ScannerIndicator, Admin, SpamSession,
                    RateLimitRule, SiteSetting, AuditLog)
from utils import require_admin, require_super_admin, log_audit, auto_add_indicators

admin_bp = Blueprint('admin', __name__)

# All routes in this file require @require_admin.
# Add header: Authorization: Bearer <token>  in every admin fetch() call.
# Token is returned from POST /api/auth/login and stored in localStorage.


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD STATS
# GET /api/admin/stats — powers dashboard stat cards
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/stats', methods=['GET'])
@require_admin
def stats():
    today = datetime.utcnow().date()
    return jsonify({
        'total':        Scam.query.filter(Scam.status != 'removed').count(),
        'pending':      Scam.query.filter_by(status='pending').count(),
        'flagged':      Scam.query.filter_by(status='flagged').count(),
        'verified':     Scam.query.filter_by(status='verified').count(),
        'today':        Scam.query.filter(func.date(Scam.created_at) == today).count(),
        'indicators':   ScannerIndicator.query.count(),
        'spam_blocked': SpamSession.query.filter(
                            func.date(SpamSession.created_at) == today
                        ).count(),
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# SCAM REPORTS — list (all statuses for admin, unlike public which only sees verified)
# GET /api/admin/reports
# Query: page, per_page, status, type, severity, search, sort
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/reports', methods=['GET'])
@require_admin
def get_reports():
    page      = max(1, int(request.args.get('page', 1)))
    per_page  = min(100, max(1, int(request.args.get('per_page', 20))))
    status    = request.args.get('status',   '').strip()
    scam_type = request.args.get('type',     '').strip()
    severity  = request.args.get('severity', '').strip()
    search    = request.args.get('search',   '').strip()
    sort      = request.args.get('sort', 'date_desc')

    q = Scam.query

    if status:
        q = q.filter(Scam.status == status)
    if scam_type:
        q = q.filter(Scam.type == scam_type)
    if severity:
        q = q.filter(Scam.severity == severity)
    if search:
        like = f'%{search}%'
        q = q.filter(db.or_(
            Scam.title.ilike(like),
            Scam.report_id.ilike(like),
            Scam.url.ilike(like),
            Scam.phone_number.ilike(like),
        ))

    sort_options = {
        'date_desc':    Scam.created_at.desc(),
        'date_asc':     Scam.created_at.asc(),
        'reports_desc': Scam.report_count.desc(),
    }
    q = q.order_by(sort_options.get(sort, Scam.created_at.desc()))

    total = q.count()
    scams = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'data':     [s.to_dict(admin=True) for s in scams],
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'pages':    max(1, (total + per_page - 1) // per_page),
    }), 200


# ── PATCH /api/admin/reports/<id> ─────────────────────────────────────────────
# Update a report status/severity/notes — verify, flag, or remove
# Body: { status?, severity?, admin_notes? }
#
# Connect in admindashboard.html quickAction() / actionReport():
#   await fetch(`http://localhost:5000/api/admin/reports/${id}`, {
#       method: 'PATCH',
#       headers: {
#           'Content-Type': 'application/json',
#           'Authorization': `Bearer ${localStorage.getItem('sw_token')}`
#       },
#       body: JSON.stringify({ status: 'verified' })
#   });
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/reports/<int:scam_id>', methods=['PATCH'])
@require_admin
def update_report(scam_id):
    admin = request.current_admin
    scam  = Scam.query.get_or_404(scam_id)
    data  = request.get_json(silent=True) or {}

    old_status = scam.status

    if 'status' in data:
        allowed_statuses = ('pending', 'verified', 'flagged', 'removed')
        if data['status'] not in allowed_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {allowed_statuses}'}), 400
        scam.status = data['status']

    if 'severity' in data:
        if data['severity'] not in ('low', 'medium', 'high'):
            return jsonify({'error': 'Invalid severity'}), 400
        scam.severity = data['severity']

    if 'admin_notes' in data:
        scam.admin_notes = data['admin_notes']

    # When verified for the first time, auto-populate scanner indicators
    if scam.status == 'verified' and old_status != 'verified':
        auto_add_indicators(scam, admin_id=admin.id)

    action = data.get('status', 'Updated').capitalize()
    log_audit(admin.id, action, 'scam', scam.id, scam.report_id, scam.title)
    db.session.commit()

    return jsonify({'success': True, 'scam': scam.to_dict(admin=True)}), 200


# ── DELETE /api/admin/reports/<id> ───────────────────────────────────────────
# Permanently delete a report (and its scanner indicators)
#
# Connect in admindashboard.html deleteReport():
#   await fetch(`http://localhost:5000/api/admin/reports/${id}`, {
#       method: 'DELETE',
#       headers: { 'Authorization': `Bearer ${localStorage.getItem('sw_token')}` }
#   });
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/reports/<int:scam_id>', methods=['DELETE'])
@require_admin
def delete_report(scam_id):
    admin = request.current_admin
    scam  = Scam.query.get_or_404(scam_id)
    ref, title = scam.report_id, scam.title

    db.session.delete(scam)
    log_audit(admin.id, 'Deleted', 'scam', scam_id, ref, title)
    db.session.commit()

    return jsonify({'success': True}), 200


# ── PATCH /api/admin/reports/bulk ────────────────────────────────────────────
# Bulk verify / flag / remove
# Body: { "ids": [1,2,3], "action": "verify" | "flag" | "remove" }
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/reports/bulk', methods=['PATCH'])
@require_admin
def bulk_update():
    admin  = request.current_admin
    data   = request.get_json(silent=True) or {}
    ids    = data.get('ids', [])
    action = data.get('action', '')

    action_map = {'verify': 'verified', 'flag': 'flagged', 'remove': 'removed'}
    if action not in action_map:
        return jsonify({'error': 'Invalid action. Must be verify, flag, or remove'}), 400

    new_status = action_map[action]
    scams      = Scam.query.filter(Scam.id.in_(ids)).all()

    for scam in scams:
        old = scam.status
        scam.status = new_status
        if new_status == 'verified' and old != 'verified':
            auto_add_indicators(scam, admin_id=admin.id)

    log_audit(admin.id, f'Bulk {action.capitalize()}', 'scam', None,
              f'{len(scams)} reports', f'Bulk action')
    db.session.commit()

    return jsonify({'success': True, 'updated': len(scams)}), 200


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER INDICATORS
# GET  /api/admin/indicators        — list all indicators
# POST /api/admin/indicators        — manually add one
# DEL  /api/admin/indicators/<id>   — remove one
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/indicators', methods=['GET'])
@require_admin
def get_indicators():
    ind_type = request.args.get('type',   '').strip()
    source   = request.args.get('source', '').strip()
    search   = request.args.get('search', '').strip()

    q = ScannerIndicator.query

    if ind_type:
        q = q.filter(ScannerIndicator.type == ind_type)
    if source:
        q = q.filter(ScannerIndicator.source == source)
    if search:
        q = q.filter(ScannerIndicator.value.ilike(f'%{search}%'))

    indicators = q.order_by(ScannerIndicator.created_at.desc()).all()
    return jsonify({
        'data':  [i.to_dict() for i in indicators],
        'total': len(indicators),
    }), 200


@admin_bp.route('/indicators', methods=['POST'])
@require_admin
def add_indicator():
    admin = request.current_admin
    data  = request.get_json(silent=True) or {}

    value = (data.get('value') or '').strip()
    if not value:
        return jsonify({'error': 'Value is required'}), 400

    valid_types = ('URL', 'Domain', 'Phone', 'Email Domain')
    ind_type = data.get('type', 'URL')
    if ind_type not in valid_types:
        return jsonify({'error': f'Invalid type. Must be one of: {valid_types}'}), 400

    if ScannerIndicator.query.filter_by(value=value).first():
        return jsonify({'error': 'This indicator already exists'}), 409

    # Optionally link to an existing scam by report_id
    scam_id = None
    if data.get('report_id'):
        scam = Scam.query.filter_by(report_id=data['report_id']).first()
        if scam:
            scam_id = scam.id

    ind = ScannerIndicator(
        value    = value,
        type     = ind_type,
        scam_id  = scam_id,
        source   = 'manual',
        added_by = admin.id,
    )
    db.session.add(ind)
    log_audit(admin.id, 'Added Indicator', 'indicator', None, value,
              f'Manual add — {ind_type}')
    db.session.commit()

    return jsonify({'success': True, 'indicator': ind.to_dict()}), 201


@admin_bp.route('/indicators/<int:ind_id>', methods=['DELETE'])
@require_admin
def delete_indicator(ind_id):
    admin = request.current_admin
    ind   = ScannerIndicator.query.get_or_404(ind_id)
    val   = ind.value

    db.session.delete(ind)
    log_audit(admin.id, 'Removed Indicator', 'indicator', ind_id, val,
              'Removed from scanner')
    db.session.commit()

    return jsonify({'success': True}), 200


# ─────────────────────────────────────────────────────────────────────────────
# SPAM & ABUSE CONTROL
# GET    /api/admin/spam             — list flagged spam sessions
# DELETE /api/admin/spam/<id>        — dismiss a session
# PATCH  /api/admin/spam/<id>/block  — block the IP
# DELETE /api/admin/spam/all         — clear all spam sessions
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/spam', methods=['GET'])
@require_admin
def get_spam():
    sessions = SpamSession.query.order_by(SpamSession.created_at.desc()).limit(100).all()
    return jsonify({'data': [s.to_dict() for s in sessions]}), 200


@admin_bp.route('/spam/<int:session_id>', methods=['DELETE'])
@require_admin
def dismiss_spam(session_id):
    admin   = request.current_admin
    session = SpamSession.query.get_or_404(session_id)
    token   = session.session_token
    db.session.delete(session)
    log_audit(admin.id, 'Dismissed Spam', 'spam_session', session_id, token)
    db.session.commit()
    return jsonify({'success': True}), 200


@admin_bp.route('/spam/<int:session_id>/block', methods=['PATCH'])
@require_admin
def block_ip(session_id):
    admin   = request.current_admin
    session = SpamSession.query.get_or_404(session_id)
    session.is_blocked = True
    log_audit(admin.id, 'Blocked IP', 'spam_session', session_id,
              session.ip_address, 'IP blocked by admin')
    db.session.commit()
    return jsonify({'success': True}), 200


@admin_bp.route('/spam/all', methods=['DELETE'])
@require_admin
def clear_all_spam():
    admin = request.current_admin
    count = SpamSession.query.delete()
    log_audit(admin.id, 'Cleared All Spam', 'spam_session', None,
              f'{count} sessions', 'Admin cleared all spam sessions')
    db.session.commit()
    return jsonify({'success': True, 'deleted': count}), 200


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ACCOUNTS
# GET    /api/admin/admins       — list all admins
# POST   /api/admin/admins       — add a new admin (super_admin only)
# DELETE /api/admin/admins/<id>  — remove an admin (super_admin only)
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/admins', methods=['GET'])
@require_admin
def get_admins():
    admins = Admin.query.order_by(Admin.created_at.asc()).all()
    return jsonify({'data': [a.to_dict() for a in admins]}), 200


@admin_bp.route('/admins', methods=['POST'])
@require_admin
@require_super_admin
def add_admin():
    admin = request.current_admin
    data  = request.get_json(silent=True) or {}

    name  = (data.get('name')     or '').strip()
    email = (data.get('email')    or '').strip().lower()
    pwd   = (data.get('password') or '').strip()
    role  = data.get('role', 'moderator')

    if not name or not email or not pwd:
        return jsonify({'error': 'Name, email, and password are required'}), 400
    if role not in ('super_admin', 'moderator', 'analyst'):
        role = 'moderator'
    if Admin.query.filter_by(email=email).first():
        return jsonify({'error': 'An admin with this email already exists'}), 409

    new_admin = Admin(
        name     = name,
        email    = email,
        password = generate_password_hash(pwd),
        role     = role,
    )
    db.session.add(new_admin)
    log_audit(admin.id, 'Added Admin', 'admin', None, email, f'{name} — {role}')
    db.session.commit()

    return jsonify({'success': True, 'admin': new_admin.to_dict()}), 201


@admin_bp.route('/admins/<int:admin_id>', methods=['DELETE'])
@require_admin
@require_super_admin
def remove_admin(admin_id):
    me = request.current_admin
    if me.id == admin_id:
        return jsonify({'error': 'You cannot remove your own account'}), 400

    target = Admin.query.get_or_404(admin_id)
    log_audit(me.id, 'Removed Admin', 'admin', admin_id, target.email, target.name)
    db.session.delete(target)
    db.session.commit()

    return jsonify({'success': True}), 200


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMIT RULES  (Spam & Abuse Control page)
# GET   /api/admin/rate-rules  — get current rules
# PATCH /api/admin/rate-rules  — update rules
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/rate-rules', methods=['GET'])
@require_admin
def get_rate_rules():
    rules = RateLimitRule.query.all()
    return jsonify({'data': [r.to_dict() for r in rules]}), 200


@admin_bp.route('/rate-rules', methods=['PATCH'])
@require_admin
def update_rate_rules():
    admin = request.current_admin
    data  = request.get_json(silent=True) or {}

    updated = []
    for key, value in data.items():
        rule = RateLimitRule.query.filter_by(rule_key=key).first()
        if rule:
            try:
                rule.rule_value = int(value)
                updated.append(key)
            except (ValueError, TypeError):
                pass

    log_audit(admin.id, 'Updated Rate Rules', 'settings', None, None,
              f'Keys updated: {", ".join(updated)}')
    db.session.commit()

    return jsonify({'success': True, 'updated': updated}), 200


# ─────────────────────────────────────────────────────────────────────────────
# SITE SETTINGS  (Settings page)
# GET   /api/admin/settings  — get all settings
# PATCH /api/admin/settings  — update settings
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/settings', methods=['GET'])
@require_admin
def get_settings():
    settings = SiteSetting.query.all()
    return jsonify({'data': {s.setting_key: s.setting_value for s in settings}}), 200


@admin_bp.route('/settings', methods=['PATCH'])
@require_admin
def update_settings():
    admin = request.current_admin
    data  = request.get_json(silent=True) or {}

    updated = []
    for key, value in data.items():
        setting = SiteSetting.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = str(value)
            updated.append(key)

    log_audit(admin.id, 'Updated Settings', 'settings', None, None,
              f'Keys updated: {", ".join(updated)}')
    db.session.commit()

    return jsonify({'success': True, 'updated': updated}), 200


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT LOG  (Audit Log page)
# GET /api/admin/audit-log?page=1&per_page=50
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/audit-log', methods=['GET'])
@require_admin
def get_audit_log():
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 50))))

    q     = AuditLog.query.order_by(AuditLog.created_at.desc())
    total = q.count()
    logs  = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'data':     [l.to_dict() for l in logs],
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'pages':    max(1, (total + per_page - 1) // per_page),
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# ANALYTICS  (Analytics page)
# GET /api/admin/analytics
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/analytics', methods=['GET'])
@require_admin
def get_analytics():
    week_ago = datetime.utcnow() - timedelta(days=7)

    # Type breakdown (verified only)
    type_counts = db.session.query(
        Scam.type, func.count(Scam.id)
    ).filter(Scam.status == 'verified').group_by(Scam.type).all()

    # Platform breakdown
    platform_counts = db.session.query(
        Scam.platform, func.count(Scam.id)
    ).filter(
        Scam.status == 'verified',
        Scam.platform.isnot(None)
    ).group_by(Scam.platform).order_by(func.count(Scam.id).desc()).limit(8).all()

    total    = Scam.query.filter(Scam.status != 'removed').count()
    verified = Scam.query.filter_by(status='verified').count()
    rate     = round((verified / total * 100) if total else 0, 1)

    return jsonify({
        'weekly_reports':     Scam.query.filter(Scam.created_at >= week_ago).count(),
        'verification_rate':  rate,
        'active_threats':     Scam.query.filter_by(status='verified', severity='high').count(),
        'avg_review_time':    '4.2 min',
        'type_breakdown':     [{'type': t, 'count': c} for t, c in type_counts],
        'platform_breakdown': [{'platform': p or 'Unknown', 'count': c} for p, c in platform_counts],
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# DANGER ZONE  (Settings page — super admin only)
# DELETE /api/admin/purge-removed  — permanently delete all removed reports
# DELETE /api/admin/clear-pending  — delete all unreviewed pending reports
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route('/purge-removed', methods=['DELETE'])
@require_admin
@require_super_admin
def purge_removed():
    admin   = request.current_admin
    removed = Scam.query.filter_by(status='removed').all()
    count   = len(removed)
    for scam in removed:
        db.session.delete(scam)
    log_audit(admin.id, 'Purged Removed Reports', 'scam', None,
              f'{count} records', 'Danger zone — permanent delete')
    db.session.commit()
    return jsonify({'success': True, 'deleted': count}), 200


@admin_bp.route('/clear-pending', methods=['DELETE'])
@require_admin
@require_super_admin
def clear_pending():
    admin   = request.current_admin
    pending = Scam.query.filter_by(status='pending').all()
    count   = len(pending)
    for scam in pending:
        db.session.delete(scam)
    log_audit(admin.id, 'Cleared Pending Queue', 'scam', None,
              f'{count} records', 'Danger zone — queue cleared')
    db.session.commit()
    return jsonify({'success': True, 'deleted': count}), 200
