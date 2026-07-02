from flask import Blueprint, request, jsonify
from models import (Scam, Admin, AuditLog, SpamSession,
                    ScannerIndicator, RateLimitRule, SiteSetting)
from database import db
from routes import require_admin, require_super_admin
from datetime import datetime, timedelta
import bcrypt

admin_bp = Blueprint('admin', __name__)

# ─────────────────────────────────────────────────────────────
# DASHBOARD STATS
# ─────────────────────────────────────────────────────────────
# GET /api/admin/stats
@admin_bp.route('/stats', methods=['GET'])
@require_admin
def get_admin_stats():
    today = datetime.utcnow().date()
    return jsonify({
        'total_reports':   Scam.query.count(),
        'today':           Scam.query.filter(
                               db.func.date(Scam.created_at) == today).count(),
        'pending':         Scam.query.filter_by(status='pending').count(),
        'flagged':         Scam.query.filter_by(status='flagged').count(),
        'verified':        Scam.query.filter_by(status='verified').count(),
        'removed':         Scam.query.filter_by(status='removed').count(),
        'spam_blocked':    SpamSession.query.filter_by(is_blocked=True).filter(
                               SpamSession.created_at >= datetime.utcnow()
                                   - timedelta(hours=24)).count(),
        'indicator_count': ScannerIndicator.query.count(),
    }), 200

# ─────────────────────────────────────────────────────────────
# SCAM REPORTS
# ─────────────────────────────────────────────────────────────
# GET /api/admin/reports
@admin_bp.route('/reports', methods=['GET'])
@require_admin
def get_reports():
    page      = int(request.args.get('page', 1))
    per_page  = int(request.args.get('per_page', 12))
    search    = request.args.get('search', '')
    status    = request.args.get('status', '')
    scam_type = request.args.get('type', '')
    severity  = request.args.get('severity', '')
    sort      = request.args.get('sort', 'date_desc')

    q = Scam.query
    if search:
        q = q.filter(db.or_(
            Scam.title.ilike(f'%{search}%'),
            Scam.report_id.ilike(f'%{search}%'),
            Scam.url.ilike(f'%{search}%')
        ))
    if status:    q = q.filter(Scam.status   == status)
    if scam_type: q = q.filter(Scam.type     == scam_type)
    if severity:  q = q.filter(Scam.severity == severity)

    sort_map = {
        'date_desc':    Scam.created_at.desc(),
        'date_asc':     Scam.created_at.asc(),
        'reports_desc': Scam.report_count.desc(),
    }
    q = q.order_by(sort_map.get(sort, Scam.created_at.desc()))

    pag = q.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'data':     [s.to_dict(full=True) for s in pag.items],
        'total':    pag.total,
        'page':     page,
        'per_page': per_page,
        'pages':    pag.pages,
    }), 200

# GET /api/admin/reports/<id>
@admin_bp.route('/reports/<int:id>', methods=['GET'])
@require_admin
def get_report(id):
    scam = Scam.query.get_or_404(id)
    return jsonify(scam.to_dict(full=True)), 200

# PATCH /api/admin/reports/<id>
# Body: { status, severity, admin_notes }  — any subset
@admin_bp.route('/reports/<int:id>', methods=['PATCH'])
@require_admin
def update_report(id):
    scam = Scam.query.get_or_404(id)
    data = request.get_json()
    old_status = scam.status

    if 'status'      in data: scam.status      = data['status']
    if 'severity'    in data: scam.severity     = data['severity']
    if 'admin_notes' in data: scam.admin_notes  = data['admin_notes']
    scam.updated_at = datetime.utcnow()

    # Auto-add to scanner indicators when verifying a scam with URL/phone
    if data.get('status') == 'verified' and old_status != 'verified':
        _auto_add_indicators(scam)

    db.session.commit()
    _log(request.admin_id, 'Updated', 'scam', scam.id, scam.report_id,
         f"Status → {scam.status}")
    return jsonify(scam.to_dict(full=True)), 200

# DELETE /api/admin/reports/<id>  — hard delete
@admin_bp.route('/reports/<int:id>', methods=['DELETE'])
@require_super_admin
def delete_report(id):
    scam = Scam.query.get_or_404(id)
    ref  = scam.report_id
    db.session.delete(scam)
    db.session.commit()
    _log(request.admin_id, 'Deleted', 'scam', id, ref, 'Hard deleted')
    return jsonify({'message': f'{ref} permanently deleted'}), 200

# POST /api/admin/reports/bulk
# Body: { ids: [1,2,3], action: 'verify'|'flag'|'remove' }
@admin_bp.route('/reports/bulk', methods=['POST'])
@require_admin
def bulk_action():
    data   = request.get_json()
    ids    = data.get('ids', [])
    action = data.get('action')
    status_map = {'verify': 'verified', 'flag': 'flagged', 'remove': 'removed'}

    if action not in status_map:
        return jsonify({'error': 'Invalid action'}), 400

    scams = Scam.query.filter(Scam.id.in_(ids)).all()
    for scam in scams:
        scam.status     = status_map[action]
        scam.updated_at = datetime.utcnow()
        if action == 'verify':
            _auto_add_indicators(scam)

    db.session.commit()
    _log(request.admin_id, f'Bulk {action}', 'scam', None,
         f'{len(scams)} reports', f'Bulk action on {len(scams)} reports')
    return jsonify({'updated': len(scams)}), 200

# ─────────────────────────────────────────────────────────────
# SPAM & ABUSE
# ─────────────────────────────────────────────────────────────
# GET /api/admin/spam
@admin_bp.route('/spam', methods=['GET'])
@require_admin
def get_spam():
    sessions = SpamSession.query.order_by(
        SpamSession.created_at.desc()).limit(50).all()
    return jsonify([s.to_dict() for s in sessions]), 200

# DELETE /api/admin/spam/<id>  — dismiss a spam session
@admin_bp.route('/spam/<int:id>', methods=['DELETE'])
@require_admin
def dismiss_spam(id):
    s = SpamSession.query.get_or_404(id)
    db.session.delete(s)
    db.session.commit()
    return jsonify({'message': 'Spam session dismissed'}), 200

# POST /api/admin/spam/<id>/block  — mark IP as blocked
@admin_bp.route('/spam/<int:id>/block', methods=['POST'])
@require_admin
def block_spam_ip(id):
    s = SpamSession.query.get_or_404(id)
    s.is_blocked = True
    db.session.commit()
    _log(request.admin_id, 'Blocked IP', 'spam_session', id,
         s.ip_address, 'IP blocked from submissions')
    return jsonify({'message': 'IP blocked'}), 200

# DELETE /api/admin/spam  — clear ALL spam sessions
@admin_bp.route('/spam', methods=['DELETE'])
@require_super_admin
def clear_all_spam():
    count = SpamSession.query.delete()
    db.session.commit()
    return jsonify({'deleted': count}), 200

# ─────────────────────────────────────────────────────────────
# ADMIN ACCOUNTS
# ─────────────────────────────────────────────────────────────
# GET /api/admin/admins
@admin_bp.route('/admins', methods=['GET'])
@require_admin
def get_admins():
    admins = Admin.query.order_by(Admin.created_at).all()
    return jsonify([a.to_dict() for a in admins]), 200

# POST /api/admin/admins
# Body: { name, email, password, role }
@admin_bp.route('/admins', methods=['POST'])
@require_super_admin
def add_admin():
    data = request.get_json()
    if Admin.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409

    hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    admin  = Admin(name=data['name'], email=data['email'],
                   password=hashed, role=data.get('role', 'moderator'))
    db.session.add(admin)
    db.session.commit()
    _log(request.admin_id, 'Added Admin', 'admin', admin.id,
         admin.email, f"Role: {admin.role}")
    return jsonify(admin.to_dict()), 201

# PATCH /api/admin/admins/<id>
# Body: { role }
@admin_bp.route('/admins/<int:id>', methods=['PATCH'])
@require_super_admin
def update_admin(id):
    admin = Admin.query.get_or_404(id)
    data  = request.get_json()
    if 'role' in data:
        admin.role = data['role']
    db.session.commit()
    _log(request.admin_id, 'Updated Admin', 'admin', id,
         admin.email, f"Role → {admin.role}")
    return jsonify(admin.to_dict()), 200

# DELETE /api/admin/admins/<id>
@admin_bp.route('/admins/<int:id>', methods=['DELETE'])
@require_super_admin
def remove_admin(id):
    if id == request.admin_id:
        return jsonify({'error': 'Cannot remove your own account'}), 400
    admin = Admin.query.get_or_404(id)
    ref   = admin.email
    db.session.delete(admin)
    db.session.commit()
    _log(request.admin_id, 'Removed Admin', 'admin', id, ref, 'Account deleted')
    return jsonify({'message': f'{ref} removed'}), 200

# ─────────────────────────────────────────────────────────────
# SCANNER INDICATORS
# ─────────────────────────────────────────────────────────────
# GET /api/admin/indicators
@admin_bp.route('/indicators', methods=['GET'])
@require_admin
def get_indicators():
    ind_type = request.args.get('type', '')
    source   = request.args.get('source', '')
    search   = request.args.get('search', '')

    q = ScannerIndicator.query
    if ind_type: q = q.filter(ScannerIndicator.type   == ind_type)
    if source:   q = q.filter(ScannerIndicator.source == source)
    if search:   q = q.filter(ScannerIndicator.value.ilike(f'%{search}%'))

    items = q.order_by(ScannerIndicator.created_at.desc()).all()
    return jsonify([i.to_dict() for i in items]), 200

# POST /api/admin/indicators
# Body: { value, type, scam_id (optional) }
@admin_bp.route('/indicators', methods=['POST'])
@require_admin
def add_indicator():
    data = request.get_json()
    if not data.get('value') or not data.get('type'):
        return jsonify({'error': 'value and type are required'}), 400

    ind = ScannerIndicator(
        value    = data['value'].strip(),
        type     = data['type'],
        scam_id  = data.get('scam_id'),
        source   = 'manual',
        added_by = request.admin_id
    )
    db.session.add(ind)
    db.session.commit()
    _log(request.admin_id, 'Added Indicator', 'indicator', ind.id,
         ind.value, f"Manual — {ind.type}")
    return jsonify(ind.to_dict()), 201

# DELETE /api/admin/indicators/<id>
@admin_bp.route('/indicators/<int:id>', methods=['DELETE'])
@require_admin
def remove_indicator(id):
    ind = ScannerIndicator.query.get_or_404(id)
    ref = ind.value
    db.session.delete(ind)
    db.session.commit()
    _log(request.admin_id, 'Removed Indicator', 'indicator', id,
         ref, 'Removed from scanner')
    return jsonify({'message': f'{ref} removed from scanner'}), 200

# ─────────────────────────────────────────────────────────────
# RATE LIMIT RULES
# ─────────────────────────────────────────────────────────────
# GET /api/admin/rate-rules
@admin_bp.route('/rate-rules', methods=['GET'])
@require_admin
def get_rate_rules():
    rules = RateLimitRule.query.all()
    return jsonify([r.to_dict() for r in rules]), 200

# PATCH /api/admin/rate-rules
# Body: { max_per_hour: 5, cooldown_minutes: 60, ... }
@admin_bp.route('/rate-rules', methods=['PATCH'])
@require_super_admin
def update_rate_rules():
    data = request.get_json()
    for key, val in data.items():
        rule = RateLimitRule.query.filter_by(rule_key=key).first()
        if rule:
            rule.rule_value = int(val)
    db.session.commit()
    _log(request.admin_id, 'Updated Rate Rules', 'settings', None,
         'rate_limit_rules', str(data))
    return jsonify({'message': 'Rules updated'}), 200

# ─────────────────────────────────────────────────────────────
# SITE SETTINGS
# ─────────────────────────────────────────────────────────────
# GET /api/admin/settings
@admin_bp.route('/settings', methods=['GET'])
@require_admin
def get_settings():
    settings = SiteSetting.query.all()
    return jsonify({s.setting_key: s.setting_value for s in settings}), 200

# PATCH /api/admin/settings
# Body: { site_name: '...', admin_email: '...', ... }
@admin_bp.route('/settings', methods=['PATCH'])
@require_super_admin
def update_settings():
    data = request.get_json()
    for key, val in data.items():
        setting = SiteSetting.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = str(val)
    db.session.commit()
    _log(request.admin_id, 'Updated Settings', 'settings', None,
         'site_settings', str(list(data.keys())))
    return jsonify({'message': 'Settings saved'}), 200

# ─────────────────────────────────────────────────────────────
# ANALYTICS
# ─────────────────────────────────────────────────────────────
# GET /api/admin/analytics
@admin_bp.route('/analytics', methods=['GET'])
@require_admin
def get_analytics():
    # Top scam types
    types = db.session.query(
        Scam.type, db.func.count(Scam.id).label('count')
    ).filter(Scam.status == 'verified').group_by(Scam.type)\
     .order_by(db.desc('count')).all()

    # Top platforms
    platforms = db.session.query(
        Scam.platform, db.func.count(Scam.id).label('count')
    ).filter(Scam.status == 'verified', Scam.platform != None)\
     .group_by(Scam.platform).order_by(db.desc('count')).all()

    total_verified = Scam.query.filter_by(status='verified').count()
    total_all      = Scam.query.count()

    return jsonify({
        'verification_rate': round(total_verified / total_all * 100, 1)
                             if total_all else 0,
        'active_threats':    Scam.query.filter_by(status='verified',
                                                  severity='high').count(),
        'scanner_lookups':   db.session.query(
                                 db.func.sum(ScannerIndicator.hit_count)
                             ).scalar() or 0,
        'top_types':    [{'type': t, 'count': c} for t, c in types],
        'top_platforms':[{'platform': p or 'Unknown', 'count': c}
                         for p, c in platforms],
    }), 200

# ─────────────────────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────────────────────
# GET /api/admin/audit-log
@admin_bp.route('/audit-log', methods=['GET'])
@require_admin
def get_audit_log():
    page = int(request.args.get('page', 1))
    logs = AuditLog.query.order_by(AuditLog.created_at.desc())\
                   .paginate(page=page, per_page=50, error_out=False)
    return jsonify({
        'data':  [l.to_dict() for l in logs.items],
        'total': logs.total,
        'pages': logs.pages,
    }), 200

# ─────────────────────────────────────────────────────────────
# DANGER ZONE
# ─────────────────────────────────────────────────────────────
# DELETE /api/admin/purge/removed
@admin_bp.route('/purge/removed', methods=['DELETE'])
@require_super_admin
def purge_removed():
    count = Scam.query.filter_by(status='removed').delete()
    db.session.commit()
    _log(request.admin_id, 'Purged Removed', 'scam', None,
         f'{count} reports', 'Danger zone: purge removed')
    return jsonify({'deleted': count}), 200

# DELETE /api/admin/purge/pending
@admin_bp.route('/purge/pending', methods=['DELETE'])
@require_super_admin
def purge_pending():
    count = Scam.query.filter_by(status='pending').delete()
    db.session.commit()
    _log(request.admin_id, 'Cleared Pending', 'scam', None,
         f'{count} reports', 'Danger zone: clear pending queue')
    return jsonify({'deleted': count}), 200

# ─────────────────────────────────────────────────────────────
# HELPERS (internal)
# ─────────────────────────────────────────────────────────────
def _log(admin_id, action, target_type, target_id, target_ref, detail=''):
    log = AuditLog(admin_id=admin_id, action=action,
                   target_type=target_type, target_id=target_id,
                   target_ref=target_ref, detail=detail)
    db.session.add(log)
    db.session.commit()

def _auto_add_indicators(scam):
    """Auto-add URL/phone to scanner_indicators when a report is verified."""
    if scam.url:
        exists = ScannerIndicator.query.filter_by(
            value=scam.url, type='URL').first()
        if not exists:
            ind = ScannerIndicator(value=scam.url, type='URL',
                                   scam_id=scam.id, source='auto')
            db.session.add(ind)

    if scam.phone_number:
        exists = ScannerIndicator.query.filter_by(
            value=scam.phone_number, type='Phone').first()
        if not exists:
            ind = ScannerIndicator(value=scam.phone_number, type='Phone',
                                   scam_id=scam.id, source='auto')
            db.session.add(ind)
