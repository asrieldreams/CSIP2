from flask import Blueprint, request, jsonify, current_app
from models import Scam, SpamSession, RateLimitRule, generate_report_id
from database import db
from datetime import datetime, timedelta
import hashlib, re

scams_bp = Blueprint('scams', __name__)

# ── GET /api/scams ────────────────────────────────────────────
# Used by: existingscams.html — browse all verified scams
# Query params: page, per_page, search, type, severity, status, platform, sort
@scams_bp.route('/scams', methods=['GET'])
def get_scams():
    page     = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page',
                   current_app.config['SCAMS_PER_PAGE']))
    search   = request.args.get('search', '').strip()
    scam_type = request.args.get('type', '')
    severity  = request.args.get('severity', '')
    status    = request.args.get('status', '')
    platform  = request.args.get('platform', '')
    sort      = request.args.get('sort', 'date_desc')

    # Public endpoint — only show verified scams unless status explicitly set
    if not status:
        status = 'verified'

    q = Scam.query

    if status:
        q = q.filter(Scam.status == status)
    if search:
        q = q.filter(
            db.or_(
                Scam.title.ilike(f'%{search}%'),
                Scam.description.ilike(f'%{search}%'),
                Scam.url.ilike(f'%{search}%'),
                Scam.phone_number.ilike(f'%{search}%')
            )
        )
    if scam_type:
        q = q.filter(Scam.type == scam_type)
    if severity:
        q = q.filter(Scam.severity == severity)
    if platform:
        q = q.filter(Scam.platform == platform)

    # Sorting
    sort_map = {
        'date_desc':     Scam.created_at.desc(),
        'date_asc':      Scam.created_at.asc(),
        'severity_desc': db.case(
            {'high': 3, 'medium': 2, 'low': 1}, value=Scam.severity
        ).desc(),
        'reports_desc':  Scam.report_count.desc(),
    }
    q = q.order_by(sort_map.get(sort, Scam.created_at.desc()))

    pagination = q.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'data':     [s.to_dict() for s in pagination.items],
        'total':    pagination.total,
        'page':     page,
        'per_page': per_page,
        'pages':    pagination.pages,
    }), 200

# ── GET /api/scams/stats ──────────────────────────────────────
# Used by: introduction.html hero stats + existingscams.html header
@scams_bp.route('/scams/stats', methods=['GET'])
def get_stats():
    today = datetime.utcnow().date()
    return jsonify({
        'total':         Scam.query.count(),
        'today':         Scam.query.filter(
                             db.func.date(Scam.created_at) == today).count(),
        'high_severity': Scam.query.filter_by(severity='high').count(),
        'verified':      Scam.query.filter_by(status='verified').count(),
        'pending':       Scam.query.filter_by(status='pending').count(),
        'flagged':       Scam.query.filter_by(status='flagged').count(),
    }), 200

# ── GET /api/scams/<id> ───────────────────────────────────────
# Used by: existingscams.html detail modal
@scams_bp.route('/scams/<int:id>', methods=['GET'])
def get_scam(id):
    scam = Scam.query.get_or_404(id)
    data = scam.to_dict()
    data['timeline'] = [
        {'text': f'Report submitted by community member',
         'time': scam.created_at.strftime('%d %b %Y, %H:%M')},
        {'text': 'Automated scan flagged as suspicious',
         'time': '~5 min later'},
        {'text': f'Status: <strong>{scam.status}</strong>',
         'time': scam.updated_at.strftime('%d %b %Y, %H:%M')
                 if scam.updated_at else '—'},
    ]
    return jsonify(data), 200

# ── POST /api/scams ───────────────────────────────────────────
# Used by: reportscam.html form submission
# Body: { title, description, type, severity, platform, url,
#         phone_number, amount_lost, session_token }
@scams_bp.route('/scams', methods=['POST'])
def submit_scam():
    data  = request.get_json()
    ip    = request.remote_addr
    token = data.get('session_token') or hashlib.sha256(ip.encode()).hexdigest()

    # ── Rate limit check ──────────────────────────────────────
    rule_hour    = RateLimitRule.query.filter_by(rule_key='max_per_hour').first()
    rule_captcha = RateLimitRule.query.filter_by(rule_key='captcha_after').first()
    max_per_hour = rule_hour.rule_value    if rule_hour    else 5
    captcha_after = rule_captcha.rule_value if rule_captcha else 3

    cutoff = datetime.utcnow() - timedelta(hours=1)
    recent_count = SpamSession.query.filter(
        SpamSession.session_token == token,
        SpamSession.created_at >= cutoff
    ).count()

    if recent_count >= max_per_hour:
        spam = SpamSession(
            session_token=token, ip_address=ip,
            reason=f'{recent_count + 1} submissions in 1 hour (rate limit hit)',
            submit_count=recent_count + 1, is_blocked=True
        )
        db.session.add(spam)
        db.session.commit()
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

    # ── Duplicate check ───────────────────────────────────────
    rule_dupe = RateLimitRule.query.filter_by(rule_key='dupe_window_hours').first()
    dupe_hours = rule_dupe.rule_value if rule_dupe else 24
    dupe_cutoff = datetime.utcnow() - timedelta(hours=dupe_hours)

    if data.get('url'):
        existing = Scam.query.filter(
            Scam.url == data['url'],
            Scam.created_at >= dupe_cutoff
        ).first()
        if existing:
            existing.report_count += 1
            db.session.commit()
            return jsonify({
                'message': 'Duplicate report detected — report count updated.',
                'report_id': existing.report_id
            }), 200

    # ── Validate required fields ──────────────────────────────
    required = ['title', 'description', 'type']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Missing required field: {field}'}), 400

    # ── Create the scam report ────────────────────────────────
    scam = Scam(
        report_id    = generate_report_id(),
        title        = data['title'].strip(),
        description  = data['description'].strip(),
        type         = data['type'],
        severity     = data.get('severity', 'medium'),
        status       = 'pending',
        platform     = data.get('platform'),
        url          = data.get('url'),
        phone_number = data.get('phone_number'),
        amount_lost  = data.get('amount_lost') or None,
    )
    db.session.add(scam)

    # ── Log session for anti-spam tracking ───────────────────
    if recent_count >= captcha_after - 1:
        spam = SpamSession(
            session_token=token, ip_address=ip,
            reason=f'Reached captcha threshold ({captcha_after} submissions)',
            submit_count=recent_count + 1
        )
        db.session.add(spam)

    db.session.commit()

    # ── Auto-verify if report_count threshold met ─────────────
    rule_verify = RateLimitRule.query.filter_by(
        rule_key='auto_verify_threshold').first()
    if rule_verify and scam.report_count >= rule_verify.rule_value:
        scam.status = 'verified'
        db.session.commit()

    return jsonify({
        'message':   'Report submitted successfully.',
        'report_id': scam.report_id
    }), 201
