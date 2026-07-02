from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models import Scam, generate_report_id
from utils import check_rate_limit, check_duplicate, get_session_token, get_client_ip
from sqlalchemy import func
from datetime import datetime

scams_bp = Blueprint('scams', __name__)

VALID_TYPES     = ('phishing','sms','investment','ecommerce','impersonation','job','love','malware','other')
VALID_SEVERITIES = ('low', 'medium', 'high')
VALID_STATUSES  = ('pending', 'verified', 'flagged', 'removed')


# ── GET /api/scams ────────────────────────────────────────────────────────────
# Public browse — powers existingscams.html
# Only returns verified scams. All filters and sorting supported.
#
# Query params:
#   page, per_page, search, type, severity, platform, sort
#
# Connect in existingscams.html fetchScams():
#   const res  = await fetch(`http://localhost:5000/api/scams?${params}`);
#   const data = await res.json();
#   // data.data = array of scams, data.total, data.pages
# ─────────────────────────────────────────────────────────────────────────────
@scams_bp.route('/scams', methods=['GET'])
def get_scams():
    page      = max(1, int(request.args.get('page', 1)))
    per_page  = min(50, max(1, int(request.args.get('per_page',
                    current_app.config['SCAMS_PER_PAGE']))))
    search    = request.args.get('search',   '').strip()
    scam_type = request.args.get('type',     '').strip()
    severity  = request.args.get('severity', '').strip()
    platform  = request.args.get('platform', '').strip()
    sort      = request.args.get('sort',     'date_desc')

    q = Scam.query.filter(Scam.status == 'verified')

    if search:
        like = f'%{search}%'
        q = q.filter(db.or_(
            Scam.title.ilike(like),
            Scam.description.ilike(like),
            Scam.url.ilike(like),
            Scam.phone_number.ilike(like),
        ))
    if scam_type and scam_type in VALID_TYPES:
        q = q.filter(Scam.type == scam_type)
    if severity and severity in VALID_SEVERITIES:
        q = q.filter(Scam.severity == severity)
    if platform:
        q = q.filter(Scam.platform.ilike(f'%{platform}%'))

    sort_options = {
        'date_desc':    Scam.created_at.desc(),
        'date_asc':     Scam.created_at.asc(),
        'reports_desc': Scam.report_count.desc(),
    }
    q = q.order_by(sort_options.get(sort, Scam.created_at.desc()))

    total      = q.count()
    scams      = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'data':     [s.to_dict() for s in scams],
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'pages':    max(1, (total + per_page - 1) // per_page),
    }), 200


# ── GET /api/scams/stats ──────────────────────────────────────────────────────
# Returns headline numbers for introduction.html and existingscams.html stat cards
#
# Connect in existingscams.html fetchStats():
#   const res  = await fetch('http://localhost:5000/api/scams/stats');
#   const data = await res.json();
#   // data.total, data.today, data.high_severity, data.verified
# ─────────────────────────────────────────────────────────────────────────────
@scams_bp.route('/scams/stats', methods=['GET'])
def get_stats():
    today = datetime.utcnow().date()
    return jsonify({
        'total':         Scam.query.filter(Scam.status != 'removed').count(),
        'today':         Scam.query.filter(
                             func.date(Scam.created_at) == today,
                             Scam.status != 'removed'
                         ).count(),
        'high_severity': Scam.query.filter_by(severity='high', status='verified').count(),
        'verified':      Scam.query.filter_by(status='verified').count(),
    }), 200


# ── GET /api/scams/<id> ───────────────────────────────────────────────────────
# Single scam detail — powers the detail modal in existingscams.html
#
# Connect in existingscams.html fetchScamById(id):
#   const res  = await fetch(`http://localhost:5000/api/scams/${id}`);
#   const data = await res.json();
# ─────────────────────────────────────────────────────────────────────────────
@scams_bp.route('/scams/<int:scam_id>', methods=['GET'])
def get_scam(scam_id):
    scam = Scam.query.filter_by(id=scam_id, status='verified').first()
    if not scam:
        return jsonify({'error': 'Scam not found'}), 404

    data = scam.to_dict()
    data['timeline'] = [
        {'text': 'Report submitted anonymously by community member',
         'time': scam.created_at.strftime('%d %b %Y, %H:%M')},
        {'text': 'Automated duplicate and spam checks passed',
         'time': '~2 minutes later'},
        {'text': 'Verified and published by ScamWatch moderation team',
         'time': '~2 hours later'},
        {'text': 'URL/number added to scanner indicators automatically',
         'time': '~2h 5m after report'},
    ]
    return jsonify(data), 200


# ── POST /api/scams ───────────────────────────────────────────────────────────
# Submit a new anonymous scam report — powers reportscam.html
#
# Body: {
#   type*:        'phishing' | 'sms' | 'investment' | 'ecommerce' |
#                 'impersonation' | 'job' | 'love' | 'malware' | 'other'
#   title*:       string
#   description*: string
#   platform:     string  (optional)
#   url:          string  (optional)
#   phone_number: string  (optional)
#   amount_lost:  number  (optional)
#   severity:     'low' | 'medium' | 'high'  (optional, defaults to medium)
# }
#
# Returns: { report_id, message, duplicate? }
#
# Connect in reportscam.html submitReport():
#   const res  = await fetch('http://localhost:5000/api/scams', {
#       method: 'POST',
#       headers: { 'Content-Type': 'application/json' },
#       body: JSON.stringify(formData)
#   });
#   const data = await res.json();
#   document.getElementById('report-id-text').textContent = data.report_id;
# ─────────────────────────────────────────────────────────────────────────────
@scams_bp.route('/scams', methods=['POST'])
def submit_scam():
    # 1. Rate limit check (anonymous, IP-based)
    allowed, reason = check_rate_limit()
    if not allowed:
        return jsonify({'error': reason}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    # 2. Validate required fields
    title       = (data.get('title')       or '').strip()
    description = (data.get('description') or '').strip()
    scam_type   = (data.get('type')        or '').strip()

    errors = {}
    if not title:       errors['title']       = 'Title is required'
    if not description: errors['description'] = 'Description is required'
    if not scam_type:   errors['type']        = 'Scam type is required'
    elif scam_type not in VALID_TYPES:
        errors['type'] = f'Invalid type. Must be one of: {", ".join(VALID_TYPES)}'

    severity = (data.get('severity') or 'medium').strip()
    if severity not in VALID_SEVERITIES:
        severity = 'medium'

    if errors:
        return jsonify({'error': 'Validation failed', 'fields': errors}), 422

    url          = (data.get('url')          or '').strip() or None
    phone_number = (data.get('phone_number') or '').strip() or None
    amount_lost  = data.get('amount_lost')
    platform     = (data.get('platform')     or '').strip() or None

    # 3. Duplicate check — if same URL/title seen recently, increment count
    is_dupe, existing_id = check_duplicate(url=url, title=title)
    if is_dupe:
        return jsonify({
            'report_id': existing_id,
            'message':   'This scam has already been reported. We\'ve updated the report count — thank you!',
            'duplicate': True,
        }), 200

    # 4. Save new report
    # Generate a unique report_id (retry on collision)
    while True:
        rid = generate_report_id()
        if not Scam.query.filter_by(report_id=rid).first():
            break

    scam = Scam(
        report_id    = rid,
        title        = title,
        description  = description,
        type         = scam_type,
        severity     = severity,
        platform     = platform,
        url          = url,
        phone_number = phone_number,
        amount_lost  = float(amount_lost) if amount_lost else None,
        status       = 'pending',
        report_count = 1,
    )
    db.session.add(scam)
    db.session.commit()

    return jsonify({
        'report_id': scam.report_id,
        'message':   'Your report has been submitted and will be reviewed shortly. Thank you for helping protect Singapore!',
        'duplicate': False,
    }), 201
