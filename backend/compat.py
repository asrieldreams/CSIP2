# ============================================================
#  CSIP2 — Scamwatch API Compatibility Layer
#  compat.py — Save in backend/
#  Maps /api/* endpoints to the reports table
# ============================================================

import re
import secrets
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, session
from db import get_connection

compat_bp = Blueprint('compat', __name__)


def normalize_url(indicator: str) -> str:
    """Add http:// prefix if indicator looks like a URL without protocol."""
    indicator = indicator.strip()
    if not indicator:
        return indicator
    # Already has protocol
    if indicator.startswith('http://') or indicator.startswith('https://'):
        return indicator
    # Common patterns that need http://
    prefixes = ['www.', 'bit.ly/', 't.me/', 'wa.me/',
                'tinyurl.com/', 'goo.gl/', 'tiny.cc/']
    for p in prefixes:
        if indicator.lower().startswith(p):
            return 'http://' + indicator
    # Has a dot, no spaces, not email → likely a domain
    if '.' in indicator and ' ' not in indicator and '@' not in indicator:
        return 'http://' + indicator
    return indicator

# ── In-memory token store ──────────────────────────────────
_tokens = {}

# ── Scam type mappings ─────────────────────────────────────
TO_API_TYPE = {
    'Phishing':        'phishing',
    'E-Commerce Scam': 'ecommerce',
    'Impersonation':   'impersonation',
    'Love Scam':       'love',
    'Investment Scam': 'investment',
    'SMS Scam':        'sms',
    'Job Scam':        'job',
    'Others':          'other',
}
FROM_API_TYPE = {v: k for k, v in TO_API_TYPE.items()}

# ── Platform normalization ─────────────────────────────────
PLATFORM_MAP = {
    'whatsapp':      'WhatsApp',
    'telegram':      'Telegram',
    'sms':           'SMS',
    'phone call':    'Phone Call',
    'email':         'Email',
    'facebook':      'Facebook',
    'instagram':     'Instagram',
    'carousell':     'Carousell',
    'lazada / shopee': 'Lazada / Shopee',
    'linkedin':      'LinkedIn',
    'website':       'Website',
    'other':         'Other',
}


def get_token():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


def get_current_admin():
    token = get_token()
    if not token:
        return None
    return _tokens.get(token)


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_admin():
            return jsonify({'error': 'Unauthorised'}), 401
        return f(*args, **kwargs)
    return decorated


def report_to_scam(r):
    """Convert a reports row to scamwatch scam format."""
    ind_type  = r.get('indicator_type', 'url')
    indicator = r.get('indicator', '') or ''
    list_type = r.get('list_type')
    scam_raw  = r.get('scam_type', 'Others') or 'Others'
    submitted = r.get('submitted_at')
    db_status = r.get('status', 'pending')

    # Use stored severity or derive from list_type
    severity = r.get('severity') or ('high' if list_type == 'blacklist' else 'medium')

    # Safe conversions for types that can't be JSON serialized
    try:
        amount = float(r['amount_lost']) if r.get('amount_lost') is not None else None
    except (TypeError, ValueError):
        amount = None

    try:
        inc_date = str(r['incident_date']) if r.get('incident_date') else None
    except Exception:
        inc_date = None

    try:
        created = str(submitted) if submitted else datetime.utcnow().isoformat()
    except Exception:
        created = datetime.utcnow().isoformat()

    return {
        'id':             r['id'],
        'report_id':      f"SS-{str(r['id']).zfill(5)}",
        'title':          f"{scam_raw}: {indicator[:60]}",
        'description':    r.get('description') or f"Reported via {r.get('source','website')}",
        'type':           TO_API_TYPE.get(scam_raw, 'other'),
        'severity':       severity or 'medium',
        # approved+blacklist = verified (confirmed)
        # approved+whitelist = flagged  (suspected)
        'status':         ('verified' if list_type == 'blacklist' else 'flagged')
                          if db_status == 'approved' else
                          'removed' if db_status == 'rejected' else 'pending',
        'platform':       r.get('platform') or r.get('source', 'website'),
        'url':            indicator if ind_type == 'url'   else None,
        'phone_number':   indicator if ind_type == 'phone' else None,
        'amount_lost':    amount,
        'incident_date':  inc_date,
        'report_count':      r.get('report_count') or 1,
        'admin_locked':      bool(r.get('admin_locked', 0)),
        'false_report_count': r.get('false_report_count') or 0,
        'created_at':        created,
        'updated_at':        created,
    }


# ============================================================
#  AUTH
# ============================================================

@compat_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if '@' not in email:
        email = email + '@scamwatch.sg'

    try:
        import bcrypt
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, name, email, password, role FROM admins WHERE email = %s",
                (email,)
            )
            row = cursor.fetchone()

        if not row:
            return jsonify({'error': 'Invalid email or password'}), 401

        if bcrypt.checkpw(password.encode('utf-8'), row['password'].encode('utf-8')):
            token = secrets.token_hex(32)
            admin_data = {
                'id':       row['id'],
                'name':     row['name'],
                'email':    row['email'],
                'role':     row['role'],
                'initials': ''.join(p[0].upper() for p in row['name'].split()[:2]),
            }
            _tokens[token] = admin_data
            session['admin_logged_in'] = True
            session['admin_id']        = row['id']
            session['admin_username']  = row['name']
            return jsonify({'token': token, 'admin': admin_data}), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/auth/me', methods=['GET'])
def api_me():
    admin = get_current_admin()
    if not admin:
        return jsonify({'error': 'Unauthorised'}), 401
    return jsonify(admin), 200


# ============================================================
#  PUBLIC SCAMS
# ============================================================

@compat_bp.route('/api/scams', methods=['GET'])
def api_get_scams():
    page      = max(1, int(request.args.get('page', 1)))
    per_page  = min(50, max(1, int(request.args.get('per_page', 12))))
    search    = request.args.get('search', '').strip()
    scam_type = request.args.get('type', '').strip()
    severity  = request.args.get('severity', '').strip()
    sort      = request.args.get('sort', 'date_desc')

    query  = """SELECT id, indicator_type, indicator, scam_type, description,
                       source, list_type, submitted_at, status,
                       severity, platform, amount_lost, incident_date, report_count
                FROM reports WHERE status = 'approved'"""
    params = []

    if search:
        query += " AND (indicator LIKE %s OR description LIKE %s OR scam_type LIKE %s)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if scam_type and scam_type in FROM_API_TYPE:
        query += " AND scam_type = %s"
        params.append(FROM_API_TYPE[scam_type])

    if severity == 'high':
        query += " AND (severity = 'high' OR list_type = 'blacklist')"
    elif severity == 'medium':
        query += " AND (severity = 'medium' OR list_type = 'whitelist')"
    elif severity == 'low':
        query += " AND severity = 'low'"

    order = "submitted_at DESC"
    if sort == 'date_asc':     order = "submitted_at ASC"
    if sort == 'reports_desc': order = "id DESC"
    query += f" ORDER BY {order}"

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            all_rows = cursor.fetchall()

        total  = len(all_rows)
        pages  = max(1, (total + per_page - 1) // per_page)
        offset = (page - 1) * per_page
        rows   = all_rows[offset:offset + per_page]

        return jsonify({
            'data':     [report_to_scam(r) for r in rows],
            'total':    total,
            'page':     page,
            'per_page': per_page,
            'pages':    pages,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/scams/stats', methods=['GET'])
def api_scams_stats():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved'")
            total = cursor.fetchone()['c']

            # Use list_type for high severity (works even without severity column)
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved' AND list_type = 'blacklist'")
            high = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved'")
            verified = cursor.fetchone()['c']

            today = datetime.utcnow().date()
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE DATE(submitted_at) = %s", (today,))
            today_count = cursor.fetchone()['c']

        return jsonify({
            'total':         total,
            'verified':      verified,
            'high_severity': high,
            'today':         today_count,
        }), 200

    except Exception as e:
        # Return zeros instead of error so frontend doesn't break
        return jsonify({
            'total': 0, 'verified': 0,
            'high_severity': 0, 'today': 0
        }), 200


@compat_bp.route('/api/scams/<int:scam_id>', methods=['GET'])
def api_get_scam(scam_id):
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, indicator_type, indicator, scam_type, description,
                       source, list_type, submitted_at, status,
                       severity, platform, amount_lost, incident_date, report_count, admin_locked, false_report_count
                FROM reports WHERE id = %s
            """, (scam_id,))
            row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(report_to_scam(row)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/scams', methods=['POST'])
def api_submit_scam():
    """Website reportscam.html posts here — saves ALL fields to reports table."""
    data = request.get_json(silent=True) or {}

    # ── Extract all fields from website form ───────────────
    url           = (data.get('url')          or '').strip()
    phone_number  = (data.get('phone_number') or '').strip()
    description   = (data.get('description')  or '').strip()
    api_type      = data.get('type', 'other')
    raw_platform  = (data.get('platform')     or 'website').strip()
    severity      = data.get('severity', 'medium')
    amount_lost   = data.get('amount_lost')
    incident_date = data.get('incident_date') or None

    # Normalize platform name
    platform = PLATFORM_MAP.get(raw_platform.lower(), raw_platform) or 'Website'

    # Normalize severity
    if severity not in ('low', 'medium', 'high'):
        severity = 'medium'

    # Normalize amount_lost
    try:
        amount_lost = float(amount_lost) if amount_lost else None
        if amount_lost == 0:
            amount_lost = None
    except (ValueError, TypeError):
        amount_lost = None

    # Normalize incident_date
    if incident_date:
        try:
            datetime.strptime(incident_date, '%Y-%m-%d')
        except ValueError:
            incident_date = None

    # Determine indicator
    if url:
        indicator      = url
        indicator_type = 'url'
    elif phone_number:
        indicator      = re.sub(r'[\s\-]', '', phone_number)
        indicator_type = 'phone'
    else:
        indicator      = description[:100] if description else 'Unknown'
        indicator_type = 'message'

    scam_type = FROM_API_TYPE.get(api_type, 'Others')

    try:
        conn = get_connection()

        # Duplicate check
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, status FROM reports WHERE indicator = %s LIMIT 1",
                (indicator,)
            )
            existing = cursor.fetchone()

        if existing and existing['status'] in ('approved', 'pending'):
            # Increment report_count
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE reports SET report_count = COALESCE(report_count, 1) + 1 WHERE id = %s",
                        (existing['id'],)
                    )
                conn.commit()
                # Get updated count
                with conn.cursor() as cursor:
                    cursor.execute("SELECT report_count FROM reports WHERE id = %s", (existing['id'],))
                    row = cursor.fetchone()
                    count = row['report_count'] if row else 1
            except Exception:
                count = 1

            return jsonify({
                'report_id': f"SS-{str(existing['id']).zfill(5)}",
                'duplicate': True,
                'report_count': count,
                'message':   f'Already reported — noted by {count} people now'
            }), 200

        # ── Insert with all new fields ─────────────────────
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO reports
                    (indicator_type, indicator, scam_type, description,
                     source, severity, platform, amount_lost, incident_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                indicator_type, indicator, scam_type, description,
                'website', severity, platform, amount_lost, incident_date
            ))
            new_id = cursor.lastrowid
        conn.commit()

        return jsonify({
            'report_id': f"SS-{str(new_id).zfill(5)}",
            'duplicate': False,
            'message':   'Report submitted successfully. Pending admin review.'
        }), 201

    except Exception as e:
        # If new columns don't exist yet, fall back to basic insert
        try:
            conn2 = get_connection()
            with conn2.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO reports
                        (indicator_type, indicator, scam_type, description, source)
                    VALUES (%s, %s, %s, %s, 'website')
                """, (indicator_type, indicator, scam_type, description))
                new_id = cursor.lastrowid
            conn2.commit()
            return jsonify({
                'report_id': f"SS-{str(new_id).zfill(5)}",
                'duplicate': False,
                'message':   'Report submitted (basic mode).'
            }), 201
        except Exception as e2:
            return jsonify({'error': str(e2)}), 500


# ============================================================
#  SCANNER
# ============================================================

@compat_bp.route('/api/scanner/check', methods=['POST'])
def api_scanner_check():
    data  = request.get_json(silent=True) or {}
    raw_value = (data.get('value') or '').strip()
    if not raw_value:
        return jsonify({'error': 'Value is required'}), 400

    # Normalize — add http:// if looks like URL without protocol
    normalized = normalize_url(raw_value)
    value      = normalized.lower()

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            # Try exact match first (with normalized URL)
            cursor.execute("""
                SELECT id, indicator_type, indicator, scam_type,
                       description, list_type, severity, report_count
                FROM reports
                WHERE LOWER(indicator) = %s AND status = 'approved'
                LIMIT 1
            """, (value,))
            row = cursor.fetchone()

            if not row:
                # Try substring match (catches partial domains)
                cursor.execute("""
                    SELECT id, indicator_type, indicator, scam_type,
                           description, list_type, severity, report_count
                    FROM reports
                    WHERE LOWER(indicator) LIKE %s AND status = 'approved'
                    LIMIT 1
                """, (f'%{value}%',))
                row = cursor.fetchone()

            if not row and '/' in value:
                # Try matching just the domain part
                domain = value.split('/')[2] if value.startswith('http') else value.split('/')[0]
                cursor.execute("""
                    SELECT id, indicator_type, indicator, scam_type,
                           description, list_type, severity, report_count
                    FROM reports
                    WHERE LOWER(indicator) LIKE %s AND status = 'approved'
                    LIMIT 1
                """, (f'%{domain}%',))
                row = cursor.fetchone()

        if not row:
            return jsonify({
                'is_scam': False,
                'message': '✓ No match found in our scam database. Always stay cautious.',
            }), 200

        scam = report_to_scam(row)
        return jsonify({
            'is_scam': True,
            'match': {
                'id':        row['id'],
                'value':     row['indicator'],
                'type':      row['indicator_type'].upper(),
                'hit_count': 1,
            },
            'scam':    scam,
            'message': f"⚠️ This {row['indicator_type']} is flagged as a confirmed scam indicator.",
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
#  ADMIN DASHBOARD
# ============================================================

@compat_bp.route('/api/admin/stats', methods=['GET'])
@require_token
def api_admin_stats():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'pending'")
            pending = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved' AND (severity='high' OR list_type='blacklist')")
            blacklisted = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved' AND (severity='medium' OR list_type='whitelist')")
            whitelisted = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'rejected'")
            rejected = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports")
            total = cursor.fetchone()['c']
            today = datetime.utcnow().date()
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE DATE(submitted_at) = %s", (today,))
            today_count = cursor.fetchone()['c']
            cursor.execute("SELECT COALESCE(SUM(amount_lost), 0) as s FROM reports WHERE status='approved' AND amount_lost IS NOT NULL")
            total_lost = float(cursor.fetchone()['s'])

        return jsonify({
            'pending':     pending,
            'blacklisted': blacklisted,
            'whitelisted': whitelisted,   # suspected count
            'rejected':    rejected,
            'verified':    blacklisted,   # only blacklist = confirmed
            'flagged':     whitelisted,   # whitelist = suspected
            'total':       total,
            'today':       today_count,
            'total_lost':  total_lost,
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/reports', methods=['GET'])
@require_token
def api_admin_reports():
    status   = request.args.get('status', 'pending')
    search   = request.args.get('search', '').strip()
    per_page = min(100, int(request.args.get('per_page', 20)))
    page     = max(1, int(request.args.get('page', 1)))

    # Build filter based on tier
    if status == 'verified':
        # Confirmed = approved + blacklist
        query  = """SELECT id, indicator_type, indicator, scam_type, description,
                           source, status, list_type, submitted_at,
                           severity, platform, amount_lost, incident_date, report_count, admin_locked, false_report_count
                    FROM reports WHERE status = 'approved' AND list_type = 'blacklist'"""
        params = []
    elif status == 'flagged':
        # Suspected = approved + whitelist
        query  = """SELECT id, indicator_type, indicator, scam_type, description,
                           source, status, list_type, submitted_at,
                           severity, platform, amount_lost, incident_date, report_count, admin_locked, false_report_count
                    FROM reports WHERE status = 'approved' AND list_type = 'whitelist'"""
        params = []
    elif status == 'removed':
        query  = """SELECT id, indicator_type, indicator, scam_type, description,
                           source, status, list_type, submitted_at,
                           severity, platform, amount_lost, incident_date, report_count, admin_locked, false_report_count
                    FROM reports WHERE status = 'rejected'"""
        params = []
    elif status == 'pending':
        query  = """SELECT id, indicator_type, indicator, scam_type, description,
                           source, status, list_type, submitted_at,
                           severity, platform, amount_lost, incident_date, report_count, admin_locked, false_report_count
                    FROM reports WHERE status = 'pending'"""
        params = []
    else:
        query  = """SELECT id, indicator_type, indicator, scam_type, description,
                           source, status, list_type, submitted_at,
                           severity, platform, amount_lost, incident_date, report_count, admin_locked, false_report_count
                    FROM reports WHERE 1=1"""
        params = []

    if search:
        query += " AND (indicator LIKE %s OR description LIKE %s)"
        params.extend([f'%{search}%', f'%{search}%'])

    query += " ORDER BY report_count DESC, submitted_at DESC"

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            all_rows = cursor.fetchall()

        total  = len(all_rows)
        pages  = max(1, (total + per_page - 1) // per_page)
        offset = (page - 1) * per_page
        rows   = all_rows[offset:offset + per_page]

        return jsonify({
            'data':     [report_to_scam(r) for r in rows],
            'total':    total,
            'page':     page,
            'per_page': per_page,
            'pages':    pages,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/reports/<int:report_id>', methods=['PATCH'])
@require_token
def api_admin_patch_report(report_id):
    data   = request.get_json(silent=True) or {}
    status = data.get('status', 'verified')

    # Tier map — controls what DB values to set
    action_map = {
        'verified': ('approved', 'blacklist', 'high'),    # Confirmed
        'flagged':  ('approved', 'whitelist', 'medium'),  # Suspected
        'pending':  ('pending',  None,        None),      # Back to pending
        'removed':  ('rejected', None,        None),      # Removed
    }
    new_status, list_type, severity = action_map.get(status, ('rejected', None, None))

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE reports SET status = %s, list_type = %s, severity = %s
                WHERE id = %s
            """, (new_status, list_type, severity, report_id))
        conn.commit()
        return jsonify({'message': f'Report {report_id} → {new_status}'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/reports/<int:report_id>', methods=['DELETE'])
@require_token
def api_admin_delete_report(report_id):
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE reports SET status = 'rejected' WHERE id = %s", (report_id,)
            )
        conn.commit()
        return jsonify({'message': f'Report {report_id} removed'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/reports/bulk', methods=['POST'])
@require_token
def api_admin_bulk():
    data   = request.get_json(silent=True) or {}
    ids    = data.get('ids', [])
    status = data.get('status', 'removed')
    # Tier map — controls what DB values to set
    action_map = {
        'verified': ('approved', 'blacklist', 'high'),    # Confirmed
        'flagged':  ('approved', 'whitelist', 'medium'),  # Suspected
        'pending':  ('pending',  None,        None),      # Back to pending
        'removed':  ('rejected', None,        None),      # Removed
    }
    new_status, list_type, severity = action_map.get(status, ('rejected', None, None))
    try:
        conn = get_connection()
        for rid in ids:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE reports SET status=%s, list_type=%s, severity=%s WHERE id=%s",
                    (new_status, list_type, severity, rid)
                )
        conn.commit()
        return jsonify({'message': f'{len(ids)} reports updated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/analytics', methods=['GET'])
@require_token
def api_analytics():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT scam_type, COUNT(*) as total,
                       COALESCE(SUM(amount_lost), 0) as total_loss
                FROM reports WHERE status = 'approved'
                GROUP BY scam_type ORDER BY total DESC
            """)
            by_type = cursor.fetchall()

            cursor.execute("""
                SELECT platform, COUNT(*) as total
                FROM reports WHERE status = 'approved' AND platform IS NOT NULL
                GROUP BY platform ORDER BY total DESC
            """)
            by_platform = cursor.fetchall()

        return jsonify({
            'by_type': [{'type':  TO_API_TYPE.get(r['scam_type'], 'other'),
                         'label': r['scam_type'],
                         'count': r['total'],
                         'loss':  float(r['total_loss'])}
                        for r in by_type],
            'by_platform': [{'platform': r['platform'], 'count': r['total']}
                            for r in by_platform],
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/admins', methods=['GET'])
@require_token
def api_admins():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, role, created_at FROM admins")
            rows = cursor.fetchall()
        admins = [{'id': r['id'], 'name': r['name'], 'email': r['email'],
                   'role': r['role'],
                   'initials': ''.join(p[0].upper() for p in r['name'].split()[:2]),
                   'created_at': str(r['created_at'])} for r in rows]
        return jsonify({'data': admins, 'total': len(admins)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/indicators', methods=['GET'])
@require_token
def api_indicators():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, value, type, scam_id, hit_count, created_at
                FROM scanner_indicators ORDER BY created_at DESC
            """)
            rows = cursor.fetchall()
        data = [{'id': r['id'], 'value': r['value'], 'type': r['type'],
                 'scam_id': r['scam_id'], 'hits': r['hit_count'],
                 'date': str(r['created_at'])[:10]} for r in rows]
        return jsonify({'data': data, 'total': len(data)}), 200
    except Exception:
        return jsonify({'data': [], 'total': 0}), 200


@compat_bp.route('/api/admin/indicators', methods=['POST'])
@require_token
def api_add_indicator():
    data = request.get_json(silent=True) or {}
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO scanner_indicators (value, type, source)
                VALUES (%s, %s, 'manual')
            """, (data.get('value', ''), data.get('type', 'URL')))
        conn.commit()
        return jsonify({'message': 'Indicator added'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@compat_bp.route('/api/admin/indicators/<int:iid>', methods=['DELETE'])
@require_token
def api_delete_indicator(iid):
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM scanner_indicators WHERE id = %s", (iid,))
        conn.commit()
        return jsonify({'message': 'Deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@compat_bp.route('/api/reports/<int:report_id>/false-report', methods=['POST'])
@require_token
def api_false_report(report_id):
    """
    Admin or community member marks a report as false.
    Layered protection:
    - admin_locked reports: IMMUNE — votes ignored
    - confirmed (blacklist): only admin can change
    - suspected (whitelist): 5 false votes → back to pending
    - pending: 5 false votes → flagged for admin review
    """
    current_admin = get_current_admin()
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, status, list_type, admin_locked, false_report_count FROM reports WHERE id = %s",
                (report_id,)
            )
            row = cursor.fetchone()

        if not row:
            return jsonify({'error': 'Report not found'}), 404

        # ── IMMUNE: admin-locked reports cannot be demoted by community ──
        if row.get('admin_locked'):
            return jsonify({
                'message':  'This report has been admin-verified and is immune to community votes.',
                'immune':   True,
                'status':   row['status'],
            }), 200

        # ── Confirmed (blacklist) — only admin can change ──
        if row['status'] == 'approved' and row['list_type'] == 'blacklist':
            return jsonify({
                'message':  'Confirmed reports can only be changed by an admin. Use the dashboard.',
                'immune':   True,
            }), 200

        # ── Increment false report count ──────────────────────────────
        new_false_count = (row.get('false_report_count') or 0) + 1
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE reports SET false_report_count = %s WHERE id = %s",
                (new_false_count, report_id)
            )
        conn.commit()

        # ── Apply demotion if threshold reached ───────────────────────
        # Threshold: 5 false votes to demote one tier
        THRESHOLD = 5
        demoted = False
        new_tier = ''

        if new_false_count >= THRESHOLD:
            if row['status'] == 'approved' and row['list_type'] == 'whitelist':
                # Suspected → back to Pending
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE reports SET status='pending', list_type=NULL, false_report_count=0 WHERE id=%s",
                        (report_id,)
                    )
                conn.commit()
                demoted  = True
                new_tier = 'pending'
                print(f"[false-report] Demoted {report_id} from suspected → pending ({new_false_count} false votes)")

                log_audit(
                    action='Community Demoted',
                    target=f"SS-{str(report_id).zfill(5)}",
                    target_id=report_id,
                    detail=f"Suspected → Pending after {new_false_count} false report votes",
                    admin=current_admin
                )

            elif row['status'] == 'pending':
                # Pending → flag for admin review (don't remove, just notify)
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE reports SET false_report_count=0 WHERE id=%s",
                        (report_id,)
                    )
                conn.commit()
                demoted  = True
                new_tier = 'admin_review'
                print(f"[false-report] Report {report_id} flagged for admin review ({new_false_count} false votes)")

                log_audit(
                    action='Flagged for Review',
                    target=f"SS-{str(report_id).zfill(5)}",
                    target_id=report_id,
                    detail=f"Pending report received {new_false_count} false votes — needs admin review",
                    admin=current_admin
                )

        return jsonify({
            'message':          'Thank you for your feedback.',
            'false_count':      new_false_count,
            'threshold':        THRESHOLD,
            'remaining':        max(0, THRESHOLD - new_false_count),
            'demoted':          demoted,
            'new_tier':         new_tier,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Stubs ──────────────────────────────────────────────────

@compat_bp.route('/api/admin/audit-log', methods=['GET'])
@require_token
def api_audit_log():
    return jsonify({'data': [], 'total': 0}), 200

@compat_bp.route('/api/admin/spam', methods=['GET'])
@require_token
def api_spam():
    return jsonify({'data': [], 'total': 0}), 200

@compat_bp.route('/api/admin/spam/<int:sid>', methods=['DELETE', 'PATCH'])
@require_token
def api_spam_action(sid):
    return jsonify({'message': 'OK'}), 200

@compat_bp.route('/api/admin/spam/all', methods=['DELETE'])
@require_token
def api_spam_all():
    return jsonify({'message': 'OK'}), 200

@compat_bp.route('/api/admin/admins/<int:aid>', methods=['DELETE'])
@require_token
def api_admin_delete_admin(aid):
    return jsonify({'message': 'OK'}), 200

@compat_bp.route('/api/admin/rate-rules', methods=['GET', 'PATCH'])
@require_token
def api_rate_rules():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT rule_key, rule_value, description FROM rate_limit_rules")
            rows = cursor.fetchall()
        return jsonify({'data': rows}), 200
    except Exception:
        return jsonify({'data': []}), 200

@compat_bp.route('/api/admin/settings', methods=['GET', 'PATCH'])
@require_token
def api_settings():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT setting_key, setting_value FROM site_settings")
            rows = cursor.fetchall()
        return jsonify({r['setting_key']: r['setting_value'] for r in rows}), 200
    except Exception:
        return jsonify({}), 200