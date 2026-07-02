import hashlib
import jwt
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from extensions import db
from models import Admin, AuditLog, SpamSession, RateLimitRule, ScannerIndicator


# ─────────────────────────────────────────────────────────────────────────────
# JWT AUTH DECORATOR
# Protects all admin routes — use @require_admin on any route function
# ─────────────────────────────────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization token'}), 401
        token = auth.replace('Bearer ', '').strip()
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET'],
                algorithms=['HS256']
            )
            admin = Admin.query.get(payload.get('admin_id'))
            if not admin:
                return jsonify({'error': 'Admin not found'}), 401
            # Attach admin to request so route can use it
            request.current_admin = admin
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired — please log in again'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


def require_super_admin(f):
    """Extra decorator — use on top of @require_admin for dangerous actions."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.current_admin.role != 'super_admin':
            return jsonify({'error': 'Super admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def make_token(admin):
    """Create a signed JWT for an admin account."""
    payload = {
        'admin_id': admin.id,
        'role':     admin.role,
        'exp':      datetime.utcnow() + timedelta(
                        hours=current_app.config['JWT_EXPIRY_HOURS'])
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT LOGGER
# Call after every admin action — writes to audit_log table
# ─────────────────────────────────────────────────────────────────────────────
def log_audit(admin_id, action, target_type=None, target_id=None,
              target_ref=None, detail=None):
    entry = AuditLog(
        admin_id    = admin_id,
        action      = action,
        target_type = target_type,
        target_id   = target_id,
        target_ref  = target_ref,
        detail      = detail,
    )
    db.session.add(entry)
    # Caller is responsible for db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# Called before every anonymous report submission
# Uses IP address + User-Agent fingerprint — no personal data stored
# ─────────────────────────────────────────────────────────────────────────────
def get_client_ip():
    """Get real IP, works behind proxies like nginx."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def get_session_token():
    """SHA-256 fingerprint from IP + User-Agent. Anonymous — no personal data."""
    ip  = get_client_ip()
    ua  = request.headers.get('User-Agent', '')
    raw = f"{ip}:{ua}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def get_rule_value(key, default):
    """Fetch a rate limit rule value from the DB."""
    rule = RateLimitRule.query.filter_by(rule_key=key).first()
    return rule.rule_value if rule else default


def check_rate_limit():
    """
    Returns (allowed: bool, reason: str or None).
    If not allowed, the caller should return 429.
    """
    ip           = get_client_ip()
    token        = get_session_token()
    max_per_hour = get_rule_value('max_per_hour', 5)
    cutoff       = datetime.utcnow() - timedelta(hours=1)

    # Hard block check — IP marked as blocked by admin
    blocked = SpamSession.query.filter_by(ip_address=ip, is_blocked=True).first()
    if blocked:
        return False, 'Your IP address has been blocked due to abuse'

    # Count this session's submissions in the last hour
    recent = SpamSession.query.filter(
        SpamSession.session_token == token,
        SpamSession.created_at   >= cutoff
    ).count()

    if recent >= max_per_hour:
        # Log the violation
        spam = SpamSession(
            session_token = token,
            ip_address    = ip,
            reason        = f'{recent + 1} submissions in 1 hour (rate limit hit)',
            submit_count  = recent + 1,
        )
        db.session.add(spam)
        db.session.commit()
        return False, f'Rate limit exceeded — max {max_per_hour} reports per hour'

    return True, None


def check_duplicate(url=None, title=None):
    """
    Checks if a very similar report was submitted recently.
    If duplicate found, increments report_count on the existing scam.
    Returns (is_duplicate: bool, existing_report_id: str or None)
    """
    from models import Scam
    dupe_hours = get_rule_value('dupe_window_hours', 24)
    cutoff     = datetime.utcnow() - timedelta(hours=dupe_hours)

    if url and url.strip():
        existing = Scam.query.filter(
            Scam.url       == url.strip(),
            Scam.created_at >= cutoff,
            Scam.status    != 'removed'
        ).first()
        if existing:
            existing.report_count += 1
            db.session.commit()
            return True, existing.report_id

    if title and title.strip():
        existing = Scam.query.filter(
            Scam.title     == title.strip(),
            Scam.created_at >= cutoff,
            Scam.status    != 'removed'
        ).first()
        if existing:
            existing.report_count += 1
            db.session.commit()
            return True, existing.report_id

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-ADD SCANNER INDICATORS
# Called automatically when an admin verifies a scam
# Extracts URL, domain, and phone from the scam record and adds them
# ─────────────────────────────────────────────────────────────────────────────
def auto_add_indicators(scam, admin_id=None):
    """Extract URL/domain/phone from a verified scam and add to scanner_indicators."""
    to_add = []

    if scam.url and scam.url.strip():
        url = scam.url.strip()
        # Add full URL
        if not ScannerIndicator.query.filter_by(value=url).first():
            to_add.append(ScannerIndicator(
                value=url, type='URL', scam_id=scam.id,
                source='auto', added_by=admin_id
            ))
        # Also add the domain part
        domain = url.split('/')[0].lower().replace('www.', '')
        if domain and domain != url and not ScannerIndicator.query.filter_by(value=domain).first():
            to_add.append(ScannerIndicator(
                value=domain, type='Domain', scam_id=scam.id,
                source='auto', added_by=admin_id
            ))

    if scam.phone_number and scam.phone_number.strip():
        phone = scam.phone_number.strip().replace(' ', '')
        if not ScannerIndicator.query.filter_by(value=phone).first():
            to_add.append(ScannerIndicator(
                value=phone, type='Phone', scam_id=scam.id,
                source='auto', added_by=admin_id
            ))

    for ind in to_add:
        db.session.add(ind)
    # Caller commits
