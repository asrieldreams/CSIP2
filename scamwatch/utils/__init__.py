import random
import hashlib
from datetime import datetime
from flask import request
from extensions import db
from models import AuditLog, SpamSession, RateLimitRule, ScannerIndicator, IndicatorType, IndicatorSource


# ─────────────────────────────────────────────────────────────────────────────
# REPORT ID GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_report_id():
    """Generate a unique report ID like SS-2025-47201."""
    from models import Scam
    year = datetime.utcnow().year
    while True:
        num = random.randint(10000, 99999)
        report_id = f"SS-{year}-{num}"
        if not Scam.query.filter_by(report_id=report_id).first():
            return report_id


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT LOGGER
# ─────────────────────────────────────────────────────────────────────────────

def log_audit(admin_id, action, target_type=None, target_id=None, target_ref=None, detail=None):
    """Write an entry to the audit log. Call this after every admin action."""
    entry = AuditLog(
        admin_id    = admin_id,
        action      = action,
        target_type = target_type,
        target_id   = target_id,
        target_ref  = target_ref,
        detail      = detail,
    )
    db.session.add(entry)
    # Note: caller must commit — don't commit here so it's part of the same transaction


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER (anonymous, IP + session based)
# ─────────────────────────────────────────────────────────────────────────────

def get_client_ip():
    """Get real IP even behind a proxy."""
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_session_token():
    """Generate a fingerprint from IP + User-Agent (anonymous, no personal data)."""
    raw = f"{get_client_ip()}:{request.headers.get('User-Agent', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def get_rule(key, default):
    """Fetch a rate limit rule value from DB, fallback to default."""
    rule = RateLimitRule.query.filter_by(rule_key=key).first()
    return rule.rule_value if rule else default

def check_rate_limit():
    """
    Check if the current session/IP is allowed to submit a report.
    Returns (allowed: bool, reason: str or None)
    """
    from datetime import timedelta
    ip            = get_client_ip()
    token         = get_session_token()
    max_per_hour  = get_rule('max_per_hour', 5)
    cooldown_mins = get_rule('cooldown_minutes', 60)
    cutoff        = datetime.utcnow() - timedelta(hours=1)

    # Check if IP is fully blocked
    blocked = SpamSession.query.filter_by(ip_address=ip, is_blocked=True).first()
    if blocked:
        return False, 'IP address is blocked due to abuse'

    # Count submissions in last hour for this session
    recent_count = SpamSession.query.filter(
        SpamSession.session_token == token,
        SpamSession.created_at >= cutoff
    ).count()

    if recent_count >= max_per_hour:
        spam = SpamSession(
            session_token=token,
            ip_address=ip,
            reason=f'{max_per_hour} submissions in 1 hour (rate limit hit)',
            submit_count=recent_count + 1,
        )
        db.session.add(spam)
        db.session.commit()
        return False, f'Rate limit exceeded — max {max_per_hour} reports per hour'

    return True, None

def check_duplicate(url=None, title=None):
    """
    Check if a very similar report was submitted recently.
    Returns (is_duplicate: bool, existing_report_id: str or None)
    """
    from models import Scam, ScamStatus
    from datetime import timedelta
    dupe_hours = get_rule('dupe_window_hours', 24)
    cutoff     = datetime.utcnow() - timedelta(hours=dupe_hours)

    if url:
        existing = Scam.query.filter(
            Scam.url == url,
            Scam.created_at >= cutoff,
            Scam.status != ScamStatus.removed
        ).first()
        if existing:
            # Increment report_count on the existing record instead
            existing.report_count += 1
            db.session.commit()
            return True, existing.report_id

    if title:
        existing = Scam.query.filter(
            Scam.title == title,
            Scam.created_at >= cutoff,
            Scam.status != ScamStatus.removed
        ).first()
        if existing:
            existing.report_count += 1
            db.session.commit()
            return True, existing.report_id

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-POPULATE SCANNER INDICATORS
# ─────────────────────────────────────────────────────────────────────────────

def auto_add_indicators(scam, admin_id=None):
    """
    When a scam is verified, auto-add its URL/domain/phone
    to scanner_indicators if not already present.
    """
    entries = []

    if scam.url:
        # Extract domain from full URL
        domain = scam.url.split('/')[0].lower()
        if not ScannerIndicator.query.filter_by(value=scam.url).first():
            entries.append(ScannerIndicator(
                value=scam.url, type=IndicatorType.URL,
                scam_id=scam.id, source=IndicatorSource.auto, added_by=admin_id
            ))
        if domain != scam.url and not ScannerIndicator.query.filter_by(value=domain).first():
            entries.append(ScannerIndicator(
                value=domain, type=IndicatorType.Domain,
                scam_id=scam.id, source=IndicatorSource.auto, added_by=admin_id
            ))

    if scam.phone_number:
        cleaned = scam.phone_number.replace(' ', '')
        if not ScannerIndicator.query.filter_by(value=cleaned).first():
            entries.append(ScannerIndicator(
                value=cleaned, type=IndicatorType.Phone,
                scam_id=scam.id, source=IndicatorSource.auto, added_by=admin_id
            ))

    for entry in entries:
        db.session.add(entry)
