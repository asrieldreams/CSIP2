from extensions import db
from datetime import datetime
import random


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — generate unique report ID like SS-2025-47201
# ─────────────────────────────────────────────────────────────────────────────
def generate_report_id():
    year = datetime.utcnow().year
    num  = random.randint(10000, 99999)
    return f"SS-{year}-{num}"


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 1: scams
# Used by: existingscams.html, reportscam.html, admindashboard.html
# ─────────────────────────────────────────────────────────────────────────────
class Scam(db.Model):
    __tablename__ = 'scams'

    id           = db.Column(db.Integer,      primary_key=True, autoincrement=True)
    report_id    = db.Column(db.String(20),   nullable=False, unique=True, default=generate_report_id)
    title        = db.Column(db.String(255),  nullable=False)
    description  = db.Column(db.Text,         nullable=False)
    type         = db.Column(
                       db.Enum('phishing', 'sms', 'investment', 'ecommerce',
                               'impersonation', 'job', 'love', 'malware', 'other'),
                       nullable=False)
    severity     = db.Column(db.Enum('low', 'medium', 'high'),                    default='medium')
    status       = db.Column(db.Enum('pending', 'verified', 'flagged', 'removed'), default='pending')
    platform     = db.Column(db.String(50))     # WhatsApp, SMS, Telegram, Email …
    url          = db.Column(db.String(500))     # suspicious link (if any)
    phone_number = db.Column(db.String(30))      # scammer phone number (if any)
    amount_lost  = db.Column(db.Numeric(10, 2))  # NULL = no financial loss reported
    report_count = db.Column(db.Integer, default=1)   # how many people reported same scam
    admin_notes  = db.Column(db.Text)            # internal only — never sent to public
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # One scam can have multiple scanner indicators (URL + domain + phone)
    indicators = db.relationship('ScannerIndicator', backref='scam',
                                 lazy=True, cascade='all, delete-orphan')

    def to_dict(self, admin=False):
        """admin=True includes admin_notes, otherwise strips it for public API."""
        d = {
            'id':           self.id,
            'report_id':    self.report_id,
            'title':        self.title,
            'description':  self.description,
            'type':         self.type,
            'severity':     self.severity,
            'status':       self.status,
            'platform':     self.platform,
            'url':          self.url,
            'phone_number': self.phone_number,
            'amount_lost':  float(self.amount_lost) if self.amount_lost else None,
            'report_count': self.report_count,
            'created_at':   self.created_at.isoformat(),
            'updated_at':   self.updated_at.isoformat() if self.updated_at else None,
        }
        if admin:
            d['admin_notes'] = self.admin_notes
        return d


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 2: scanner_indicators
# Confirmed scam URLs / domains / phone numbers the scanner checks against
# ─────────────────────────────────────────────────────────────────────────────
class ScannerIndicator(db.Model):
    __tablename__ = 'scanner_indicators'

    id         = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    value      = db.Column(db.String(500), nullable=False)
    type       = db.Column(db.Enum('URL', 'Domain', 'Phone', 'Email Domain'), nullable=False)
    scam_id    = db.Column(db.Integer, db.ForeignKey('scams.id', ondelete='SET NULL'), nullable=True)
    source     = db.Column(db.Enum('auto', 'manual'), default='auto')
    # auto   = extracted automatically when admin verifies a scam with a URL/phone
    # manual = admin added it directly from Scanner Indicators page
    hit_count  = db.Column(db.Integer, default=0)   # incremented on every scanner match
    added_by   = db.Column(db.Integer, db.ForeignKey('admins.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':        self.id,
            'value':     self.value,
            'type':      self.type,
            'scam_id':   self.scam_id,
            'report_id': self.scam.report_id if self.scam else None,
            'source':    self.source,
            'hits':      self.hit_count,
            'date':      self.created_at.strftime('%Y-%m-%d'),
        }


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 3: admins
# The ONLY real accounts on ScamWatch — reporting is fully anonymous
# ─────────────────────────────────────────────────────────────────────────────
class Admin(db.Model):
    __tablename__ = 'admins'

    id         = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    name       = db.Column(db.String(100), nullable=False)
    email      = db.Column(db.String(255), nullable=False, unique=True)
    password   = db.Column(db.String(255), nullable=False)   # werkzeug hashed
    role       = db.Column(db.Enum('super_admin', 'moderator', 'analyst'), default='moderator')
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    audit_logs = db.relationship('AuditLog',         backref='admin', lazy=True)
    indicators = db.relationship('ScannerIndicator', backref='admin', lazy=True,
                                 foreign_keys='ScannerIndicator.added_by')

    def to_dict(self):
        name_parts = self.name.strip().split()
        initials   = ''.join(p[0].upper() for p in name_parts[:2])
        return {
            'id':         self.id,
            'name':       self.name,
            'email':      self.email,
            'role':       self.role,
            'initials':   initials,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 4: spam_sessions
# Anonymous abuse tracking — no user accounts, IP + session fingerprint only
# ─────────────────────────────────────────────────────────────────────────────
class SpamSession(db.Model):
    __tablename__ = 'spam_sessions'

    id            = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    session_token = db.Column(db.String(64),  nullable=False)   # SHA-256 of IP+UserAgent
    ip_address    = db.Column(db.String(45))                    # IPv4 or IPv6
    reason        = db.Column(db.String(255), nullable=False)   # why it was flagged
    submit_count  = db.Column(db.Integer,     default=1)
    is_blocked    = db.Column(db.Boolean,     default=False)    # True = hard block this IP
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)

    def to_dict(self):
        from datetime import datetime as dt
        now    = dt.utcnow()
        diff   = (now - self.created_at).total_seconds()
        if diff < 3600:
            time_ago = f"{int(diff // 60)}m ago"
        elif diff < 86400:
            time_ago = f"{int(diff // 3600)}h ago"
        else:
            time_ago = f"{int(diff // 86400)}d ago"
        return {
            'id':         self.id,
            'token':      self.session_token,
            'ip_address': self.ip_address,
            'reason':     self.reason,
            'count':      self.submit_count,
            'is_blocked': self.is_blocked,
            'time':       time_ago,
            'created_at': self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 5: rate_limit_rules
# Configurable from admin Settings page — Spam & Abuse Control
# ─────────────────────────────────────────────────────────────────────────────
class RateLimitRule(db.Model):
    __tablename__ = 'rate_limit_rules'

    id          = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    rule_key    = db.Column(db.String(50),  nullable=False, unique=True)
    rule_value  = db.Column(db.Integer,     nullable=False)
    description = db.Column(db.String(255))
    updated_at  = db.Column(db.DateTime,    default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'key':         self.rule_key,
            'value':       self.rule_value,
            'description': self.description,
        }


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 6: site_settings
# Key-value store for general settings (site name, approval mode, thresholds)
# ─────────────────────────────────────────────────────────────────────────────
class SiteSetting(db.Model):
    __tablename__ = 'site_settings'

    id            = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    setting_key   = db.Column(db.String(50),  nullable=False, unique=True)
    setting_value = db.Column(db.String(255), nullable=False)
    updated_at    = db.Column(db.DateTime,    default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {'key': self.setting_key, 'value': self.setting_value}


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 7: audit_log
# Every admin action is auto-written here — used by Audit Log page
# ─────────────────────────────────────────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id          = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    admin_id    = db.Column(db.Integer,     db.ForeignKey('admins.id', ondelete='SET NULL'), nullable=True)
    action      = db.Column(db.String(50),  nullable=False)   # 'Verified', 'Removed', 'Flagged' …
    target_type = db.Column(db.String(50))                    # 'scam', 'indicator', 'admin', 'settings'
    target_id   = db.Column(db.Integer)                       # the DB id of what was acted on
    target_ref  = db.Column(db.String(100))                   # human-readable e.g. SS-2025-47201
    detail      = db.Column(db.String(255))                   # extra context
    created_at  = db.Column(db.DateTime,   default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':          self.id,
            'admin':       self.admin.name if self.admin else 'System',
            'action':      self.action,
            'target_type': self.target_type,
            'target':      self.target_ref,
            'detail':      self.detail,
            'ts':          self.created_at.strftime('%Y-%m-%d %H:%M'),
        }
