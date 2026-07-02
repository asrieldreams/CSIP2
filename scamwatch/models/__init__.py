from database import db
from datetime import datetime
import random, string

# ─────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────
def generate_report_id():
    year = datetime.utcnow().year
    num  = random.randint(10000, 99999)
    return f"SS-{year}-{num}"


# ─────────────────────────────────────────────────────────────
# SCAMS  (core table — public + admin)
# ─────────────────────────────────────────────────────────────
class Scam(db.Model):
    __tablename__ = 'scams'

    id           = db.Column(db.Integer,      primary_key=True)
    report_id    = db.Column(db.String(20),   nullable=False, unique=True,
                             default=generate_report_id)
    title        = db.Column(db.String(255),  nullable=False)
    description  = db.Column(db.Text,         nullable=False)
    type         = db.Column(db.Enum('phishing','sms','investment','ecommerce',
                                     'impersonation','job','love','malware','other'),
                             nullable=False)
    severity     = db.Column(db.Enum('low','medium','high'), default='medium')
    status       = db.Column(db.Enum('pending','verified','flagged','removed'),
                             default='pending')
    platform     = db.Column(db.String(50))
    url          = db.Column(db.String(500))
    phone_number = db.Column(db.String(30))
    amount_lost  = db.Column(db.Numeric(10, 2))
    report_count = db.Column(db.Integer, default=1)
    admin_notes  = db.Column(db.Text)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow,
                             onupdate=datetime.utcnow)

    # relationships
    indicators   = db.relationship('ScannerIndicator', backref='scam',
                                   lazy=True, cascade='all, delete-orphan')

    def to_dict(self, full=False):
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
        if full:
            d['admin_notes'] = self.admin_notes
        return d


# ─────────────────────────────────────────────────────────────
# SCANNER INDICATORS
# ─────────────────────────────────────────────────────────────
class ScannerIndicator(db.Model):
    __tablename__ = 'scanner_indicators'

    id         = db.Column(db.Integer,     primary_key=True)
    value      = db.Column(db.String(500), nullable=False)
    type       = db.Column(db.Enum('URL','Domain','Phone','Email Domain'),
                           nullable=False)
    scam_id    = db.Column(db.Integer, db.ForeignKey('scams.id',
                           ondelete='SET NULL'), nullable=True)
    source     = db.Column(db.Enum('auto','manual'), default='auto')
    hit_count  = db.Column(db.Integer, default=0)
    added_by   = db.Column(db.Integer, db.ForeignKey('admins.id',
                           ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':         self.id,
            'value':      self.value,
            'type':       self.type,
            'scam_id':    self.scam_id,
            'report_id':  self.scam.report_id if self.scam else None,
            'source':     self.source,
            'hits':       self.hit_count,
            'added_by':   self.added_by,
            'date':       self.created_at.strftime('%Y-%m-%d'),
        }


# ─────────────────────────────────────────────────────────────
# ADMINS  (only real accounts on the system)
# ─────────────────────────────────────────────────────────────
class Admin(db.Model):
    __tablename__ = 'admins'

    id         = db.Column(db.Integer,     primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    email      = db.Column(db.String(255), nullable=False, unique=True)
    password   = db.Column(db.String(255), nullable=False)   # bcrypt hash
    role       = db.Column(db.Enum('super_admin','moderator','analyst'),
                           default='moderator')
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    audit_logs  = db.relationship('AuditLog', backref='admin', lazy=True)
    indicators  = db.relationship('ScannerIndicator', backref='admin', lazy=True)

    def to_dict(self):
        return {
            'id':         self.id,
            'name':       self.name,
            'email':      self.email,
            'role':       self.role,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────
# SPAM SESSIONS  (anonymous abuse tracking)
# ─────────────────────────────────────────────────────────────
class SpamSession(db.Model):
    __tablename__ = 'spam_sessions'

    id            = db.Column(db.Integer,    primary_key=True)
    session_token = db.Column(db.String(64), nullable=False)
    ip_address    = db.Column(db.String(45))
    reason        = db.Column(db.String(255), nullable=False)
    submit_count  = db.Column(db.Integer,    default=1)
    is_blocked    = db.Column(db.Boolean,    default=False)
    created_at    = db.Column(db.DateTime,   default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':            self.id,
            'token':         self.session_token,
            'ip_address':    self.ip_address,
            'reason':        self.reason,
            'count':         self.submit_count,
            'is_blocked':    self.is_blocked,
            'time':          self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────
# RATE LIMIT RULES  (configurable from Settings page)
# ─────────────────────────────────────────────────────────────
class RateLimitRule(db.Model):
    __tablename__ = 'rate_limit_rules'

    id          = db.Column(db.Integer,     primary_key=True)
    rule_key    = db.Column(db.String(50),  nullable=False, unique=True)
    rule_value  = db.Column(db.Integer,     nullable=False)
    description = db.Column(db.String(255))
    updated_at  = db.Column(db.DateTime,   default=datetime.utcnow,
                            onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'key':         self.rule_key,
            'value':       self.rule_value,
            'description': self.description,
        }


# ─────────────────────────────────────────────────────────────
# SITE SETTINGS
# ─────────────────────────────────────────────────────────────
class SiteSetting(db.Model):
    __tablename__ = 'site_settings'

    id            = db.Column(db.Integer,     primary_key=True)
    setting_key   = db.Column(db.String(50),  nullable=False, unique=True)
    setting_value = db.Column(db.String(255), nullable=False)
    updated_at    = db.Column(db.DateTime,    default=datetime.utcnow,
                              onupdate=datetime.utcnow)

    def to_dict(self):
        return { 'key': self.setting_key, 'value': self.setting_value }


# ─────────────────────────────────────────────────────────────
# AUDIT LOG  (auto-written on every admin action)
# ─────────────────────────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id          = db.Column(db.Integer,     primary_key=True)
    admin_id    = db.Column(db.Integer,     db.ForeignKey('admins.id',
                            ondelete='SET NULL'), nullable=True)
    action      = db.Column(db.String(50),  nullable=False)
    target_type = db.Column(db.String(50))
    target_id   = db.Column(db.Integer)
    target_ref  = db.Column(db.String(50))
    detail      = db.Column(db.String(255))
    created_at  = db.Column(db.DateTime,   default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':          self.id,
            'admin':       self.admin.name if self.admin else 'System',
            'action':      self.action,
            'target_type': self.target_type,
            'target_id':   self.target_id,
            'target':      self.target_ref,
            'detail':      self.detail,
            'ts':          self.created_at.strftime('%Y-%m-%d %H:%M'),
        }
