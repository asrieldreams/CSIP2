"""
seed.py  —  Creates all tables and populates sample data.
Run once:  python seed.py
"""
from app import create_app
from database import db
from models import (Scam, Admin, AuditLog, SpamSession,
                    ScannerIndicator, RateLimitRule,
                    SiteSetting, generate_report_id)
import bcrypt
from datetime import datetime, timedelta
import random

app = create_app()

def hash_pw(plain):
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def seed():
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("✓ Tables created")

        # ── ADMINS ────────────────────────────────────────────
        admins = [
            Admin(name='Admin',
                  email='admin@scamwatch.sg',
                  password=hash_pw('admin123'),
                  role='super_admin',
                  last_login=datetime.utcnow()),
            Admin(name='Sarah Tan',
                  email='sarah.t@scamwatch.sg',
                  password=hash_pw('sarah123'),
                  role='moderator',
                  last_login=datetime.utcnow() - timedelta(hours=2)),
            Admin(name='Marcus Lim',
                  email='m.lim@scamwatch.sg',
                  password=hash_pw('marcus123'),
                  role='analyst',
                  last_login=datetime.utcnow() - timedelta(days=1)),
        ]
        db.session.add_all(admins)
        db.session.flush()
        print("✓ Admins seeded")

        # ── RATE LIMIT RULES ──────────────────────────────────
        rules = [
            RateLimitRule(rule_key='max_per_hour',
                          rule_value=5,
                          description='Max reports per IP per hour'),
            RateLimitRule(rule_key='cooldown_minutes',
                          rule_value=60,
                          description='Cooldown after rate limit hit (minutes)'),
            RateLimitRule(rule_key='dupe_window_hours',
                          rule_value=24,
                          description='Hours before same URL can be resubmitted'),
            RateLimitRule(rule_key='captcha_after',
                          rule_value=3,
                          description='Trigger CAPTCHA after N submissions'),
            RateLimitRule(rule_key='auto_flag_threshold',
                          rule_value=3,
                          description='Auto-flag if fewer than N people reported'),
            RateLimitRule(rule_key='auto_verify_threshold',
                          rule_value=10,
                          description='Auto-verify when N+ people report same scam'),
            RateLimitRule(rule_key='auto_block_threshold',
                          rule_value=5,
                          description='Auto-add to scanner when N+ reports exist'),
        ]
        db.session.add_all(rules)

        # ── SITE SETTINGS ─────────────────────────────────────
        settings = [
            SiteSetting(setting_key='site_name',            setting_value='ScamWatch'),
            SiteSetting(setting_key='admin_email',          setting_value='admin@scamwatch.sg'),
            SiteSetting(setting_key='require_approval',     setting_value='yes'),
            SiteSetting(setting_key='auto_flag_threshold',  setting_value='3'),
            SiteSetting(setting_key='auto_verify_threshold',setting_value='10'),
            SiteSetting(setting_key='auto_block_threshold', setting_value='5'),
        ]
        db.session.add_all(settings)
        db.session.flush()
        print("✓ Rules & settings seeded")

        # ── SCAM REPORTS ──────────────────────────────────────
        scams_data = [
            dict(report_id='SS-2025-47201',
                 title='Fake OCBC Bank Login Page',
                 description='A phishing SMS was sent impersonating OCBC Bank, directing victims to a fake login page hosted on a typosquatting domain. The page harvests internet banking credentials and OTPs before redirecting to the real OCBC website.',
                 type='phishing', severity='high', status='verified',
                 platform='SMS', url='ocbc-verify-login.xyz',
                 phone_number=None, amount_lost=None, report_count=142,
                 created_at=datetime.utcnow() - timedelta(days=1, hours=2)),

            dict(report_id='SS-2025-47198',
                 title='Part-time "Like & Follow" Job Scam',
                 description='Victims are recruited via WhatsApp with offers of earning SGD 50–200/day for simple online tasks. After completing initial tasks and receiving small payments, they are asked to pay upfront capital to unlock higher-paying missions before the scammer disappears.',
                 type='job', severity='high', status='pending',
                 platform='WhatsApp', url=None,
                 phone_number='+65 8123 4567', amount_lost=4500.00, report_count=89,
                 created_at=datetime.utcnow() - timedelta(days=1, hours=5)),

            dict(report_id='SS-2025-47186',
                 title='SingPass Account Suspension SMS',
                 description='An SMS claiming to be from the Government Technology Agency (GovTech) states that your SingPass account has been suspended and requests immediate verification via a phishing link to steal credentials.',
                 type='impersonation', severity='high', status='verified',
                 platform='SMS', url='singpass-secure-verify.net',
                 phone_number=None, amount_lost=None, report_count=211,
                 created_at=datetime.utcnow() - timedelta(days=2, hours=7)),

            dict(report_id='SS-2025-47170',
                 title='Crypto Investment Telegram Group',
                 description='A Telegram group promising guaranteed 30% monthly returns on cryptocurrency investments. Members are shown fabricated profit screenshots and encouraged to deposit via crypto wallets. Withdrawals are blocked with excuses about tax clearance fees.',
                 type='investment', severity='high', status='pending',
                 platform='Telegram', url=None,
                 phone_number=None, amount_lost=12000.00, report_count=67,
                 created_at=datetime.utcnow() - timedelta(days=3, hours=1)),

            dict(report_id='SS-2025-47155',
                 title='Fake Carousell Buyer Overpayment',
                 description='A buyer on Carousell sends a PayNow confirmation screenshot showing overpayment and asks the seller to refund the difference immediately. The original payment was never made, leaving the seller out of pocket.',
                 type='ecommerce', severity='medium', status='verified',
                 platform='Carousell', url=None,
                 phone_number='+65 9876 5432', amount_lost=320.00, report_count=38,
                 created_at=datetime.utcnow() - timedelta(days=3, hours=5)),

            dict(report_id='SS-2025-47140',
                 title='DHL Parcel Customs Fee Email',
                 description='An email mimicking DHL branding informs recipients of a held parcel requiring urgent customs fee payment of SGD 2–5 via a fake payment page that captures credit card details.',
                 type='phishing', severity='medium', status='pending',
                 platform='Email', url='dhl-delivery-sg-customs.com',
                 phone_number=None, amount_lost=None, report_count=55,
                 created_at=datetime.utcnow() - timedelta(days=4, hours=2)),

            dict(report_id='SS-2025-47129',
                 title='Romance Scam via Facebook Dating',
                 description='Scammer poses as an overseas engineer on Facebook Dating, builds a relationship over weeks, then claims to be stranded and requests emergency fund transfers. No repayment is ever made.',
                 type='love', severity='high', status='flagged',
                 platform='Facebook', url=None,
                 phone_number=None, amount_lost=8800.00, report_count=12,
                 created_at=datetime.utcnow() - timedelta(days=4, hours=8)),

            dict(report_id='SS-2025-47110',
                 title='Fake SGDeals App APK',
                 description='A link circulating on Telegram promises exclusive SingTel deals and prompts users to sideload an APK file. The app requests SMS permissions and intercepts OTPs to take over banking apps.',
                 type='malware', severity='high', status='verified',
                 platform='Telegram', url='sgdeals-app.top/download',
                 phone_number=None, amount_lost=None, report_count=29,
                 created_at=datetime.utcnow() - timedelta(days=5, hours=3)),

            dict(report_id='SS-2025-47098',
                 title='"You have a parcel" Phishing SMS',
                 description='A generic SMS claiming a parcel is awaiting collection, linking to a page that requests name, address, and credit card details for a small redelivery fee of SGD 0.50.',
                 type='sms', severity='medium', status='verified',
                 platform='SMS', url='parcels-sg-redeliver.com',
                 phone_number=None, amount_lost=None, report_count=183,
                 created_at=datetime.utcnow() - timedelta(days=6, hours=1)),

            dict(report_id='SS-2025-47080',
                 title='SPF Police Impersonation Call',
                 description='Caller claims to be an SPF officer investigating a money laundering case involving the victim bank account. Instructs victim to transfer funds to a safe government account to assist the investigation.',
                 type='impersonation', severity='high', status='verified',
                 platform='Phone Call', url=None,
                 phone_number='+65 6765 0000', amount_lost=25000.00, report_count=44,
                 created_at=datetime.utcnow() - timedelta(days=6, hours=7)),

            dict(report_id='SS-2025-47055',
                 title='Forex Guaranteed Profits WhatsApp Group',
                 description='WhatsApp group run by supposed forex trading experts showing fabricated daily profit charts. New members are asked to deposit a minimum of SGD 500 to join premium signals. Funds cannot be withdrawn.',
                 type='investment', severity='medium', status='pending',
                 platform='WhatsApp', url=None,
                 phone_number=None, amount_lost=1200.00, report_count=19,
                 created_at=datetime.utcnow() - timedelta(days=7, hours=3)),

            dict(report_id='SS-2025-47030',
                 title='Shopee Fake Electronics Seller',
                 description='A Shopee seller with inflated fake reviews sells electronics at drastically reduced prices. After payment, orders are never shipped and the seller disappears after a few days.',
                 type='ecommerce', severity='low', status='flagged',
                 platform='Lazada / Shopee', url=None,
                 phone_number=None, amount_lost=459.00, report_count=27,
                 created_at=datetime.utcnow() - timedelta(days=7, hours=6)),
        ]

        scam_objects = []
        for s in scams_data:
            scam = Scam(**s)
            db.session.add(scam)
            scam_objects.append(scam)
        db.session.flush()
        print(f"✓ {len(scam_objects)} scams seeded")

        # ── SCANNER INDICATORS (auto from verified scams) ─────
        indicators_data = [
            dict(value='ocbc-verify-login.xyz',      type='URL',    scam_id=scam_objects[0].id,  source='auto',   hit_count=142),
            dict(value='singpass-secure-verify.net',  type='URL',    scam_id=scam_objects[2].id,  source='auto',   hit_count=211),
            dict(value='+65 8123 4567',               type='Phone',  scam_id=scam_objects[1].id,  source='auto',   hit_count=89),
            dict(value='dhl-delivery-sg-customs.com', type='Domain', scam_id=scam_objects[5].id,  source='auto',   hit_count=55),
            dict(value='sgdeals-app.top',             type='Domain', scam_id=scam_objects[7].id,  source='auto',   hit_count=29),
            dict(value='parcels-sg-redeliver.com',    type='Domain', scam_id=scam_objects[8].id,  source='auto',   hit_count=183),
            dict(value='+65 9876 5432',               type='Phone',  scam_id=scam_objects[4].id,  source='manual', hit_count=38,  added_by=admins[0].id),
            dict(value='fake-mas-invest.sg',          type='Domain', scam_id=None,                source='manual', hit_count=14,  added_by=admins[0].id),
        ]

        for ind_data in indicators_data:
            ind = ScannerIndicator(**ind_data)
            db.session.add(ind)
        print(f"✓ {len(indicators_data)} scanner indicators seeded")

        # ── SPAM SESSIONS ─────────────────────────────────────
        spam_data = [
            dict(session_token='sess_a3f9b1', ip_address='103.24.77.12',
                 reason='5 submissions in 12 min (rate limit hit)', submit_count=5,
                 is_blocked=False,
                 created_at=datetime.utcnow() - timedelta(minutes=8)),
            dict(session_token='sess_c72de4', ip_address='202.166.122.88',
                 reason='Duplicate URL submitted 3x in 1 hour', submit_count=3,
                 is_blocked=False,
                 created_at=datetime.utcnow() - timedelta(minutes=22)),
            dict(session_token='sess_88fa02', ip_address='118.200.44.9',
                 reason='Identical description text across 4 reports', submit_count=4,
                 is_blocked=True,
                 created_at=datetime.utcnow() - timedelta(minutes=45)),
            dict(session_token='sess_11dc77', ip_address='185.220.101.7',
                 reason='Non-SG IP submitting high-volume reports', submit_count=9,
                 is_blocked=True,
                 created_at=datetime.utcnow() - timedelta(hours=1)),
            dict(session_token='sess_5b3e90', ip_address='45.142.212.100',
                 reason='CAPTCHA failed 3 consecutive times', submit_count=3,
                 is_blocked=False,
                 created_at=datetime.utcnow() - timedelta(hours=2)),
        ]
        for s in spam_data:
            db.session.add(SpamSession(**s))
        print(f"✓ {len(spam_data)} spam sessions seeded")

        # ── AUDIT LOG ─────────────────────────────────────────
        audit_data = [
            dict(admin_id=admins[0].id, action='Verified',
                 target_type='scam', target_id=scam_objects[0].id,
                 target_ref='SS-2025-47201', detail='Fake OCBC Bank Login Page',
                 created_at=datetime.utcnow() - timedelta(hours=2)),
            dict(admin_id=admins[1].id, action='Flagged',
                 target_type='scam', target_id=scam_objects[6].id,
                 target_ref='SS-2025-47129', detail='Romance Scam — unverifiable',
                 created_at=datetime.utcnow() - timedelta(hours=3)),
            dict(admin_id=admins[0].id, action='Added Indicator',
                 target_type='indicator', target_id=1,
                 target_ref='ocbc-verify-login.xyz', detail='Auto from verified report',
                 created_at=datetime.utcnow() - timedelta(hours=4)),
            dict(admin_id=admins[2].id, action='Verified',
                 target_type='scam', target_id=scam_objects[2].id,
                 target_ref='SS-2025-47186', detail='SingPass Suspension SMS',
                 created_at=datetime.utcnow() - timedelta(hours=6)),
            dict(admin_id=admins[1].id, action='Blocked IP',
                 target_type='spam_session', target_id=4,
                 target_ref='185.220.101.7', detail='High-volume non-SG IP',
                 created_at=datetime.utcnow() - timedelta(hours=8)),
            dict(admin_id=admins[0].id, action='Bulk Verified',
                 target_type='scam', target_id=None,
                 target_ref='4 reports', detail='Batch verification of phishing scams',
                 created_at=datetime.utcnow() - timedelta(days=1)),
            dict(admin_id=admins[0].id, action='Login',
                 target_type='admin', target_id=admins[0].id,
                 target_ref='admin@scamwatch.sg', detail='Admin logged in',
                 created_at=datetime.utcnow() - timedelta(minutes=5)),
        ]
        for a in audit_data:
            db.session.add(AuditLog(**a))
        print(f"✓ {len(audit_data)} audit log entries seeded")

        db.session.commit()
        print("\n✅ Database seeded successfully!")
        print("\n── Admin credentials ────────────────")
        print("  Email:    admin@scamwatch.sg")
        print("  Password: admin123")
        print("─────────────────────────────────────")

if __name__ == '__main__':
    seed()
