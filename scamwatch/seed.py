"""
seed.py — Create all tables and populate with realistic demo data.

Run once after setting up your MySQL database:
    python seed.py
"""
from app import create_app
from extensions import db
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from models import (
    Scam, ScannerIndicator, Admin,
    SpamSession, RateLimitRule, SiteSetting, AuditLog,
    generate_report_id,
)

app = create_app()

def seed():
    with app.app_context():
        print("⏳ Dropping and recreating all tables...")
        db.drop_all()
        db.create_all()

        # ── 1. ADMIN ACCOUNTS ─────────────────────────────────────────────
        print("   Seeding admin accounts...")
        admin1 = Admin(name='Admin',      email='admin@scamwatch.sg',   password=generate_password_hash('admin123'),  role='super_admin', last_login=datetime.utcnow())
        admin2 = Admin(name='Sarah Tan',  email='sarah.t@scamwatch.sg', password=generate_password_hash('sarah456'),  role='moderator',   last_login=datetime.utcnow()-timedelta(hours=2))
        admin3 = Admin(name='Marcus Lim', email='m.lim@scamwatch.sg',   password=generate_password_hash('marcus789'), role='analyst',     last_login=datetime.utcnow()-timedelta(days=1))
        db.session.add_all([admin1, admin2, admin3])
        db.session.flush()  # get IDs before using them below

        # ── 2. SCAM REPORTS ───────────────────────────────────────────────
        print("   Seeding scam reports...")
        scams = [
            Scam(report_id='SS-2025-47201', title='Fake OCBC Bank Login Page',
                 description='A phishing SMS impersonating OCBC Bank directs victims to a typosquatted domain that harvests internet banking credentials and OTPs before redirecting to the real site. Multiple victims report unauthorised transactions within hours.',
                 type='phishing', severity='high', status='verified', platform='SMS',
                 url='ocbc-verify-login.xyz', report_count=142,
                 created_at=datetime.utcnow()-timedelta(hours=2)),

            Scam(report_id='SS-2025-47198', title='Part-time "Like & Follow" Job Scam',
                 description='Victims recruited via WhatsApp with offers of SGD 50–200/day for simple social media tasks. After initial small payouts to build trust, they are asked to pay upfront "capital" to unlock higher missions. Scammer disappears with the deposit.',
                 type='job', severity='high', status='verified', platform='WhatsApp',
                 phone_number='+6581234567', amount_lost=4500.00, report_count=89,
                 created_at=datetime.utcnow()-timedelta(hours=5)),

            Scam(report_id='SS-2025-47186', title='SingPass Account Suspension SMS',
                 description='SMS claiming to be from GovTech states the recipient\'s SingPass has been suspended and requires immediate verification. The linked page mimics the official SingPass portal and steals login credentials for CPF and government digital services.',
                 type='impersonation', severity='high', status='verified', platform='SMS',
                 url='singpass-secure-verify.net', report_count=211,
                 created_at=datetime.utcnow()-timedelta(days=1)),

            Scam(report_id='SS-2025-47170', title='Crypto Investment Telegram Group',
                 description='Telegram group promises guaranteed 30% monthly returns. Members shown fabricated profit screenshots. After depositing via crypto wallet, withdrawals are blocked with excuses about "tax clearance fees" that keep escalating.',
                 type='investment', severity='high', status='verified', platform='Telegram',
                 amount_lost=12000.00, report_count=67,
                 created_at=datetime.utcnow()-timedelta(days=2)),

            Scam(report_id='SS-2025-47155', title='Fake Carousell Buyer Overpayment',
                 description='Buyer on Carousell sends a fabricated PayNow confirmation screenshot claiming overpayment, then requests the seller refund the excess via PayNow immediately. The original payment was never made.',
                 type='ecommerce', severity='medium', status='verified', platform='Carousell',
                 phone_number='+6598765432', amount_lost=320.00, report_count=38,
                 created_at=datetime.utcnow()-timedelta(days=2, hours=3)),

            Scam(report_id='SS-2025-47140', title='DHL Parcel Customs Fee Email',
                 description='Phishing email mimicking DHL branding claims a held parcel requires urgent customs fee payment. A convincing fake payment page captures full credit card details including CVV. Victims report subsequent fraudulent charges far exceeding the initial fee.',
                 type='phishing', severity='medium', status='verified', platform='Email',
                 url='dhl-delivery-sg-customs.com', report_count=55,
                 created_at=datetime.utcnow()-timedelta(days=3)),

            Scam(report_id='SS-2025-47129', title='Romance Scam via Facebook Dating',
                 description='Scammer poses as overseas engineer on Facebook Dating, builds relationship over weeks, then claims to be stranded and urgently needs fund transfers. Requests escalate. No repayment made and profile disappears.',
                 type='love', severity='high', status='flagged', platform='Facebook',
                 amount_lost=8800.00, report_count=12,
                 admin_notes='Only 1 verifiable report — flagged for additional evidence before publishing.',
                 created_at=datetime.utcnow()-timedelta(days=3, hours=5)),

            Scam(report_id='SS-2025-47110', title='Fake SGDeals App APK',
                 description='Link on Telegram promises exclusive SingTel deals and prompts users to sideload an APK file. The malicious app requests SMS permissions and silently intercepts OTPs to take over banking apps. Multiple victims report full account drainage.',
                 type='malware', severity='high', status='verified', platform='Telegram',
                 url='sgdeals-app.top/download', report_count=29,
                 created_at=datetime.utcnow()-timedelta(days=4)),

            Scam(report_id='SS-2025-47098', title='"You Have a Parcel" Phishing SMS',
                 description='Generic SMS claiming a parcel awaits collection links to a page requesting name, address, and credit card details for a SGD 0.50 redelivery fee. Card details are used for larger fraudulent purchases.',
                 type='sms', severity='medium', status='verified', platform='SMS',
                 url='parcels-sg-redeliver.com', report_count=183,
                 created_at=datetime.utcnow()-timedelta(days=5)),

            Scam(report_id='SS-2025-47080', title='SPF Police Impersonation Call',
                 description='Caller claims to be an SPF officer investigating money laundering involving the victim\'s account. Instructs victim to transfer all funds to a "safe government account". Funds are never returned.',
                 type='impersonation', severity='high', status='verified', platform='Phone Call',
                 phone_number='+6567650000', amount_lost=25000.00, report_count=44,
                 created_at=datetime.utcnow()-timedelta(days=5, hours=5)),

            Scam(report_id='SS-2025-47055', title='Forex "Guaranteed Profits" WhatsApp Group',
                 description='WhatsApp group run by supposed forex experts shows fabricated daily profit charts. New members asked to deposit minimum SGD 500 for premium signals. Initial payouts build trust before a large deposit is requested and access cut.',
                 type='investment', severity='medium', status='pending', platform='WhatsApp',
                 amount_lost=1200.00, report_count=19,
                 created_at=datetime.utcnow()-timedelta(days=6)),

            Scam(report_id='SS-2025-47030', title='Shopee Fake Electronics Seller',
                 description='Shopee seller with inflated fake reviews sells electronics at heavily discounted prices. Orders never shipped after payment. Seller responds with excuses then disappears.',
                 type='ecommerce', severity='low', status='flagged', platform='Lazada / Shopee',
                 amount_lost=459.00, report_count=27,
                 admin_notes='Seller provided shipping receipts — pending further verification.',
                 created_at=datetime.utcnow()-timedelta(days=6, hours=3)),

            Scam(report_id='SS-2025-46990', title='Fake MAS Financial Advisory Cold Call',
                 description='Caller claims to be a licensed MAS financial advisor offering an exclusive investment opportunity. High-pressure tactics to get immediate fund transfer. No MAS registration found for the claimed advisory firm.',
                 type='investment', severity='high', status='pending', platform='Phone Call',
                 phone_number='+6531234567', report_count=8,
                 created_at=datetime.utcnow()-timedelta(hours=14)),

            Scam(report_id='SS-2025-46975', title='Instagram Influencer Giveaway Phishing',
                 description='Fake Instagram accounts impersonating local influencers announce prize giveaways. Victims directed to a form requesting NRIC, bank account, and OTP to "claim" prize. Accounts subsequently drained.',
                 type='phishing', severity='medium', status='pending', platform='Instagram',
                 url='sg-giveaway-claim.com', report_count=31,
                 created_at=datetime.utcnow()-timedelta(hours=8)),

            Scam(report_id='SS-2025-46960', title='Netflix Account Suspension Email',
                 description='Phishing email claiming Netflix suspended the account due to failed payment. Convincing Netflix lookalike page requests credit card update. Details harvested for fraudulent purchases.',
                 type='phishing', severity='medium', status='pending', platform='Email',
                 url='netflix-account-sg.com', report_count=14,
                 created_at=datetime.utcnow()-timedelta(hours=3)),
        ]
        db.session.add_all(scams)
        db.session.flush()

        # ── 3. SCANNER INDICATORS ─────────────────────────────────────────
        print("   Seeding scanner indicators...")
        indicators = [
            ScannerIndicator(value='ocbc-verify-login.xyz',       type='URL',    scam_id=scams[0].id,  source='auto',   hit_count=142, added_by=admin1.id, created_at=datetime.utcnow()-timedelta(hours=2)),
            ScannerIndicator(value='singpass-secure-verify.net',  type='URL',    scam_id=scams[2].id,  source='auto',   hit_count=211, added_by=admin2.id, created_at=datetime.utcnow()-timedelta(days=1)),
            ScannerIndicator(value='+6581234567',                  type='Phone',  scam_id=scams[1].id,  source='auto',   hit_count=89,  added_by=admin1.id, created_at=datetime.utcnow()-timedelta(hours=5)),
            ScannerIndicator(value='dhl-delivery-sg-customs.com', type='Domain', scam_id=scams[5].id,  source='auto',   hit_count=55,  added_by=admin3.id, created_at=datetime.utcnow()-timedelta(days=3)),
            ScannerIndicator(value='sgdeals-app.top',             type='Domain', scam_id=scams[7].id,  source='auto',   hit_count=29,  added_by=admin1.id, created_at=datetime.utcnow()-timedelta(days=4)),
            ScannerIndicator(value='parcels-sg-redeliver.com',    type='Domain', scam_id=scams[8].id,  source='auto',   hit_count=183, added_by=admin2.id, created_at=datetime.utcnow()-timedelta(days=5)),
            ScannerIndicator(value='+6598765432',                  type='Phone',  scam_id=scams[4].id,  source='manual', hit_count=38,  added_by=admin1.id, created_at=datetime.utcnow()-timedelta(days=2)),
            ScannerIndicator(value='fake-mas-invest.sg',          type='Domain', scam_id=None,          source='manual', hit_count=14,  added_by=admin1.id, created_at=datetime.utcnow()-timedelta(days=6)),
        ]
        db.session.add_all(indicators)

        # ── 4. SPAM SESSIONS ─────────────────────────────────────────────
        print("   Seeding spam sessions...")
        spam_sessions = [
            SpamSession(session_token='sess_a3f9b1', ip_address='103.24.77.12',  reason='5 submissions in 12 min (rate limit hit)',          submit_count=5, is_blocked=False, created_at=datetime.utcnow()-timedelta(minutes=8)),
            SpamSession(session_token='sess_c72de4', ip_address='118.200.55.89', reason='Duplicate URL submitted 3× in 1 hour',              submit_count=3, is_blocked=False, created_at=datetime.utcnow()-timedelta(minutes=22)),
            SpamSession(session_token='sess_88fa02', ip_address='1.179.200.45',  reason='Identical description text across 4 reports',        submit_count=4, is_blocked=False, created_at=datetime.utcnow()-timedelta(minutes=45)),
            SpamSession(session_token='sess_11dc77', ip_address='45.125.66.201', reason='Non-SG IP submitting high-volume reports',           submit_count=9, is_blocked=True,  created_at=datetime.utcnow()-timedelta(hours=1)),
            SpamSession(session_token='sess_5b3e90', ip_address='202.12.94.33',  reason='CAPTCHA failed 3 consecutive times',                submit_count=3, is_blocked=False, created_at=datetime.utcnow()-timedelta(hours=2)),
            SpamSession(session_token='sess_f04ab2', ip_address='103.56.12.78',  reason='Gibberish/test content detected by filter',          submit_count=2, is_blocked=False, created_at=datetime.utcnow()-timedelta(hours=3)),
            SpamSession(session_token='sess_d19cc5', ip_address='185.220.101.4', reason='Known VPN/proxy exit node flagged',                 submit_count=1, is_blocked=True,  created_at=datetime.utcnow()-timedelta(hours=5)),
        ]
        db.session.add_all(spam_sessions)

        # ── 5. RATE LIMIT RULES ───────────────────────────────────────────
        print("   Seeding rate limit rules...")
        rules = [
            RateLimitRule(rule_key='max_per_hour',      rule_value=5,  description='Max reports per IP per hour'),
            RateLimitRule(rule_key='cooldown_minutes',  rule_value=60, description='Cooldown after rate limit hit (minutes)'),
            RateLimitRule(rule_key='dupe_window_hours', rule_value=24, description='Hours before same URL/title can be resubmitted'),
            RateLimitRule(rule_key='captcha_after',     rule_value=3,  description='Trigger CAPTCHA after N submissions per session'),
        ]
        db.session.add_all(rules)

        # ── 6. SITE SETTINGS ─────────────────────────────────────────────
        print("   Seeding site settings...")
        settings = [
            SiteSetting(setting_key='site_name',              setting_value='ScamWatch'),
            SiteSetting(setting_key='admin_email',            setting_value='admin@scamwatch.sg'),
            SiteSetting(setting_key='require_approval',       setting_value='yes'),
            SiteSetting(setting_key='auto_flag_threshold',    setting_value='3'),
            SiteSetting(setting_key='auto_verify_threshold',  setting_value='10'),
            SiteSetting(setting_key='auto_block_threshold',   setting_value='5'),
        ]
        db.session.add_all(settings)

        # ── 7. AUDIT LOG ──────────────────────────────────────────────────
        print("   Seeding audit log...")
        logs = [
            AuditLog(admin_id=admin1.id, action='Verified',          target_type='scam',         target_id=scams[0].id, target_ref='SS-2025-47201',     detail='Fake OCBC Bank Login Page',           created_at=datetime.utcnow()-timedelta(hours=2)),
            AuditLog(admin_id=admin2.id, action='Flagged',           target_type='scam',         target_id=scams[6].id, target_ref='SS-2025-47129',     detail='Romance Scam — unverifiable',         created_at=datetime.utcnow()-timedelta(hours=3)),
            AuditLog(admin_id=admin1.id, action='Added Indicator',   target_type='indicator',    target_id=indicators[0].id, target_ref='ocbc-verify-login.xyz', detail='Auto from verified report',  created_at=datetime.utcnow()-timedelta(hours=2, minutes=5)),
            AuditLog(admin_id=admin3.id, action='Removed',           target_type='scam',         target_id=None,        target_ref='SS-2025-46800',     detail='False report — confirmed legitimate', created_at=datetime.utcnow()-timedelta(days=1)),
            AuditLog(admin_id=admin1.id, action='Verified',          target_type='scam',         target_id=scams[2].id, target_ref='SS-2025-47186',     detail='SingPass Suspension SMS',             created_at=datetime.utcnow()-timedelta(days=1, hours=2)),
            AuditLog(admin_id=admin2.id, action='Blocked IP',        target_type='spam_session', target_id=4,           target_ref='45.125.66.201',     detail='High-volume non-SG submissions',      created_at=datetime.utcnow()-timedelta(days=2)),
            AuditLog(admin_id=admin1.id, action='Bulk Verified',     target_type='scam',         target_id=None,        target_ref='4 reports',          detail='Batch verification',                 created_at=datetime.utcnow()-timedelta(days=2, hours=3)),
            AuditLog(admin_id=admin3.id, action='Added Indicator',   target_type='indicator',    target_id=5,           target_ref='sgdeals-app.top',   detail='Malware APK distribution site',       created_at=datetime.utcnow()-timedelta(days=3)),
            AuditLog(admin_id=admin1.id, action='Login',             target_type='admin',        target_id=admin1.id,   target_ref='admin@scamwatch.sg', detail='Admin logged in',                    created_at=datetime.utcnow()),
        ]
        db.session.add_all(logs)

        db.session.commit()

        print("\n✅ Seed complete!\n")
        print(f"   admins             : {Admin.query.count()}")
        print(f"   scam reports       : {Scam.query.count()}")
        print(f"   scanner indicators : {ScannerIndicator.query.count()}")
        print(f"   spam sessions      : {SpamSession.query.count()}")
        print(f"   rate limit rules   : {RateLimitRule.query.count()}")
        print(f"   site settings      : {SiteSetting.query.count()}")
        print(f"   audit log entries  : {AuditLog.query.count()}")
        print("\nAdmin login credentials:")
        print("   admin@scamwatch.sg    /  admin123   (Super Admin)")
        print("   sarah.t@scamwatch.sg  /  sarah456   (Moderator)")
        print("   m.lim@scamwatch.sg    /  marcus789  (Analyst)\n")


if __name__ == '__main__':
    seed()
