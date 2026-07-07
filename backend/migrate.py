# ============================================================
#  CSIP2 — Database Migration Script
#  Merges scamwatch schema INTO the existing backend database
#
#  What this does:
#  1. Creates all new scamwatch tables in defaultdb
#  2. Migrates existing 'reports' data → 'scams' + 'scanner_indicators'
#  3. Keeps the original 'reports' table intact (safe rollback)
#
#  Run from project root:
#  python backend/migrate.py
# ============================================================

import os
import re
import random
from datetime import datetime
from dotenv import load_dotenv
import pymysql

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# ── Connect to database ────────────────────────────────────
conn = pymysql.connect(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    ssl={"ssl": {}},
    cursorclass=pymysql.cursors.DictCursor,
    connect_timeout=10
)
print(f"✅ Connected to: {os.getenv('DB_HOST')}\n")


# ── Scam type mapping ──────────────────────────────────────
SCAM_TYPE_MAP = {
    'Phishing':        'phishing',
    'E-Commerce Scam': 'ecommerce',
    'Impersonation':   'impersonation',
    'Love Scam':       'love',
    'Investment Scam': 'investment',
    'SMS Scam':        'sms',
    'Job Scam':        'job',
    'Others':          'other',
}

def generate_report_id():
    year = datetime.utcnow().year
    num  = random.randint(10000, 99999)
    return f"SS-{year}-{num}"


# ============================================================
#  STEP 1 — Create new scamwatch tables
# ============================================================
print("📦 Step 1 — Creating new tables...")

CREATE_TABLES = [

    # scams
    """CREATE TABLE IF NOT EXISTS scams (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        report_id    VARCHAR(20)  NOT NULL UNIQUE,
        title        VARCHAR(255) NOT NULL,
        description  TEXT         NOT NULL,
        type         ENUM('phishing','sms','investment','ecommerce',
                          'impersonation','job','love','malware','other') NOT NULL,
        severity     ENUM('low','medium','high')                       DEFAULT 'medium',
        status       ENUM('pending','verified','flagged','removed')    DEFAULT 'pending',
        platform     VARCHAR(50),
        url          VARCHAR(500),
        phone_number VARCHAR(30),
        amount_lost  DECIMAL(10,2),
        report_count INT          DEFAULT 1,
        admin_notes  TEXT,
        created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
        updated_at   DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",

    # scanner_indicators
    """CREATE TABLE IF NOT EXISTS scanner_indicators (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        value      VARCHAR(500) NOT NULL,
        type       ENUM('URL','Domain','Phone','Email Domain') NOT NULL,
        scam_id    INT,
        source     ENUM('auto','manual') DEFAULT 'auto',
        hit_count  INT          DEFAULT 0,
        added_by   INT,
        created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scam_id) REFERENCES scams(id) ON DELETE SET NULL
    )""",

    # spam_sessions
    """CREATE TABLE IF NOT EXISTS spam_sessions (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        session_token VARCHAR(64)  NOT NULL,
        ip_address    VARCHAR(45),
        reason        VARCHAR(255) NOT NULL,
        submit_count  INT          DEFAULT 1,
        is_blocked    TINYINT(1)   DEFAULT 0,
        created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP
    )""",

    # rate_limit_rules
    """CREATE TABLE IF NOT EXISTS rate_limit_rules (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        rule_key    VARCHAR(50)  NOT NULL UNIQUE,
        rule_value  INT          NOT NULL,
        description VARCHAR(255),
        updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",

    # site_settings
    """CREATE TABLE IF NOT EXISTS site_settings (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        setting_key   VARCHAR(50)  NOT NULL UNIQUE,
        setting_value VARCHAR(255) NOT NULL,
        updated_at    DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",

    # audit_log
    """CREATE TABLE IF NOT EXISTS audit_log (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        admin_id    INT,
        action      VARCHAR(50)  NOT NULL,
        target_type VARCHAR(50),
        target_id   INT,
        target_ref  VARCHAR(100),
        detail      VARCHAR(255),
        created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
    )""",

    # bot_users
    """CREATE TABLE IF NOT EXISTS bot_users (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        telegram_id BIGINT       NOT NULL UNIQUE,
        username    VARCHAR(100),
        first_name  VARCHAR(100),
        is_blocked  TINYINT(1)   DEFAULT 0,
        first_seen  DATETIME     DEFAULT CURRENT_TIMESTAMP,
        last_seen   DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",

    # bot_history
    """CREATE TABLE IF NOT EXISTS bot_history (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        telegram_id  BIGINT       NOT NULL,
        indicator    VARCHAR(500) NOT NULL,
        scam_type    VARCHAR(50),
        scam_id      INT,
        report_id    VARCHAR(20),
        submitted_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (telegram_id) REFERENCES bot_users(telegram_id) ON DELETE CASCADE
    )""",

    # bot_rate_limits
    """CREATE TABLE IF NOT EXISTS bot_rate_limits (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        telegram_id BIGINT       NOT NULL,
        action      VARCHAR(20)  DEFAULT 'report',
        actioned_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (telegram_id) REFERENCES bot_users(telegram_id) ON DELETE CASCADE
    )""",

    # bot_check_logs
    """CREATE TABLE IF NOT EXISTS bot_check_logs (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        telegram_id BIGINT,
        indicator   VARCHAR(500) NOT NULL,
        result      VARCHAR(20),
        source      VARCHAR(20)  DEFAULT 'command',
        chat_type   VARCHAR(20)  DEFAULT 'private',
        checked_at  DATETIME     DEFAULT CURRENT_TIMESTAMP
    )""",

    # bot_group_chats
    """CREATE TABLE IF NOT EXISTS bot_group_chats (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        chat_id     BIGINT       NOT NULL UNIQUE,
        chat_title  VARCHAR(255),
        is_active   TINYINT(1)   DEFAULT 1,
        alerts_sent INT          DEFAULT 0,
        added_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
        last_alert  DATETIME
    )""",
]

with conn.cursor() as cursor:
    for sql in CREATE_TABLES:
        table_name = sql.split('TABLE IF NOT EXISTS ')[1].split(' ')[0]
        cursor.execute(sql)
        print(f"  ✅ Table ready: {table_name}")

conn.commit()
print()


# ============================================================
#  STEP 2 — Seed default rate limit rules and site settings
# ============================================================
print("⚙️  Step 2 — Seeding default settings...")

with conn.cursor() as cursor:
    # Rate limit rules
    rules = [
        ('max_reports_per_hour',    10, 'Max reports per IP per hour'),
        ('max_reports_per_day',     50, 'Max reports per IP per day'),
        ('bot_max_reports_per_min',  5, 'Bot: max reports per minute per user'),
        ('bot_max_checks_per_min',  20, 'Bot: max checks per minute per user'),
    ]
    for key, val, desc in rules:
        cursor.execute("""
            INSERT INTO rate_limit_rules (rule_key, rule_value, description)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE rule_value = VALUES(rule_value)
        """, (key, val, desc))

    # Site settings
    settings = [
        ('site_name',        'CSIP2 ScamWatch'),
        ('approval_mode',    'manual'),
        ('contact_email',    'admin@csip2.com'),
        ('auto_verify',      'false'),
    ]
    for key, val in settings:
        cursor.execute("""
            INSERT INTO site_settings (setting_key, setting_value)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
        """, (key, val))

conn.commit()
print("  ✅ Default settings seeded\n")


# ============================================================
#  STEP 3 — Migrate reports → scams + scanner_indicators
# ============================================================
print("🔄 Step 3 — Migrating reports to scams table...")

with conn.cursor() as cursor:
    cursor.execute("""
        SELECT id, indicator_type, indicator, scam_type,
               description, source, status, list_type, submitted_at
        FROM reports
        WHERE status = 'approved'
        ORDER BY submitted_at ASC
    """)
    reports = cursor.fetchall()

print(f"  Found {len(reports)} approved reports to migrate\n")

migrated    = 0
skipped     = 0
used_ids    = set()

for r in reports:
    indicator      = r['indicator']
    indicator_type = r['indicator_type']
    scam_type_raw  = r['scam_type'] or 'Others'
    description    = r['description'] or f"Reported via {r['source']}"
    list_type      = r['list_type']
    submitted_at   = r['submitted_at']

    # Map scam type
    api_type = SCAM_TYPE_MAP.get(scam_type_raw, 'other')

    # Map list_type → severity + status
    severity = 'high'   if list_type == 'blacklist' else 'medium'
    status   = 'verified' if list_type in ('blacklist', 'whitelist') else 'pending'

    # Map indicator to correct column
    url          = indicator if indicator_type == 'url'   else None
    phone_number = indicator if indicator_type == 'phone' else None
    title        = f"{scam_type_raw}: {indicator[:60]}"

    # Map indicator type to scanner type
    scanner_type_map = {
        'url':     'URL',
        'phone':   'Phone',
        'email':   'Email Domain',
        'message': None,   # messages can't be scanner indicators
    }
    scanner_type = scanner_type_map.get(indicator_type)

    # Generate unique report ID
    report_id = generate_report_id()
    while report_id in used_ids:
        report_id = generate_report_id()
    used_ids.add(report_id)

    try:
        with conn.cursor() as cursor:
            # Insert into scams
            cursor.execute("""
                INSERT INTO scams
                    (report_id, title, description, type, severity,
                     status, platform, url, phone_number, report_count, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                report_id, title, description, api_type, severity,
                status, r['source'], url, phone_number, 1, submitted_at
            ))
            scam_id = cursor.lastrowid

            # Insert scanner indicator (only for url/phone/email)
            if scanner_type and indicator:
                cursor.execute("""
                    INSERT INTO scanner_indicators
                        (value, type, scam_id, source, created_at)
                    VALUES (%s, %s, %s, 'auto', %s)
                """, (indicator, scanner_type, scam_id, submitted_at))

        conn.commit()
        badge = '🔴' if list_type == 'blacklist' else '🟡'
        print(f"  {badge} [{api_type}] {indicator[:50]} → {report_id}")
        migrated += 1

    except Exception as e:
        print(f"  ⚠️  Skipped {indicator[:50]}: {e}")
        skipped += 1

print()


# ============================================================
#  STEP 4 — Summary
# ============================================================
with conn.cursor() as cursor:
    cursor.execute("SELECT COUNT(*) as c FROM scams")
    total_scams = cursor.fetchone()['c']

    cursor.execute("SELECT COUNT(*) as c FROM scanner_indicators")
    total_indicators = cursor.fetchone()['c']

conn.close()

print("=" * 50)
print("✅ MIGRATION COMPLETE")
print("=" * 50)
print(f"  Migrated:  {migrated} reports")
print(f"  Skipped:   {skipped} reports")
print(f"  Scams:     {total_scams} total in scams table")
print(f"  Indicators:{total_indicators} total in scanner_indicators")
print()
print("📋 New tables created:")
print("  scams, scanner_indicators, spam_sessions")
print("  rate_limit_rules, site_settings, audit_log")
print("  bot_users, bot_history, bot_rate_limits")
print("  bot_check_logs, bot_group_chats")
print()
print("⚠️  Original 'reports' table is UNCHANGED — safe rollback available")
