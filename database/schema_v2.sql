-- ============================================================
--  CSIP2 — Crowdsourced Scam Intelligence Platform 2
--  Database Schema v2
--  Updated: Blacklist/Whitelist system + Extension submission
--  Owner: Kaden (Backend Lead)
-- ============================================================

CREATE DATABASE IF NOT EXISTS csip2;
USE csip2;

-- ============================================================
--  TABLE 1: reports
--  Stores all scam reports submitted via website, Telegram bot,
--  OR the browser extension
-- ============================================================
CREATE TABLE reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,

    indicator_type  ENUM('url', 'phone', 'email', 'message') NOT NULL,

    -- The actual scam content
    indicator       VARCHAR(500) NOT NULL,

    scam_type       ENUM(
                        'Phishing',
                        'E-Commerce Scam',
                        'Impersonation',
                        'Love Scam',
                        'Investment Scam',
                        'Others'
                    ) NOT NULL DEFAULT 'Others',

    description     TEXT,

    -- Where was this submitted from?
    source          ENUM('website', 'telegram', 'extension') NOT NULL DEFAULT 'website',

    -- Admin reviews before going public
    status          ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',

    -- ★ NEW: Blacklist = hard block, Whitelist = soft warn with override
    -- NULL = not yet classified (pending review)
    list_type       ENUM('blacklist', 'whitelist') NULL DEFAULT NULL,

    submitted_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at     DATETIME NULL
);

-- ============================================================
--  TABLE 2: overrides
--  ★ NEW: Tracks when a user chose to proceed past a whitelist warning
--  Useful for audit trail and admin reporting
-- ============================================================
CREATE TABLE overrides (
    id              INT AUTO_INCREMENT PRIMARY KEY,

    -- Which report/indicator was overridden
    report_id       INT NOT NULL,

    -- IP address of the user who chose to proceed
    user_ip         VARCHAR(100) NOT NULL,

    -- Timestamp of when they clicked "proceed anyway"
    overridden_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

-- ============================================================
--  TABLE 3: admins
--  Stores admin login accounts
--  Owner: Zavier (Security)
-- ============================================================
CREATE TABLE admins (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(100) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,  -- bcrypt hashed
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  TABLE 4: rate_limits
--  Prevents spamming from website, bot, AND extension
--  Owner: Zavier (Security)
-- ============================================================
CREATE TABLE rate_limits (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    identifier      VARCHAR(100) NOT NULL,  -- IP or Telegram user ID
    report_count    INT NOT NULL DEFAULT 1,
    window_start    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  SAMPLE DATA
-- ============================================================

-- Blacklisted URLs (hard block — cannot proceed)
INSERT INTO reports (indicator_type, indicator, scam_type, description, source, status, list_type) VALUES
('url', 'http://myinfo-verify-sg.com',   'Phishing',        'Fake Singpass/MyInfo page stealing NRIC and password.', 'website',   'approved', 'blacklist'),
('url', 'http://dbs-secure-login.net',   'Phishing',        'Fake DBS bank login page.', 'telegram',  'approved', 'blacklist'),
('url', 'http://shopee-lucky-draw.xyz',  'E-Commerce Scam', 'Fake Shopee lucky draw collecting credit card details.', 'website',   'approved', 'blacklist'),
('url', 'http://grab-promo-2024.com',    'E-Commerce Scam', 'Fake Grab promo site collecting personal info.', 'extension', 'approved', 'blacklist');

-- Whitelisted URLs (soft warn — user can override and proceed)
INSERT INTO reports (indicator_type, indicator, scam_type, description, source, status, list_type) VALUES
('url', 'http://sg-lucky-draw.com',      'E-Commerce Scam', 'Suspected scam but unverified. Proceed with caution.', 'website',   'approved', 'whitelist'),
('url', 'http://investment-sg.net',      'Investment Scam', 'Reported by 2 users, under review.', 'telegram',  'approved', 'whitelist'),
('url', 'http://parcel-track-sg.com',    'Phishing',        'Possible fake parcel tracking site. Not fully confirmed.', 'extension', 'approved', 'whitelist');

-- Phone numbers and emails (no list_type needed — not URLs)
INSERT INTO reports (indicator_type, indicator, scam_type, description, source, status) VALUES
('phone', '+65 8123 4567', 'Impersonation',  'Caller claimed to be SPF officer, demanded payment.', 'website', 'approved'),
('phone', '+65 9876 5432', 'Love Scam',      'Person on dating app asked for money after 2 weeks.',  'telegram', 'approved'),
('email', 'support@posb-alert-sg.com', 'Phishing', 'Fake POSB email saying account is suspended.', 'website', 'approved');

-- Pending reports (not yet reviewed by admin)
INSERT INTO reports (indicator_type, indicator, scam_type, description, source, status) VALUES
('url',   'http://unknown-promo.sg', 'Others', 'Not sure if scam, looks suspicious.', 'extension', 'pending'),
('phone', '+65 6999 0000',           'Others', 'Received weird automated call.',      'telegram',  'pending');

-- Default admin account (password: Admin@1234 — CHANGE before deployment)
INSERT INTO admins (username, password_hash) VALUES
('admin', '$2b$12$KIXyV3zG1Qz5v5v5v5v5vOQz5v5v5v5v5v5v5v5v5v5v5v5v5v5v');

-- ============================================================
--  USEFUL QUERIES (for reference)
-- ============================================================

-- Check if a URL is blacklisted (hard block)
-- SELECT * FROM reports WHERE indicator = ? AND status = 'approved' AND list_type = 'blacklist';

-- Check if a URL is whitelisted (soft warn)
-- SELECT * FROM reports WHERE indicator = ? AND status = 'approved' AND list_type = 'whitelist';

-- Get all approved reports for public feed
-- SELECT * FROM reports WHERE status = 'approved' ORDER BY submitted_at DESC;

-- Get all pending reports for admin panel
-- SELECT * FROM reports WHERE status = 'pending' ORDER BY submitted_at ASC;

-- Count how many users overrode a whitelist warning
-- SELECT report_id, COUNT(*) as override_count FROM overrides GROUP BY report_id;
