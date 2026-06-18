from db import get_connection

conn = get_connection()

with conn.cursor() as cursor:
    # Create reports table (v2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        indicator_type ENUM('url', 'phone', 'email', 'message') NOT NULL,
        indicator VARCHAR(500) NOT NULL,
        scam_type ENUM('PhSG', 'Phishing', 'E-Commerce Scam', 'Impersonation', 'Love Scam', 'Investment Scam', 'Others') NOT NULL DEFAULT 'Others',
        description TEXT,
        source ENUM('website', 'telegram', 'extension') NOT NULL DEFAULT 'website',
        status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
        list_type ENUM('blacklist', 'whitelist') NULL DEFAULT NULL,
        submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at DATETIME NULL
    )
    """)

    # Create overrides table (v2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS overrides (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_id INT NOT NULL,
        user_ip VARCHAR(100) NOT NULL,
        overridden_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
    )
    """)

conn.commit()
print("Database tables updated to Schema V2 successfully!")
