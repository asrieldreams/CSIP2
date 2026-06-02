from db import get_connection

conn = get_connection()

with conn.cursor() as cursor:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        indicator_type VARCHAR(50),
        indicator VARCHAR(255),
        scam_type VARCHAR(50),
        description TEXT,
        source VARCHAR(50),
        status ENUM('pending','approved','rejected') DEFAULT 'pending',
        list_type ENUM('blacklist','whitelist') NULL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

conn.commit()
print("reports table created")