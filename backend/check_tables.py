from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    # Check admins table structure
    cursor.execute("DESCRIBE admins")
    print("=== ADMINS TABLE ===")
    for row in cursor.fetchall():
        print(row)

    print()

    # Check reports table structure
    cursor.execute("DESCRIBE reports")
    print("=== REPORTS TABLE ===")
    for row in cursor.fetchall():
        print(row)