import bcrypt
from db import get_connection

conn = get_connection()
with conn.cursor() as cursor:
    # Check what's in the admins table
    cursor.execute("SELECT id, name, email, password FROM admins")
    rows = cursor.fetchall()
    print(f"Found {len(rows)} admin(s):")
    for r in rows:
        print(f"  ID: {r['id']} | Name: {r['name']} | Email: {r['email']}")

        # Test password
        test_password = 'Admin@1234'
        match = bcrypt.checkpw(
            test_password.encode('utf-8'),
            r['password'].encode('utf-8')
        )
        print(f"  Password 'Admin@1234' matches: {match}")