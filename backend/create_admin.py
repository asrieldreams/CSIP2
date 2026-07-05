import bcrypt
from db import get_connection

name     = 'Admin'
email    = 'admin@csip2.com'
password = 'Admin@1234'

hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

try:
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            INSERT INTO admins (name, email, password, role)
            VALUES (%s, %s, %s, %s)
        """, (name, email, hashed.decode('utf-8'), 'super_admin'))
    conn.commit()
    print(f"✅ Admin created! Email: {email} Password: {password}")
except Exception as e:
    print(f"❌ Error: {e}")