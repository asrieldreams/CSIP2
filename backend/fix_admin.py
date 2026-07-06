import bcrypt
from db import get_connection

password = 'Admin@1234'
hashed   = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

conn = get_connection()
with conn.cursor() as cursor:
    # Update ALL admins with a fresh valid hash
    cursor.execute("""
        UPDATE admins SET password = %s WHERE email = 'admin@scamwatch.sg'
    """, (hashed.decode('utf-8'),))
conn.commit()
print(f"✅ Password fixed for admin@scamwatch.sg")
print(f"   Password: {password}")