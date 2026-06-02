from db import get_connection

conn = get_connection()

with conn.cursor() as cursor:
    cursor.execute("DESCRIBE reports")
    columns = cursor.fetchall()

print(columns)