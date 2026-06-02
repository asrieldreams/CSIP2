from db import get_connection

conn = get_connection()

with conn.cursor() as cursor:
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()

print(tables)