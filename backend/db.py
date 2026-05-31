import pymysql
import os
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(BASE_DIR, '.env'))

print("DB_HOST:", os.getenv("DB_HOST"))
print("DB_PORT:", os.getenv("DB_PORT"))
print("DB_NAME:", os.getenv("DB_NAME"))

_connection = None

def get_connection():
    global _connection

    try:
        if _connection is not None:
            _connection.ping(reconnect=True)
            return _connection
    except Exception:
        pass

    _connection = pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        ssl={"ssl": {}},                # enable SSL, skip cert verification
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10
    )
    return _connection