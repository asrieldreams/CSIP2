import pymysql
import os
import ssl
from dotenv import load_dotenv

# ── Load .env ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(BASE_DIR, '.env'))

print("DB_HOST:", os.getenv("DB_HOST"))
print("DB_PORT:", os.getenv("DB_PORT"))
print("DB_NAME:", os.getenv("DB_NAME"))

CA_CERT = os.path.join(BASE_DIR, 'ca.pem')

# ── Build SSL context ──────────────────────────────────────
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname  = False
ssl_ctx.verify_mode     = ssl.CERT_NONE  # skip cert verification

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
        ssl_context=ssl_ctx,            # pass full SSL context
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10
    )
    return _connection