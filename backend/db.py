# ============================================================
#  CSIP2 — Database Connection
#  db.py — Reuses a persistent connection per thread, with
#  automatic ping-based reconnect if Aiven drops an idle connection.
# ============================================================

import pymysql
import os
import threading
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(BASE_DIR, '.env'))

_local = threading.local()


def _create_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        ssl={"ssl": {}},
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        read_timeout=30,
        write_timeout=30,
        autocommit=False,
    )


def get_connection():
    """
    Returns a connection reused for the current thread whenever possible,
    avoiding a fresh TLS handshake to Aiven on every call.
    Automatically reconnects if the cached connection went stale,
    timed out, or was explicitly closed elsewhere in the code.
    """
    conn = getattr(_local, "conn", None)

    if conn is not None:
        try:
            conn.ping(reconnect=True)
            return conn
        except Exception:
            pass  # couldn't be revived — fall through and open a fresh one

    conn = _create_connection()
    _local.conn = conn
    return conn