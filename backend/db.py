import pymysql
import os
import ssl
from dotenv import load_dotenv

load_dotenv()

# ── Point to your downloaded ca.pem file ──────────────────
ssl_context = ssl.create_default_context(
    cafile=os.path.join(os.path.dirname(__file__), 'ca.pem')
)

def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        ssl={"ca": os.path.join(os.path.dirname(__file__), 'ca.pem')},
        cursorclass=pymysql.cursors.DictCursor
    )