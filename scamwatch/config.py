import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ── Database (reads from .env) ──────────────────────────────────────────
    DB_HOST     = os.getenv('DB_HOST',     'localhost')
    DB_PORT     = os.getenv('DB_PORT',     '3306')
    DB_USER     = os.getenv('DB_USER',     'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME     = os.getenv('DB_NAME',     'scamwatch')
    DB_SSL      = os.getenv('DB_SSL',      'false').lower() == 'true'

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        f"?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False  # set True to print SQL queries for debugging

    # SSL connect_args — required for Aiven cloud MySQL
    # If DB_SSL=true in .env, SSL is enabled automatically
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "ssl": {"ssl_disabled": not DB_SSL}
        } if DB_SSL else {}
    }

    # ── Flask secrets ────────────────────────────────────────────────────────
    SECRET_KEY       = os.getenv('SECRET_KEY',       'change-me')
    JWT_SECRET       = os.getenv('JWT_SECRET',       'change-jwt')
    JWT_EXPIRY_HOURS = int(os.getenv('JWT_EXPIRY_HOURS', 8))

    # ── Pagination ───────────────────────────────────────────────────────────
    SCAMS_PER_PAGE = 12
