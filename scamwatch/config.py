import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ── Database ──────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER','root')}:"
        f"{os.getenv('DB_PASSWORD','password')}@"
        f"{os.getenv('DB_HOST','localhost')}/"
        f"{os.getenv('DB_NAME','scamwatch')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Security ──────────────────────────────────────────────
    SECRET_KEY      = os.getenv('SECRET_KEY', 'change-me-in-production')
    JWT_SECRET      = os.getenv('JWT_SECRET', 'change-jwt-secret-too')
    JWT_EXPIRY_HOURS = int(os.getenv('JWT_EXPIRY_HOURS', 8))

    # ── Pagination ────────────────────────────────────────────
    SCAMS_PER_PAGE  = 12
