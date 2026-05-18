import pymysql
import os
import ssl
from dotenv import load_dotenv

load_dotenv()

ssl_context = ssl.create_default_context()

connection = pymysql.connect(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    ssl=ssl_context,
    cursorclass=pymysql.cursors.DictCursor
)

def get_connection():
    return connection