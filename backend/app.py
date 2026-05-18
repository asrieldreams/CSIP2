from flask import Flask
from db import get_connection

app = Flask(__name__)

@app.route("/")
def home():
    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            cursor.execute("SELECT NOW() as current_time")
            result = cursor.fetchone()

        return {
            "status": "connected",
            "time": str(result["current_time"])
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":
    app.run(debug=True)