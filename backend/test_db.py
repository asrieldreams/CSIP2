import pymysql

try:
    conn = pymysql.connect(
        host="scamawareness-scamawareness.e.aivencloud.com",
        port=22420,
        user="avnadmin",
        password="YOUR_PASSWORD",
        database="defaultdb"
    )

    print("CONNECTED")

except Exception as e:
    print("ERROR:")
    print(e)