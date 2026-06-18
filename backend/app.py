# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Backend API — app.py
#  Owner: Kaden (Backend Lead)
# ============================================================

from flask_cors import CORS #new import
from flask import Flask, request, jsonify, session
from db import get_connection
from datetime import datetime

from admin import admin_bp
from security import rate_limit, validate_report_payload, sanitise_text

app = Flask(__name__)
CORS(app) # This allows your browser extension to safely make API requests
app.secret_key = 'csip2-secret-change-this-before-deployment'

# Register admin routes
app.register_blueprint(admin_bp)


# ============================================================
#  TEST ROUTE — confirms DB connection is working
#  GET /
# ============================================================
@app.route('/')
def home():
    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            # Check database connection and list tables
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()

        return jsonify({
            'status': 'connected',
            'database': 'online',
            'tables_found': len(tables),
            'tables': tables
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ============================================================
#  ENDPOINT 1: POST /report
#  Submit a new scam report (website, bot, or extension)
# ============================================================
@app.route('/report', methods=['POST'])
@rate_limit
def submit_report():
    data = request.get_json()

    # Validate all fields using Zavier's security.py
    is_valid, error = validate_report_payload(data)
    if not is_valid:
        return jsonify({'error': error}), 400

    # Sanitise free text before saving
    indicator   = sanitise_text(data['indicator'])
    description = sanitise_text(data.get('description', ''))

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO reports (indicator_type, indicator, scam_type, description, source)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                data['indicator_type'],
                indicator,
                data['scam_type'],
                description,
                data['source']
            ))
        conn.commit()
        return jsonify({'message': 'Report submitted successfully. Pending admin review.'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
#  ENDPOINT 2: GET /reports
#  Get all approved reports for the public feed
#  Used by: Caden's frontend
# ============================================================
@app.route('/reports', methods=['GET'])
def get_reports():
    scam_type = request.args.get('scam_type')
    keyword   = request.args.get('keyword')
    list_type = request.args.get('list_type')

    query  = """SELECT id, indicator_type, indicator, scam_type,
                       description, source, list_type, submitted_at
                FROM reports WHERE status = 'approved'"""
    params = []

    if scam_type:
        query += " AND scam_type = %s"
        params.append(scam_type)
    if list_type:
        query += " AND list_type = %s"
        params.append(list_type)
    if keyword:
        query += " AND (indicator LIKE %s OR description LIKE %s)"
        params.extend([f'%{keyword}%', f'%{keyword}%'])

    query += " ORDER BY submitted_at DESC"

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()

        reports = []
        for row in rows:
            reports.append({
                'id':             row['id'],
                'indicator_type': row['indicator_type'],
                'indicator':      row['indicator'],
                'scam_type':      row['scam_type'],
                'description':    row['description'],
                'source':         row['source'],
                'list_type':      row['list_type'],
                'submitted_at':   str(row['submitted_at'])
            })

        return jsonify({'reports': reports, 'total': len(reports)}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
#  ENDPOINT 3: GET /check
#  Check if a URL/phone/email is flagged
#  Used by: Bin Zheng's extension + Alyosius's bot
# ============================================================
@app.route('/check', methods=['GET'])
def check_indicator():
    indicator = request.args.get('url') or request.args.get('indicator')

    if not indicator:
        return jsonify({'error': 'Missing indicator parameter'}), 400

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, list_type, scam_type, description
                FROM reports
                WHERE indicator = %s AND status = 'approved'
                ORDER BY submitted_at DESC
                LIMIT 1
            """, (indicator.strip(),))
            row = cursor.fetchone()

        if not row:
            return jsonify({
                'status':    'clean',
                'indicator': indicator,
                'message':   'No reports found for this indicator.'
            }), 200

        if row['list_type'] == 'blacklist':
            return jsonify({
                'status':      'blacklist',
                'report_id':   row['id'],
                'indicator':   indicator,
                'scam_type':   row['scam_type'],
                'description': row['description'],
                'message':     'WARNING: This has been confirmed as a scam. Do not proceed.'
            }), 200

        elif row['list_type'] == 'whitelist':
            return jsonify({
                'status':      'whitelist',
                'report_id':   row['id'],
                'indicator':   indicator,
                'scam_type':   row['scam_type'],
                'description': row['description'],
                'message':     'CAUTION: This has been flagged by the community. Proceed with care.'
            }), 200

        else:
            return jsonify({
                'status':    'flagged',
                'indicator': indicator,
                'message':   'This indicator has been reported but is under review.'
            }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
#  ENDPOINT 4: POST /override
#  Log when user clicks "Proceed Anyway" on a whitelist warning
#  Used by: Bin Zheng's extension
# ============================================================
@app.route('/override', methods=['POST'])
def log_override():
    data      = request.get_json()
    report_id = data.get('report_id')
    user_ip   = request.remote_addr

    if not report_id:
        return jsonify({'error': 'Missing report_id'}), 400

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO overrides (report_id, user_ip)
                VALUES (%s, %s)
            """, (report_id, user_ip))
        conn.commit()
        return jsonify({'message': 'Override logged.'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Run ────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True, port=5000)
