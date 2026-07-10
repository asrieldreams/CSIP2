# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Backend API — app.py
#  Owner: Kaden (Backend Lead)
# ============================================================

import re
from flask_cors import CORS
from flask import Flask, request, jsonify, session
from db import get_connection
from datetime import datetime

from admin import admin_bp
from compat import compat_bp
from security import rate_limit, validate_report_payload, sanitise_text

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})
app.secret_key = 'csip2-secret-change-this-before-deployment'

app.register_blueprint(admin_bp)
app.register_blueprint(compat_bp)


def normalize_indicator(indicator: str) -> str:
    cleaned = re.sub(r'[\s\-]', '', indicator.strip())
    if re.match(r'^\+?\d{8,15}$', cleaned):
        return cleaned
    return indicator.strip()


@app.route('/')
def home():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
        return jsonify({
            'status': 'connected', 'database': 'online',
            'tables_found': len(tables), 'tables': tables
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/report', methods=['POST'])
@rate_limit
def submit_report():
    data = request.get_json()
    is_valid, error = validate_report_payload(data)
    if not is_valid:
        return jsonify({'error': error}), 400

    indicator   = normalize_indicator(sanitise_text(data['indicator']))
    description = sanitise_text(data.get('description', ''))

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, status FROM reports WHERE indicator = %s LIMIT 1",
                (indicator,)
            )
            existing = cursor.fetchone()

        if existing and existing['status'] in ('approved', 'pending'):
            # Increment report count
            count = 1
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE reports SET report_count = COALESCE(report_count, 1) + 1 WHERE id = %s",
                        (existing['id'],)
                    )
                conn.commit()
                # Fetch updated count
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT report_count FROM reports WHERE id = %s",
                        (existing['id'],)
                    )
                    row = cursor.fetchone()
                    count = row['report_count'] if row and row.get('report_count') else 1
            except Exception as e:
                print(f"[report_count] {e}")

            return jsonify({
                'message':    f'Thanks! Now reported by {count} people.',
                'duplicate':  True,
                'status':     existing['status'],
                'report_id':  existing['id'],
                'report_count': count,
            }), 200

        with conn.cursor() as cursor:
            try:
                cursor.execute("""
                    INSERT INTO reports
                        (indicator_type, indicator, scam_type, description,
                         source, severity, platform, report_count)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
                """, (
                    data['indicator_type'], indicator,
                    data['scam_type'], description,
                    data.get('source', 'website'),
                    data.get('severity', 'medium'),
                    data.get('platform', 'website'),
                ))
            except Exception:
                # Fallback without new columns
                cursor.execute("""
                    INSERT INTO reports
                        (indicator_type, indicator, scam_type, description, source)
                    VALUES (%s, %s, %s, %s, %s)
                """, (data['indicator_type'], indicator,
                      data['scam_type'], description,
                      data.get('source', 'website')))
        conn.commit()
        return jsonify({'message': 'Report submitted. Pending admin review.'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        query += " AND (indicator LIKE %s OR description LIKE %s OR scam_type LIKE %s)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])

    query += " ORDER BY submitted_at DESC"

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()

        reports = [{'id': r['id'], 'indicator_type': r['indicator_type'],
                    'indicator': r['indicator'], 'scam_type': r['scam_type'],
                    'description': r['description'], 'source': r['source'],
                    'list_type': r['list_type'],
                    'submitted_at': str(r['submitted_at'])} for r in rows]
        return jsonify({'reports': reports, 'total': len(reports)}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/check', methods=['GET'])
def check_indicator():
    indicator = request.args.get('url') or request.args.get('indicator')
    if not indicator:
        return jsonify({'error': 'Missing indicator parameter'}), 400

    normalized = normalize_indicator(indicator)

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, list_type, scam_type, description
                FROM reports
                WHERE indicator = %s AND status = 'approved'
                ORDER BY submitted_at DESC LIMIT 1
            """, (normalized,))
            row = cursor.fetchone()

        if not row:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM reports WHERE indicator = %s AND status = 'pending' LIMIT 1",
                    (normalized,)
                )
                pending = cursor.fetchone()
            if pending:
                return jsonify({'status': 'pending', 'indicator': indicator,
                                'message': 'This indicator is pending admin review.'}), 200
            return jsonify({'status': 'clean', 'indicator': indicator,
                            'message': 'No reports found.'}), 200

        if row['list_type'] == 'blacklist':
            return jsonify({'status': 'blacklist', 'report_id': row['id'],
                            'indicator': indicator, 'scam_type': row['scam_type'],
                            'description': row['description'],
                            'message': 'WARNING: Confirmed scam. Do not proceed.'}), 200
        elif row['list_type'] == 'whitelist':
            return jsonify({'status': 'whitelist', 'report_id': row['id'],
                            'indicator': indicator, 'scam_type': row['scam_type'],
                            'description': row['description'],
                            'message': 'CAUTION: Flagged. Proceed with care.'}), 200
        else:
            return jsonify({'status': 'flagged', 'indicator': indicator,
                            'message': 'Reported but under review.'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
            cursor.execute(
                "INSERT INTO overrides (report_id, user_ip) VALUES (%s, %s)",
                (report_id, user_ip)
            )
        conn.commit()
        return jsonify({'message': 'Override logged.'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    import os
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))