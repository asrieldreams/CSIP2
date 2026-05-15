# ============================================================
#  CSIP2 — Admin Panel Routes
#  admin.py
#  Owner: Zavier (Security + Admin Panel)
# ============================================================

from flask import Blueprint, request, jsonify, session
from flask_mysqldb import MySQL
import bcrypt
from datetime import datetime
from security import admin_required, sanitise_text

admin_bp = Blueprint('admin', __name__)
mysql    = None   # injected from app.py

def init_mysql(mysql_instance):
    """Called from app.py to pass in the MySQL instance."""
    global mysql
    mysql = mysql_instance


# ============================================================
#  POST /admin/login
#  Admin logs in with username + password
#  Sets a session cookie on success
# ============================================================
@admin_bp.route('/admin/login', methods=['POST'])
def admin_login():
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT id, password_hash FROM admins WHERE username = %s", (username,)
    )
    row = cursor.fetchone()
    cursor.close()

    if not row:
        return jsonify({'error': 'Invalid username or password.'}), 401

    admin_id, password_hash = row

    # Verify password against bcrypt hash
    if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
        session['admin_logged_in'] = True
        session['admin_id']        = admin_id
        session['admin_username']  = username
        return jsonify({'message': f'Welcome, {username}!'}), 200
    else:
        return jsonify({'error': 'Invalid username or password.'}), 401


# ============================================================
#  POST /admin/logout
#  Clears the admin session
# ============================================================
@admin_bp.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully.'}), 200


# ============================================================
#  GET /admin/reports
#  Get all pending reports for the admin to review
#  Protected by @admin_required
# ============================================================
@admin_bp.route('/admin/reports', methods=['GET'])
@admin_required
def admin_get_reports():
    status = request.args.get('status', 'pending')  # can also pass 'approved'/'rejected'

    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, indicator_type, indicator, scam_type,
               description, source, status, list_type, submitted_at
        FROM reports
        WHERE status = %s
        ORDER BY submitted_at ASC
    """, (status,))
    rows = cursor.fetchall()
    cursor.close()

    reports = []
    for row in rows:
        reports.append({
            'id':             row[0],
            'indicator_type': row[1],
            'indicator':      row[2],
            'scam_type':      row[3],
            'description':    row[4],
            'source':         row[5],
            'status':         row[6],
            'list_type':      row[7],
            'submitted_at':   str(row[8])
        })

    return jsonify({'reports': reports, 'total': len(reports)}), 200


# ============================================================
#  POST /admin/review
#  Approve or reject a report + classify as blacklist/whitelist
#  Protected by @admin_required
# ============================================================
@admin_bp.route('/admin/review', methods=['POST'])
@admin_required
def admin_review():
    data      = request.get_json()
    report_id = data.get('report_id')
    action    = data.get('action')       # 'approve' or 'reject'
    list_type = data.get('list_type')    # 'blacklist', 'whitelist', or None

    if not report_id or not action:
        return jsonify({'error': 'report_id and action are required.'}), 400

    if action not in ['approve', 'reject']:
        return jsonify({'error': 'Invalid action. Use approve or reject.'}), 400

    if action == 'approve' and list_type not in ['blacklist', 'whitelist']:
        return jsonify({'error': 'Approved reports must be classified as blacklist or whitelist.'}), 400

    new_status = 'approved' if action == 'approve' else 'rejected'
    final_list = list_type if action == 'approve' else None

    cursor = mysql.connection.cursor()
    cursor.execute("""
        UPDATE reports
        SET status = %s, list_type = %s, reviewed_at = %s
        WHERE id = %s
    """, (new_status, final_list, datetime.now(), report_id))
    mysql.connection.commit()
    cursor.close()

    return jsonify({
        'message': f'Report {report_id} has been {new_status}.'
                   + (f' Classified as {final_list}.' if final_list else '')
    }), 200


# ============================================================
#  GET /admin/stats
#  Returns summary statistics for the admin dashboard
# ============================================================
@admin_bp.route('/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM reports WHERE status = 'pending'")
    pending = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM reports WHERE status = 'approved' AND list_type = 'blacklist'")
    blacklisted = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM reports WHERE status = 'approved' AND list_type = 'whitelist'")
    whitelisted = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM reports WHERE status = 'rejected'")
    rejected = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM overrides")
    overrides = cursor.fetchone()[0]

    cursor.execute("""
        SELECT scam_type, COUNT(*) as total
        FROM reports WHERE status = 'approved'
        GROUP BY scam_type ORDER BY total DESC
    """)
    by_type = [{'scam_type': r[0], 'total': r[1]} for r in cursor.fetchall()]

    cursor.close()

    return jsonify({
        'pending':     pending,
        'blacklisted': blacklisted,
        'whitelisted': whitelisted,
        'rejected':    rejected,
        'overrides':   overrides,
        'by_type':     by_type
    }), 200