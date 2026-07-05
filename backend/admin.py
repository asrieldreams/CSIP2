from flask import Blueprint, request, jsonify, session
from db import get_connection
import bcrypt
from datetime import datetime
from security import admin_required, sanitise_text

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/login', methods=['POST'])
def admin_login():
    data     = request.get_json()
    email    = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, name, password FROM admins WHERE email = %s", (email,)
            )
            row = cursor.fetchone()

        if not row:
            return jsonify({'error': 'Invalid email or password.'}), 401

        if bcrypt.checkpw(password.encode('utf-8'), row['password'].encode('utf-8')):
            session['admin_logged_in'] = True
            session['admin_id']        = row['id']
            session['admin_username']  = row['name']
            return jsonify({'message': f"Welcome, {row['name']}!"}), 200
        else:
            return jsonify({'error': 'Invalid email or password.'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully.'}), 200


@admin_bp.route('/admin/reports', methods=['GET'])
@admin_required
def admin_get_reports():
    status = request.args.get('status', 'pending')
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, indicator_type, indicator, scam_type,
                       description, source, status, list_type, submitted_at
                FROM reports WHERE status = %s
                ORDER BY submitted_at ASC
            """, (status,))
            rows = cursor.fetchall()

        reports = [{
            'id':             r['id'],
            'indicator_type': r['indicator_type'],
            'indicator':      r['indicator'],
            'scam_type':      r['scam_type'],
            'description':    r['description'],
            'source':         r['source'],
            'status':         r['status'],
            'list_type':      r['list_type'],
            'submitted_at':   str(r['submitted_at'])
        } for r in rows]

        return jsonify({'reports': reports, 'total': len(reports)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/admin/review', methods=['POST'])
@admin_required
def admin_review():
    data      = request.get_json()
    report_id = data.get('report_id')
    action    = data.get('action')
    list_type = data.get('list_type')

    if not report_id or not action:
        return jsonify({'error': 'report_id and action are required.'}), 400
    if action not in ['approve', 'reject']:
        return jsonify({'error': 'Invalid action. Use approve or reject.'}), 400
    if action == 'approve' and list_type not in ['blacklist', 'whitelist']:
        return jsonify({'error': 'Approved reports must be classified as blacklist or whitelist.'}), 400

    new_status = 'approved' if action == 'approve' else 'rejected'
    final_list = list_type if action == 'approve' else None

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE reports SET status = %s, list_type = %s
                WHERE id = %s
            """, (new_status, final_list, report_id))
        conn.commit()
        return jsonify({'message': f'Report {report_id} has been {new_status}.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'pending'")
            pending = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved' AND list_type = 'blacklist'")
            blacklisted = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'approved' AND list_type = 'whitelist'")
            whitelisted = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'rejected'")
            rejected = cursor.fetchone()['c']
            try:
                cursor.execute("SELECT COUNT(*) as c FROM overrides")
                overrides = cursor.fetchone()['c']
            except Exception:
                overrides = 0
            cursor.execute("""
                SELECT scam_type, COUNT(*) as total FROM reports
                WHERE status = 'approved'
                GROUP BY scam_type ORDER BY total DESC
            """)
            by_type = [{'scam_type': r['scam_type'], 'total': r['total']} for r in cursor.fetchall()]

        return jsonify({
            'pending': pending, 'blacklisted': blacklisted,
            'whitelisted': whitelisted, 'rejected': rejected,
            'overrides': overrides, 'by_type': by_type
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500