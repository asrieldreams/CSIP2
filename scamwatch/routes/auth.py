from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash
from datetime import datetime
from extensions import db
from models import Admin, AuditLog
from utils import make_token, require_admin, log_audit

auth_bp = Blueprint('auth', __name__)


# ── POST /api/auth/login ──────────────────────────────────────────────────────
# Called by the admin login modal on introduction.html
# Body:    { "email": "admin@scamwatch.sg", "password": "admin123" }
# Returns: { "token": "...", "admin": { id, name, email, role, ... } }
#
# Connect in introduction.html attemptLogin():
#   const res  = await fetch('http://localhost:5000/api/auth/login', {
#       method: 'POST',
#       headers: { 'Content-Type': 'application/json' },
#       body: JSON.stringify({ email, password })
#   });
#   const data = await res.json();
#   if (res.ok) {
#       localStorage.setItem('sw_token', data.token);
#       window.location.href = 'admindashboard.html';
#   }
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    email = (data.get('email') or '').strip().lower()
    pwd   = data.get('password') or ''

    if not email or not pwd:
        return jsonify({'error': 'Email and password are required'}), 400

    admin = Admin.query.filter_by(email=email).first()
    if not admin or not check_password_hash(admin.password, pwd):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Update last login timestamp
    admin.last_login = datetime.utcnow()
    log_audit(admin.id, 'Login', 'admin', admin.id, admin.email, 'Admin logged in')
    db.session.commit()

    return jsonify({
        'token': make_token(admin),
        'admin': admin.to_dict(),
    }), 200


# ── GET /api/auth/me ──────────────────────────────────────────────────────────
# Verify a stored token and return current admin info.
# Header: Authorization: Bearer <token>
# Used by admindashboard.html on page load to verify the session is still valid.
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route('/me', methods=['GET'])
@require_admin
def me():
    return jsonify(request.current_admin.to_dict()), 200
