from flask import Blueprint, request, jsonify, current_app
from models import Admin, AuditLog
from database import db
from datetime import datetime, timedelta
import bcrypt, jwt

auth_bp = Blueprint('auth', __name__)

def _make_token(admin):
    payload = {
        'admin_id': admin.id,
        'role':     admin.role,
        'exp':      datetime.utcnow() + timedelta(
                        hours=current_app.config['JWT_EXPIRY_HOURS'])
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')

# ── POST /api/auth/login ──────────────────────────────────────
# Body: { "email": "...", "password": "..." }
# Used by: admin login modal on introduction.html
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400

    admin = Admin.query.filter_by(email=data['email']).first()
    if not admin:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not bcrypt.checkpw(data['password'].encode(), admin.password.encode()):
        return jsonify({'error': 'Invalid credentials'}), 401

    admin.last_login = datetime.utcnow()
    db.session.commit()

    log = AuditLog(admin_id=admin.id, action='Login',
                   target_type='admin', target_ref=admin.email,
                   detail='Admin logged in')
    db.session.add(log)
    db.session.commit()

    return jsonify({
        'token': _make_token(admin),
        'admin': admin.to_dict()
    }), 200

# ── GET /api/auth/me ──────────────────────────────────────────
# Header: Authorization: Bearer <token>
@auth_bp.route('/me', methods=['GET'])
def me():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET'],
                             algorithms=['HS256'])
        admin = Admin.query.get(payload['admin_id'])
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404
        return jsonify(admin.to_dict()), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
