from functools import wraps
from flask import request, jsonify, current_app
from models import Admin
import jwt

def require_admin(f):
    """Decorator — protect any route that needs a logged-in admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            payload = jwt.decode(token, current_app.config['JWT_SECRET'],
                                 algorithms=['HS256'])
            request.admin_id   = payload['admin_id']
            request.admin_role = payload['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def require_super_admin(f):
    """Only super_admin role can access."""
    @wraps(f)
    @require_admin
    def decorated(*args, **kwargs):
        if request.admin_role != 'super_admin':
            return jsonify({'error': 'Insufficient permissions'}), 403
        return f(*args, **kwargs)
    return decorated
