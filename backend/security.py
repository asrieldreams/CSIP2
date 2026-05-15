# ============================================================
#  CSIP2 — Backend Security Controls
#  security.py
#  Owner: Zavier (Security)
# ============================================================

import re
import time
from functools import wraps
from collections import defaultdict
from flask import request, jsonify, session

# ── Rate Limit Config ──────────────────────────────────────
RATE_LIMIT_MAX    = 5   # max reports per window
RATE_LIMIT_WINDOW = 60  # seconds

# In-memory store: { ip_address: [timestamp1, timestamp2, ...] }
ip_request_times = defaultdict(list)


# ============================================================
#  RATE LIMITER — decorator for Flask routes
#  Usage: add @rate_limit above any route in app.py
# ============================================================
def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip  = request.remote_addr
        now = time.time()

        # Remove timestamps outside the window
        ip_request_times[ip] = [
            t for t in ip_request_times[ip]
            if now - t < RATE_LIMIT_WINDOW
        ]

        if len(ip_request_times[ip]) >= RATE_LIMIT_MAX:
            return jsonify({
                'error': f'Too many requests. Max {RATE_LIMIT_MAX} per {RATE_LIMIT_WINDOW} seconds.'
            }), 429

        ip_request_times[ip].append(now)
        return f(*args, **kwargs)
    return decorated


# ============================================================
#  ADMIN AUTH — decorator to protect admin routes
#  Usage: add @admin_required above admin routes in app.py
# ============================================================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({'error': 'Unauthorised. Please log in.'}), 401
        return f(*args, **kwargs)
    return decorated


# ============================================================
#  INPUT VALIDATION FUNCTIONS
#  Called in app.py before saving any data to the database
# ============================================================

def validate_indicator(indicator: str, indicator_type: str) -> tuple[bool, str]:
    """
    Validates the scam indicator based on its type.
    Returns (is_valid, error_message).
    """
    if not indicator or not indicator.strip():
        return False, 'Indicator cannot be empty.'

    if len(indicator) > 500:
        return False, 'Indicator is too long (max 500 characters).'

    if indicator_type == 'url':
        pattern = re.compile(
            r'^(https?://)'
            r'([a-zA-Z0-9\-\.]+)'
            r'(\.[a-zA-Z]{2,})'
            r'(/.*)?$'
        )
        if not pattern.match(indicator.strip()):
            return False, 'Invalid URL format. Must start with http:// or https://'

    elif indicator_type == 'phone':
        cleaned = re.sub(r'[\s\-\(\)]', '', indicator)
        pattern = re.compile(r'^\+?\d{8,15}$')
        if not pattern.match(cleaned):
            return False, 'Invalid phone number format.'

    elif indicator_type == 'email':
        pattern = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
        if not pattern.match(indicator.strip()):
            return False, 'Invalid email address format.'

    return True, ''


def sanitise_text(text: str) -> str:
    """
    Sanitises free text input to prevent XSS and injection attacks.
    - Strips HTML tags
    - Removes dangerous characters
    - Limits to 500 characters
    """
    if not text:
        return ''
    # Remove HTML/script tags
    text = re.sub(r'<[^>]+>', '', text)
    # Remove characters that could be used for SQL injection or XSS
    text = re.sub(r'[<>"\';\\]', '', text)
    return text.strip()[:500]


def validate_report_payload(data: dict) -> tuple[bool, str]:
    """
    Full validation of the /report POST payload.
    Returns (is_valid, error_message).
    """
    required = ['indicator_type', 'indicator', 'scam_type', 'source']
    for field in required:
        if field not in data or not str(data[field]).strip():
            return False, f'Missing or empty field: {field}'

    valid_types   = ['url', 'phone', 'email', 'message']
    valid_scams   = ['Phishing', 'E-Commerce Scam', 'Impersonation',
                     'Love Scam', 'Investment Scam', 'Others']
    valid_sources = ['website', 'telegram', 'extension']

    if data['indicator_type'] not in valid_types:
        return False, f'Invalid indicator_type. Must be one of: {valid_types}'
    if data['scam_type'] not in valid_scams:
        return False, f'Invalid scam_type. Must be one of: {valid_scams}'
    if data['source'] not in valid_sources:
        return False, f'Invalid source. Must be one of: {valid_sources}'

    # Validate the indicator format
    is_valid, error = validate_indicator(data['indicator'], data['indicator_type'])
    if not is_valid:
        return False, error

    return True, ''