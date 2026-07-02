from flask import Blueprint, request, jsonify
from models import ScannerIndicator, Scam
from database import db
import re

scanner_bp = Blueprint('scanner', __name__)

# ── POST /api/scanner/check ───────────────────────────────────
# Used by: the built-in scanner tool on the site
# Body: { value: "https://fake-site.com" or "+65 9123 4567" }
@scanner_bp.route('/check', methods=['POST'])
def check_indicator():
    data  = request.get_json()
    value = (data.get('value') or '').strip()
    if not value:
        return jsonify({'error': 'No value provided'}), 400

    # Detect type
    if re.match(r'^\+?\d[\d\s\-]{7,}$', value):
        ind_type = 'Phone'
        query_val = re.sub(r'[\s\-]', '', value)
    elif re.match(r'^https?://', value) or '/' in value:
        ind_type = 'URL'
        query_val = value
    else:
        ind_type = 'Domain'
        query_val = value.lower()

    # Exact match first
    match = ScannerIndicator.query.filter(
        db.func.lower(ScannerIndicator.value) == query_val.lower()
    ).first()

    # Domain partial match (strip https://, path)
    if not match and ind_type in ('URL', 'Domain'):
        domain = re.sub(r'^https?://', '', query_val).split('/')[0]
        match = ScannerIndicator.query.filter(
            ScannerIndicator.value.ilike(f'%{domain}%')
        ).first()

    if match:
        # Increment hit counter
        match.hit_count += 1
        db.session.commit()

        scam = Scam.query.get(match.scam_id) if match.scam_id else None
        return jsonify({
            'result':    'SCAM',
            'matched':   match.value,
            'type':      match.type,
            'report_id': scam.report_id if scam else None,
            'title':     scam.title     if scam else 'Confirmed scam indicator',
            'severity':  scam.severity  if scam else 'high',
        }), 200

    return jsonify({
        'result':  'CLEAN',
        'message': 'No match found in our database. Stay cautious.'
    }), 200
