from flask import Blueprint, request, jsonify
from extensions import db
from models import ScannerIndicator

scanner_bp = Blueprint('scanner', __name__)


# ── POST /api/scanner/check ───────────────────────────────────────────────────
# Check a URL, domain, or phone number against the confirmed scam indicators.
# This is what powers the "Built-in Scanner" feature shown on introduction.html.
#
# Body:    { "value": "ocbc-verify-login.xyz" }
# Returns: { is_scam, match?, scam?, message }
#
# Connect from any scanner input on your site:
#   const res  = await fetch('http://localhost:5000/api/scanner/check', {
#       method: 'POST',
#       headers: { 'Content-Type': 'application/json' },
#       body: JSON.stringify({ value: inputValue })
#   });
#   const data = await res.json();
#   if (data.is_scam) {
#       // show red warning with data.match and data.scam
#   } else {
#       // show green clear result
#   }
# ─────────────────────────────────────────────────────────────────────────────
@scanner_bp.route('/check', methods=['POST'])
def check():
    data  = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    value = (data.get('value') or '').strip().lower()
    if not value:
        return jsonify({'error': 'Value is required'}), 400

    # 1. Try exact match first
    match = ScannerIndicator.query.filter(
        db.func.lower(ScannerIndicator.value) == value
    ).first()

    # 2. Try substring match — e.g. user pastes full URL, we have just the domain
    if not match:
        all_indicators = ScannerIndicator.query.all()
        for ind in all_indicators:
            ind_val = ind.value.lower()
            if ind_val in value or value in ind_val:
                match = ind
                break

    if match:
        # Increment hit counter
        match.hit_count += 1
        db.session.commit()

        scam_data = None
        if match.scam and match.scam.status == 'verified':
            scam_data = match.scam.to_dict()

        return jsonify({
            'is_scam': True,
            'match':   match.to_dict(),
            'scam':    scam_data,
            'message': f'⚠️ This {match.type} is flagged as a confirmed scam indicator.',
        }), 200

    return jsonify({
        'is_scam': False,
        'message': '✓ No match found in our scam database. Always stay cautious.',
    }), 200
