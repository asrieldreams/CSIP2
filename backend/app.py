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
    indicator = indicator.strip()
    # Normalize phone numbers
    cleaned = re.sub(r'[\s\-]', '', indicator)
    if re.match(r'^\+?\d{8,15}$', cleaned):
        return cleaned
    # Normalize URLs — add http:// if missing
    if not indicator.startswith('http') and '.' in indicator and ' ' not in indicator and '@' not in indicator:
        indicator = 'http://' + indicator
    # Strip trailing slash from root URLs (http://domain.com/ → http://domain.com)
    if indicator.endswith('/') and indicator.count('/') == 3:
        indicator = indicator.rstrip('/')
    return indicator


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
            current_list = existing.get('list_type', '')
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        'UPDATE reports SET report_count = COALESCE(report_count, 1) + 1 WHERE id = %s',
                        (existing['id'],)
                    )
                conn.commit()
                with conn.cursor() as cursor:
                    cursor.execute(
                        'SELECT report_count, status, list_type FROM reports WHERE id = %s',
                        (existing['id'],)
                    )
                    row = cursor.fetchone()
                    if row:
                        count        = row['report_count'] or 1
                        current_list = row['list_type'] or ''
            except Exception as e:
                print(f'[report_count] {e}')

            # ── Crowdsourced auto-promotion ─────────────────────
            # 3+ reports  → auto-flag SUSPECTED (whitelist)
            # 5+ reports  → auto-BLACKLIST (confirmed, no admin needed)
            promotion_tier = ''
            promotion_msg  = ''
            try:
                already_black = (existing['status'] == 'approved' and current_list == 'blacklist')
                if count >= 5 and not already_black:
                    with conn.cursor() as cursor:
                        sql = "UPDATE reports SET status='approved', list_type='blacklist', severity=COALESCE(NULLIF(severity,''),'high') WHERE id=%s"
                        cursor.execute(sql, (existing['id'],))
                    conn.commit()
                    promotion_tier = 'blacklist'
                    promotion_msg  = 'Thank you. Your report has been recorded and reviewed.'
                    print(f'[crowdsource] AUTO-BLACKLIST id={existing["id"]} count={count}')
                elif count >= 3 and existing['status'] == 'pending':
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "UPDATE reports SET status='approved', list_type='whitelist' WHERE id=%s",
                            (existing['id'],)
                        )
                    conn.commit()
                    promotion_tier = 'whitelist'
                    promotion_msg  = 'Thank you. Your report has been recorded and is under review.'
                    print(f'[crowdsource] AUTO-FLAG id={existing["id"]} count={count}')
            except Exception as e:
                print(f'[crowdsource] {e}')


            # ── Record this vote ──────────────────────────────────
            new_scam_type = data.get('scam_type', '')
            new_severity  = data.get('severity', '')
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO report_votes
                            (report_id, scam_type, severity, source, ip_address)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        existing['id'],
                        new_scam_type or None,
                        new_severity  or None,
                        data.get('source', 'unknown'),
                        request.remote_addr
                    ))
                conn.commit()
            except Exception as e:
                print(f'[votes] Insert error: {e}')

            # ── Consensus check ────────────────────────────────────
            # Tally ALL votes (original report + all additional votes)
            consensus_type     = None
            consensus_severity = None
            try:
                with conn.cursor() as cursor:
                    # Count scam_type votes from additional reporters
                    cursor.execute("""
                        SELECT scam_type, COUNT(*) as votes
                        FROM report_votes
                        WHERE report_id = %s AND scam_type IS NOT NULL
                        GROUP BY scam_type ORDER BY votes DESC LIMIT 1
                    """, (existing['id'],))
                    top_type = cursor.fetchone()

                    # Count severity votes
                    cursor.execute("""
                        SELECT severity, COUNT(*) as votes
                        FROM report_votes
                        WHERE report_id = %s AND severity IS NOT NULL
                        GROUP BY severity ORDER BY votes DESC LIMIT 1
                    """, (existing['id'],))
                    top_sev = cursor.fetchone()

                # Consensus threshold: majority of votes (>50%)
                total_votes = count  # report_count includes original
                if top_type and top_type['votes'] > total_votes / 2:
                    consensus_type = top_type['scam_type']
                if top_sev and top_sev['votes'] > total_votes / 2:
                    consensus_severity = top_sev['severity']

                # Apply consensus if reached
                updates = []
                vals    = []
                if consensus_type:
                    updates.append('scam_type = %s')
                    vals.append(consensus_type)
                    print(f'[consensus] scam_type → {consensus_type} ({top_type["votes"]}/{total_votes} votes)')
                if consensus_severity:
                    updates.append('severity = %s')
                    vals.append(consensus_severity)
                    print(f'[consensus] severity → {consensus_severity} ({top_sev["votes"]}/{total_votes} votes)')
                if updates:
                    vals.append(existing['id'])
                    with conn.cursor() as cursor:
                        cursor.execute(
                            f'UPDATE reports SET {", ".join(updates)} WHERE id = %s',
                            vals
                        )
                    conn.commit()
            except Exception as e:
                print(f'[consensus] Error: {e}')

            return jsonify({
                'message':        promotion_msg or f'Thank you. Your report has been recorded.',
                'duplicate':      True,
                'status':         existing['status'],
                'report_id':      existing['id'],
                'report_count':   count,
                'promoted':       bool(promotion_tier),
                'promotion_tier': promotion_tier,
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

        # Record first vote for consensus tracking
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    'INSERT INTO report_votes (report_id, scam_type, severity, source, ip_address) VALUES (%s, %s, %s, %s, %s)',
                    (new_id, data.get('scam_type',''), data.get('severity','medium'), data.get('source','unknown'), request.remote_addr)
                )
            conn.commit()
        except Exception as e:
            print(f'[votes] first vote: {e}')

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
            # Build all variants to check:
            # - http vs https
            # - www. vs no www.
            # - trailing slash vs no trailing slash
            def url_variants(u):
                u = u.rstrip('/')
                # Extract protocol and rest
                if u.startswith('https://'):
                    proto, rest = 'https://', u[8:]
                elif u.startswith('http://'):
                    proto, rest = 'http://', u[7:]
                else:
                    return [u]

                # Strip or add www.
                if rest.startswith('www.'):
                    rest_no_www = rest[4:]
                    rest_www    = rest
                else:
                    rest_no_www = rest
                    rest_www    = 'www.' + rest

                variants = set()
                for p in ('http://', 'https://'):
                    for r in (rest_no_www, rest_www):
                        base = p + r
                        variants.add(base)
                        variants.add(base + '/')
                return list(variants)

            variants = url_variants(normalized)
            placeholders = ','.join(['%s'] * len(variants))
            cursor.execute(f"""
                SELECT id, list_type, scam_type, description,
                       COALESCE(report_count, 1) as report_count
                FROM reports
                WHERE indicator IN ({placeholders})
                  AND status = 'approved'
                ORDER BY submitted_at DESC LIMIT 1
            """, variants)
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
                            'report_count': row.get('report_count', 1),
                            'message': 'WARNING: Confirmed scam. Do not proceed.'}), 200
        elif row['list_type'] == 'whitelist':
            return jsonify({'status': 'whitelist', 'report_id': row['id'],
                            'indicator': indicator, 'scam_type': row['scam_type'],
                            'description': row['description'],
                            'report_count': row.get('report_count', 1),
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