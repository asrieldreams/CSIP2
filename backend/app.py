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


def extract_domain(url: str) -> str:
    """Extract just the bare domain from a URL for fuzzy matching."""
    import re as _re
    url = url.strip().lower()
    url = _re.sub(r'^https?://', '', url)   # strip protocol
    url = _re.sub(r'^www\.', '', url)       # strip www.
    url = url.split('/')[0]                  # strip path
    url = url.split(':')[0]                  # strip port
    url = url.split('?')[0]                  # strip query
    return url


def is_domain_match(checked_url: str, stored_url: str) -> bool:
    """
    True if the stored URL's domain is a PARENT of the checked URL's domain.
    Examples:
      stored=tp.edu.sg, checked=app.tp.edu.sg  → True  (subdomain match)
      stored=tp.edu.sg, checked=tp.edu.sg/page → True  (path match)
      stored=app.tp.edu.sg, checked=tp.edu.sg  → False (don't escalate up)
    """
    c_domain = extract_domain(checked_url)
    s_domain = extract_domain(stored_url)

    if not c_domain or not s_domain:
        return False

    # Exact domain match (different paths)
    if c_domain == s_domain:
        return True

    # Checked URL is a subdomain of stored domain
    # app.tp.edu.sg ends with .tp.edu.sg
    if c_domain.endswith('.' + s_domain):
        return True

    return False


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
            # ── Step 1: Increment report count (fresh connection) ──────
            count = 1
            try:
                c1 = get_connection()
                with c1.cursor() as cur:
                    cur.execute(
                        "UPDATE reports SET report_count = COALESCE(report_count,1)+1 WHERE id=%s",
                        (existing['id'],)
                    )
                c1.commit()
                with c1.cursor() as cur:
                    cur.execute(
                        "SELECT report_count, status, list_type FROM reports WHERE id=%s",
                        (existing['id'],)
                    )
                    row = cur.fetchone()
                    if row:
                        count        = row['report_count'] or 1
                        current_list = row['list_type'] or ''
                        current_status = row['status']
            except Exception as e:
                print(f'[report_count] {e}')
                current_list   = existing.get('list_type', '')
                current_status = existing['status']

            # ── Step 2: Crowdsource promotion (fresh connection) ─────────
            # Ceiling = SUSPECTED — community cannot auto-blacklist
            try:
                c2 = get_connection()
                if count >= 3 and current_status == 'pending':
                    with c2.cursor() as cur:
                        cur.execute(
                            "UPDATE reports SET status='approved', list_type='whitelist' WHERE id=%s",
                            (existing['id'],)
                        )
                    c2.commit()
                    print(f'[crowdsource] AUTO-SUSPECT id={existing["id"]} count={count}')
                elif count >= 5 and current_status == 'approved' and current_list == 'whitelist':
                    print(f'[crowdsource] Ceiling id={existing["id"]} count={count} — admin needed')
            except Exception as e:
                print(f'[crowdsource] {e}')

            # ── Step 3: Record vote (fresh connection) ────────────────────
            try:
                c3 = get_connection()
                with c3.cursor() as cur:
                    cur.execute(
                        "INSERT INTO report_votes (report_id, scam_type, severity, source, ip_address) VALUES (%s,%s,%s,%s,%s)",
                        (existing['id'], data.get('scam_type',''), data.get('severity',''), data.get('source','unknown'), request.remote_addr)
                    )
                c3.commit()
            except Exception as e:
                print(f'[votes] {e}')

            # ── Step 4: Consensus check (fresh connection) ────────────────
            try:
                c4 = get_connection()
                with c4.cursor() as cur:
                    cur.execute(
                        "SELECT scam_type, COUNT(*) as v FROM report_votes WHERE report_id=%s AND scam_type IS NOT NULL GROUP BY scam_type ORDER BY v DESC LIMIT 1",
                        (existing['id'],)
                    )
                    top_type = cur.fetchone()
                    cur.execute(
                        "SELECT severity, COUNT(*) as v FROM report_votes WHERE report_id=%s AND severity IS NOT NULL GROUP BY severity ORDER BY v DESC LIMIT 1",
                        (existing['id'],)
                    )
                    top_sev = cur.fetchone()

                updates, vals = [], []
                if top_type and top_type['v'] > count / 2:
                    updates.append('scam_type=%s'); vals.append(top_type['scam_type'])
                    print(f'[consensus] scam_type={top_type["scam_type"]} ({top_type["v"]}/{count})')
                if top_sev and top_sev['v'] > count / 2:
                    updates.append('severity=%s'); vals.append(top_sev['severity'])
                    print(f'[consensus] severity={top_sev["severity"]} ({top_sev["v"]}/{count})')
                if updates:
                    vals.append(existing['id'])
                    with c4.cursor() as cur:
                        cur.execute(f'UPDATE reports SET {", ".join(updates)} WHERE id=%s', vals)
                    c4.commit()
            except Exception as e:
                print(f'[consensus] {e}')

            # ── Always return 200 — report was recorded ───────────────────
            return jsonify({
                'message':      'Thank you. Your report has been recorded.',
                'duplicate':    True,
                'status':       current_status,
                'report_id':    existing['id'],
                'report_count': count,
                'promoted':     False,
                'promotion_tier': '',
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
                SELECT id, list_type, scam_type, description, severity,
                       COALESCE(report_count, 1) as report_count
                FROM reports
                WHERE indicator IN ({placeholders})
                  AND status = 'approved'
                ORDER BY submitted_at DESC LIMIT 1
            """, variants)
            row = cursor.fetchone()

        # ── Domain fuzzy matching (SQL-based) ─────────────────────────
        # Generate parent domain candidates from checked URL and query DB
        # e.g. dab.ding.com → check if ding.com is blacklisted
        if not row:
            try:
                checked_domain = extract_domain(normalized)
                parts = checked_domain.split('.')
                # Build parent domain list (strip labels from left)
                # dab.ding.com → [ding.com]  (skip single-part like 'com')
                parent_domains = []
                for i in range(1, len(parts) - 1):  # skip last part (tld alone)
                    parent_domains.append('.'.join(parts[i:]))

                # ── Also check domain-only (same domain, different path) ──
                # e.g. DB has nyp.edu.sg, checking nyp.edu.sg/main → MATCH
                domain_only_variants = []
                for proto in ('http://', 'https://'):
                    for prefix in ('', 'www.'):
                        domain_only_variants.append(proto + prefix + checked_domain)
                        domain_only_variants.append(proto + prefix + checked_domain + '/')

                # Combine: domain-only first, then parent domains
                all_variants = domain_only_variants
                if parent_domains:
                    # Generate http/https × www/no-www variants for each parent
                    for pd in parent_domains:
                        for proto in ('http://', 'https://'):
                            for prefix in ('', 'www.'):
                                all_variants.append(proto + prefix + pd)
                                all_variants.append(proto + prefix + pd + '/')

                if all_variants:
                    parent_variants = all_variants

                    placeholders = ','.join(['%s'] * len(parent_variants))
                    with conn.cursor() as cursor:
                        cursor.execute(f"""
                            SELECT id, list_type, scam_type, description,
                                   severity, indicator,
                                   COALESCE(report_count, 1) as report_count
                            FROM reports
                            WHERE indicator IN ({placeholders})
                              AND status = 'approved'
                            LIMIT 1
                        """, parent_variants)
                        fuzzy_row = cursor.fetchone()

                    if fuzzy_row:
                        row = dict(fuzzy_row)
                        row['fuzzy_match']    = True
                        row['matched_domain'] = extract_domain(fuzzy_row['indicator'])
                        print(f'[fuzzy] HIT: {checked_domain} → {row["matched_domain"]}')
                    else:
                        print(f'[fuzzy] MISS: {checked_domain} parents={parent_domains}')
            except Exception as e:
                print(f'[fuzzy] Error: {e}')


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
            desc = row.get('description') or ''
            if row.get('fuzzy_match'):
                desc = f"Domain match: {row.get('matched_domain')} is blacklisted. {desc}".strip()
            return jsonify({'status': 'blacklist', 'report_id': row['id'],
                            'indicator': indicator,
                            'matched_indicator': row.get('indicator', indicator),
                            'scam_type': row.get('scam_type', 'Unknown'),
                            'description': desc,
                            'severity': row.get('severity') or 'high',
                            'report_count': row.get('report_count', 1),
                            'fuzzy_match': row.get('fuzzy_match', False),
                            'message': 'WARNING: Confirmed scam. Do not proceed.'}), 200
        elif row['list_type'] == 'whitelist':
            desc = row.get('description') or ''
            if row.get('fuzzy_match'):
                desc = f"Domain match: {row.get('matched_domain')} is suspected. {desc}".strip()
            return jsonify({'status': 'whitelist', 'report_id': row['id'],
                            'indicator': indicator,
                            'matched_indicator': row.get('indicator', indicator),
                            'scam_type': row.get('scam_type', 'Unknown'),
                            'description': desc,
                            'severity': row.get('severity') or 'medium',
                            'report_count': row.get('report_count', 1),
                            'fuzzy_match': row.get('fuzzy_match', False),
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