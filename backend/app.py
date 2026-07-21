# ============================================================
#  CSIP2 — Crowdsourced Scam Intelligence Platform 2
#  Backend API — app.py
#  Owner: Kaden (Backend Lead)
# ============================================================

import re
import os
from dotenv import load_dotenv
load_dotenv()
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

# ── /check rate limiting ───────────────────────────────────────
import time as _time
_check_counts  = {}   # ip -> {'count': n, 'window_start': ts}
_CHECK_LIMIT   = 60   # checks per hour per IP
_CHECK_WINDOW  = 3600 # 1 hour window

def check_rate_limit(ip):
    if ip in ('127.0.0.1', '::1', 'localhost'):
        return True, _CHECK_LIMIT
    now   = _time.time()
    entry = _check_counts.get(ip)
    if not entry or (now - entry['window_start']) > _CHECK_WINDOW:
        _check_counts[ip] = {'count': 1, 'window_start': now}
        return True, _CHECK_LIMIT - 1
    entry['count'] += 1
    if entry['count'] > _CHECK_LIMIT:
        if entry['count'] in (61, 100, 200):
            print(f'[rate:check] {ip} hit {entry["count"]} checks')
        return False, 0
    return True, _CHECK_LIMIT - entry['count']

# ── Velocity spike tracking ─────────────────────────────────────
_spike_tracker        = {}  # indicator → [timestamps]
_SPIKE_THRESHOLD      = 3   # reports within window triggers alert
_SPIKE_WINDOW         = 3600  # 1 hour
_pending_notifications = []  # in-memory alert store — bot + dashboard poll this


# ── Typosquatting detection ──────────────────────────────────────
TRUSTED_DOMAINS = [
    'singpass.gov.sg','myinfo.gov.sg','gov.sg','iras.gov.sg',
    'cpf.gov.sg','hdb.gov.sg','police.gov.sg','moh.gov.sg',
    'mom.gov.sg','mas.gov.sg','nea.gov.sg','lta.gov.sg',
    'dbs.com','dbs.com.sg','posb.com.sg','ocbc.com.sg',
    'uob.com.sg','maybank.com.sg','sc.com.sg',
    'grab.com','shopee.sg','lazada.sg','carousell.sg',
    'singtel.com','starhub.com','paypal.com',
    'apple.com','google.com','microsoft.com',
    'facebook.com','instagram.com','telegram.org',
]

CHAR_SUBS = str.maketrans({
    '0':'o','1':'l','3':'e','4':'a',
    '5':'s','6':'g','7':'t','8':'b',
    '@':'a','$':'s',
})

def levenshtein(a, b):
    if len(a) < len(b): a, b = b, a
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for ca in a:
        curr = [prev[0]+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(0 if ca==cb else 1)))
        prev = curr
    return prev[-1]

def check_typosquatting(domain):
    domain = domain.lower().strip().lstrip('www.')
    domain_norm = domain.translate(CHAR_SUBS)
    best_match = None
    best_dist  = 999
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain_norm == trusted:
            return None
        if trusted in domain:
            return {'trusted':trusted,'distance':0,
                    'note':f'Contains trusted name "{trusted}" — possible impersonation'}
        t_label = trusted.split('.')[0]
        d_label = domain_norm.split('.')[0]
        if abs(len(t_label)-len(d_label)) <= 3 and len(t_label) >= 4:
            dist = levenshtein(d_label, t_label)
            threshold = 2 if len(t_label) <= 6 else 3
            if dist <= threshold and dist < best_dist:
                best_dist = dist; best_match = trusted
    if best_match:
        return {'trusted':best_match,'distance':best_dist,
                'note':f'Looks similar to "{best_match}" — possible typosquat'}
    return None

def send_spike_alert(indicator, scam_type, count, minutes_span):
    """Store spike alert in memory — dashboard polls it, bot sends to Telegram."""
    import re as _r
    c    = _r.sub(r'[\s\-\+\(\)]', '', indicator)
    icon = '📞' if (c.isdigit() and 8<=len(c)<=15) else '📧' if '@' in indicator else '🔗'

    alert = {
        'type':         'spike',
        'indicator':    indicator,
        'icon':         icon,
        'scam_type':    scam_type,
        'count':        count,
        'minutes_span': minutes_span,
        'timestamp':    _time.time(),
        'sent_to_bot':  False,
    }
    _pending_notifications.append(alert)
    if len(_pending_notifications) > 50:
        _pending_notifications.pop(0)

    print(f'[spike] Alert queued: {indicator} — {count} reports in {minutes_span}min')




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



@app.route('/', methods=['GET'])
@app.route('/health', methods=['GET'])
def health_check():
    """Quick health check — used by website to verify backend is reachable."""
    return jsonify({'status': 'ok', 'service': 'CSIP2 ScamWatch API'}), 200

@app.route('/report', methods=['POST'])
@rate_limit
def submit_report():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data received'}), 400


    # Normalize indicator FIRST so validation uses the cleaned version
    if 'indicator' in data:
        data['indicator'] = normalize_indicator(sanitise_text(str(data['indicator'])))

    is_valid, error = validate_report_payload(data)
    if not is_valid:
        return jsonify({'error': error}), 400

    indicator   = data['indicator']  # already normalized above
    description = sanitise_text(data.get('description', ''))

    try:
        conn = get_connection()
        # Check for previously rejected record
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, admin_classified, admin_locked,
                       COALESCE(rejection_count, 0) as rejection_count
                FROM reports
                WHERE indicator = %s AND status = 'rejected'
                LIMIT 1
            """, (indicator,))
            rejected = cursor.fetchone()

        if rejected:
            rid             = rejected['id']
            admin_reviewed  = rejected.get('admin_classified', 0)
            locked          = rejected.get('admin_locked', 0)
            rejection_count = rejected.get('rejection_count', 0)

            # Case 1: Admin explicitly reviewed & rejected — permanently blocked
            if admin_reviewed or locked:
                print(f'[report] Blocked: admin-reviewed rejection for {indicator}')
                return jsonify({
                    'error': 'This indicator was reviewed and rejected by our admin team. '
                             'If you believe this is a scam, contact the admin directly.',
                    'blocked': True
                }), 409

            # Case 2: Repeatedly submitted after rejection (3+ times) — block it
            if rejection_count >= 2:
                # Lock it down to prevent abuse
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE reports SET admin_classified=1 WHERE id=%s",
                        (rid,)
                    )
                conn.commit()
                print(f'[report] Blocked: {indicator} rejected {rejection_count+1}x — now locked')
                return jsonify({
                    'error': 'This indicator has been repeatedly reviewed and rejected. '
                             'It has been permanently blocked from re-submission.',
                    'blocked': True
                }), 409

            # Case 3: Not admin-reviewed, first/second re-report — allow reactivation
            with conn.cursor() as cursor:
                # Core update — columns guaranteed to exist
                cursor.execute("""
                    UPDATE reports
                    SET status = 'pending',
                        list_type = NULL,
                        report_count = 1,
                        scam_type = %s,
                        severity = %s,
                        description = %s,
                        submitted_at = NOW(),
                        false_report_count = 0,
                        admin_classified = 0,
                        admin_locked = 0
                    WHERE id = %s
                """, (
                    data.get('scam_type', 'Others'),
                    data.get('severity', 'medium'),
                    description,
                    rid
                ))
            conn.commit()
            # Optional columns — silently skip if they don't exist yet
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE reports SET platform=%s, last_reported_at=NOW(), "
                        "telegram_user_id=%s WHERE id=%s",
                        (data.get('platform','website'), data.get('telegram_user_id'), rid)
                    )
                conn.commit()
            except Exception:
                pass
            print(f'[report] Reactivated rejected record {rid} (rejection #{rejection_count+1}) for {indicator}')
            return jsonify({
                'message': 'Report submitted. Pending admin review.',
                'report_id': f"SS-{str(rid).zfill(5)}",
                'duplicate': False,
                'reactivated': True,
            }), 201

        # Build URL variants to check (http/https, www/no-www, slash/no-slash)
        def _url_variants(u):
            u = u.rstrip('/')
            variants = set()
            for proto in ('http://', 'https://'):
                if u.startswith('http://') or u.startswith('https://'):
                    rest = u.split('://', 1)[1]
                else:
                    rest = u
                rest_nw = rest[4:] if rest.startswith('www.') else rest
                rest_ww = 'www.' + rest_nw
                for r in (rest_nw, rest_ww):
                    variants.add(proto + r)
                    variants.add(proto + r + '/')
            return list(variants)

        dup_variants = _url_variants(indicator) if indicator.startswith('http') else [indicator]
        dup_ph       = ','.join(['%s'] * len(dup_variants))

        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, status, list_type FROM reports WHERE indicator IN ({dup_ph}) AND status != 'rejected' LIMIT 1",
                dup_variants
            )
            existing = cursor.fetchone()

        # Only treat as duplicate if report is active (not rejected/removed)
        if existing and existing['status'] in ('approved', 'pending'):
            import threading

            # ── Step 1: Increment report count immediately ──────────────
            count          = 1
            current_list   = existing.get('list_type', '')
            current_status = existing['status']
            try:
                c1 = get_connection()
                with c1.cursor() as cur:
                    cur.execute(
                        "UPDATE reports SET report_count = COALESCE(report_count,1)+1, last_reported_at = NOW() WHERE id=%s",
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
                        count          = row['report_count'] or 1
                        current_list   = row['list_type'] or ''
                        current_status = row['status']
            except Exception as e:
                print(f'[report_count] {e}')

            # ── Step 2: Return response IMMEDIATELY ─────────────────────
            # Background thread handles promotion, vote, consensus
            # This prevents timeout errors on slow Aiven connections
            response_data = {
                'message':        'Thank you. Your report has been recorded.',
                'duplicate':      True,
                'status':         current_status,
                'report_id':      existing['id'],
                'report_count':   count,
                'promoted':       False,
                'promotion_tier': '',
            }

            def background_work(report_id, count, current_status, current_list,
                                 scam_type, severity, source, ip):
                """Run promotion + vote + consensus after response is sent."""
                # 1. Promotion check
                try:
                    c2 = get_connection()
                    if count >= 3 and current_status == 'pending':
                        with c2.cursor() as cur:
                            cur.execute(
                                "UPDATE reports SET status='approved',list_type='whitelist' WHERE id=%s",
                                (report_id,)
                            )
                        c2.commit()
                        print(f'[bg] AUTO-SUSPECT id={report_id} count={count}')
                except Exception as e:
                    print(f'[bg:promotion] {e}')

                # 2. Record vote
                try:
                    c3 = get_connection()
                    with c3.cursor() as cur:
                        cur.execute(
                            "INSERT INTO report_votes (report_id,scam_type,severity,source,ip_address) VALUES (%s,%s,%s,%s,%s)",
                            (report_id, scam_type, severity, source, ip)
                        )
                    c3.commit()
                except Exception as e:
                    print(f'[bg:vote] {e}')

                # 3. Consensus check
                try:
                    # Skip if admin manually classified
                    cg = get_connection()
                    with cg.cursor() as cur:
                        cur.execute('SELECT admin_classified FROM reports WHERE id=%s', (report_id,))
                        cg_row = cur.fetchone()
                    if cg_row and cg_row.get('admin_classified'):
                        print(f'[consensus] Skipped — admin_classified for id={report_id}')
                        return

                    c4 = get_connection()
                    with c4.cursor() as cur:
                        cur.execute(
                            "SELECT scam_type,COUNT(*) as v FROM report_votes WHERE report_id=%s AND scam_type IS NOT NULL GROUP BY scam_type ORDER BY v DESC LIMIT 1",
                            (report_id,)
                        )
                        top_t = cur.fetchone()
                        cur.execute(
                            "SELECT severity,COUNT(*) as v FROM report_votes WHERE report_id=%s AND severity IS NOT NULL GROUP BY severity ORDER BY v DESC LIMIT 1",
                            (report_id,)
                        )
                        top_s = cur.fetchone()
                    updates, vals = [], []
                    if top_t and top_t['v'] > count / 2:
                        updates.append('scam_type=%s'); vals.append(top_t['scam_type'])
                    if top_s and top_s['v'] > count / 2:
                        updates.append('severity=%s'); vals.append(top_s['severity'])
                    if updates:
                        vals.append(report_id)
                        with c4.cursor() as cur:
                            cur.execute(f'UPDATE reports SET {", ".join(updates)} WHERE id=%s', vals)
                        c4.commit()
                        print(f'[bg:consensus] {updates} for id={report_id}')
                except Exception as e:
                    print(f'[bg:consensus] {e}')

                # ── 4. Velocity spike check ────────────────────────
                try:
                    now = _time.time()
                    # Get indicator from DB for spike tracking
                    cs = get_connection()
                    with cs.cursor() as cur:
                        cur.execute('SELECT indicator, scam_type FROM reports WHERE id=%s', (report_id,))
                        rpt = cur.fetchone()
                    if rpt:
                        ind = rpt['indicator']
                        # Update spike tracker
                        times = _spike_tracker.get(ind, [])
                        times = [t for t in times if now - t < _SPIKE_WINDOW]  # trim old
                        times.append(now)
                        _spike_tracker[ind] = times
                        print(f'[spike] {ind[:40]} → {len(times)} report(s) in window (need {_SPIKE_THRESHOLD})')
                        # Fire alert if threshold hit (exactly at threshold, not every report after)
                        if len(times) == _SPIKE_THRESHOLD:
                            minutes_span = int((times[-1] - times[0]) / 60) + 1
                            import threading as _th
                            _th.Thread(
                                target=send_spike_alert,
                                args=(ind, rpt['scam_type'], len(times), minutes_span),
                                daemon=True
                            ).start()
                except Exception as e:
                    print(f'[bg:spike] {e}')

            # Fire background thread — non-blocking
            t = threading.Thread(
                target=background_work,
                args=(
                    existing['id'], count, current_status, current_list,
                    data.get('scam_type',''), data.get('severity','medium'),
                    data.get('source','unknown'), request.remote_addr
                ),
                daemon=True
            )
            t.start()

            return jsonify(response_data), 200


        with conn.cursor() as cursor:
            try:
                cursor.execute("""
                    INSERT INTO reports
                        (indicator_type, indicator, scam_type, description,
                         source, severity, platform, report_count, telegram_user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)
                """, (
                    data['indicator_type'], indicator,
                    data['scam_type'], description,
                    data.get('source', 'website'),
                    data.get('severity', 'medium'),
                    data.get('platform', 'website'),
                    data.get('telegram_user_id', None),
                ))
            except Exception:
                cursor.execute("""
                    INSERT INTO reports
                        (indicator_type, indicator, scam_type, description, source)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    data['indicator_type'], indicator,
                    data['scam_type'], description,
                     data.get('source', 'website'),
                 ))
        conn.commit()
        new_report_id = conn.insert_id()  # get inserted ID
        # Track new report in spike tracker too
        try:
            _ind   = data.get('indicator', '')
            _times = _spike_tracker.get(_ind, [])
            _now   = _time.time()
            _times = [t for t in _times if _now - t < _SPIKE_WINDOW]
            _times.append(_now)
            _spike_tracker[_ind] = _times
        except Exception as _se:
            print(f'[spike:new] {_se}')

        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    'INSERT INTO report_votes (report_id, scam_type, severity, source, ip_address) VALUES (%s, %s, %s, %s, %s)',
                    (new_report_id, data.get('scam_type',''), data.get('severity','medium'), data.get('source','unknown'), request.remote_addr)
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
    # ── Rate limit: 60 checks/hour per IP ─────────────────────
    _ip       = request.remote_addr
    _ok, _rem = check_rate_limit(_ip)
    if not _ok:
        _e    = _check_counts.get(_ip, {})
        _rst  = int(_CHECK_WINDOW - (_time.time() - _e.get('window_start', _time.time())))
        return jsonify({'status':'rate_limited','error':f'Too many checks ({_CHECK_LIMIT}/hr)','reset_in':max(0,_rst),'message':f'Try again in {max(0,_rst)//60} min.'}), 429

    indicator = request.args.get('url') or request.args.get('indicator')
    if not indicator:
        return jsonify({'error': 'Missing indicator parameter'}), 400


    indicator = indicator.strip()

    # Detect type — phone and email need different matching logic than URL
    import re as _re
    _cleaned = _re.sub(r'[\s\-\+\(\)]', '', indicator)
    if _cleaned.isdigit() and 8 <= len(_cleaned) <= 15:
        _ind_type = 'phone'
    elif '@' in indicator and '.' in indicator.split('@')[-1]:
        _ind_type = 'email'
    else:
        _ind_type = 'url'

    if _ind_type in ('phone', 'email'):
        try:
            _conn = get_connection()
            if _ind_type == 'phone':
                _bare = _re.sub(r'[\s\-\(\)]', '', indicator)
                _variants = [_bare]
                if _bare.startswith('+65'):   _variants.append(_bare[3:])
                elif len(_bare) == 8:          _variants.append('+65' + _bare)
            else:
                _variants = [indicator.lower()]
            _ph = ','.join(['%s'] * len(_variants))
            with _conn.cursor() as _cur:
                _cur.execute(f'SELECT id, list_type, scam_type, description, severity, COALESCE(report_count,1) as report_count FROM reports WHERE LOWER(indicator) IN ({_ph}) AND status=%s ORDER BY submitted_at DESC LIMIT 1', _variants + ['approved'])
                _row = _cur.fetchone()
            if not _row:
                with _conn.cursor() as _cur:
                    _cur.execute(f'SELECT id, COALESCE(report_count,1) as report_count FROM reports WHERE LOWER(indicator) IN ({_ph}) AND status=%s LIMIT 1', _variants + ['pending'])
                    _pend = _cur.fetchone()
                if _pend:
                    return jsonify({'status':'pending','indicator':indicator,'report_count':_pend.get('report_count',1),'message':'Under review.'}), 200

                # ── Email domain cross-reference ───────────────────────────
                # Check if the email's domain is blacklisted as a URL
                # e.g. scam@fake-dbs.com → check fake-dbs.com
                if '@' in indicator:
                    email_domain = indicator.split('@')[1].lower().strip()
                    domain_variants = []
                    for proto in ('http://', 'https://'):
                        for prefix in ('', 'www.'):
                            domain_variants.append(proto + prefix + email_domain)
                            domain_variants.append(proto + prefix + email_domain + '/')
                    _dph = ','.join(['%s'] * len(domain_variants))
                    with _conn.cursor() as _cur:
                        _cur.execute(f"""
                            SELECT id, list_type, scam_type, description,
                                   severity, indicator as matched_url,
                                   COALESCE(report_count,1) as report_count
                            FROM reports
                            WHERE indicator IN ({_dph}) AND status='approved'
                            ORDER BY submitted_at DESC LIMIT 1
                        """, domain_variants)
                        _domain_row = _cur.fetchone()
                    if _domain_row:
                        _stype = 'blacklist' if _domain_row['list_type'] == 'blacklist' else 'whitelist'
                        _note  = f"Domain match: {email_domain} is {'blacklisted' if _stype == 'blacklist' else 'flagged'}"
                        return jsonify({
                            'status':       _stype,
                            'indicator':    indicator,
                            'scam_type':    _domain_row.get('scam_type', 'Unknown'),
                            'description':  _note,
                            'severity':     _domain_row.get('severity') or ('high' if _stype == 'blacklist' else 'medium'),
                            'report_count': _domain_row.get('report_count', 1),
                            'fuzzy_match':  True,
                            'matched_domain': email_domain,
                            'message':      'Domain blacklisted'
                        }), 200

                return jsonify({'status':'clean','indicator':indicator,'message':'No reports found.'}), 200
            _stype = 'blacklist' if _row['list_type'] == 'blacklist' else 'whitelist'
            return jsonify({'status':_stype,'indicator':indicator,'scam_type':_row.get('scam_type','Unknown'),'description':_row.get('description',''),'severity':_row.get('severity') or ('high' if _stype=='blacklist' else 'medium'),'report_count':_row.get('report_count',1),'message':'WARNING' if _stype=='blacklist' else 'CAUTION'}), 200
        except Exception as _e:
            return jsonify({'status':'error','message':str(_e)}), 500

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
                    "SELECT id, scam_type, COALESCE(report_count,1) as report_count FROM reports WHERE indicator = %s AND status = 'pending' LIMIT 1",
                    (normalized,)
                )
                pending = cursor.fetchone()
            if pending:
                return jsonify({'status': 'pending', 'indicator': indicator,
                                'scam_type':    pending.get('scam_type', 'Unknown'),
                                'report_count': pending.get('report_count', 1),
                                'message': 'This indicator is pending admin review.'}), 200
            # ── Redirect check ───────────────────────────────────────
            # ── Typosquatting check ──────────────────────────────
            try:
                _domain = indicator.split('://')[-1].split('/')[0].split('?')[0]
                _typo   = check_typosquatting(_domain)
                if _typo:
                    print(f'[typosquat] {indicator} → {_typo["note"]}')
                    return jsonify({
                        'status':      'typosquat',
                        'indicator':   indicator,
                        'trusted':     _typo['trusted'],
                        'distance':    _typo['distance'],
                        'note':        _typo['note'],
                        'scam_type':   'Impersonation',
                        'severity':    'high',
                        'message':     _typo['note'],
                    }), 200
            except Exception as _te:
                print(f'[typosquat] {_te}')

            if indicator.startswith('http'):
                final_url = None
                try:
                    sess = requests.Session()
                    sess.max_redirects = 10
                    current = indicator
                    for _ in range(10):
                        try:
                            resp = sess.get(
                                current,
                                timeout=3,
                                allow_redirects=False,
                                headers={'User-Agent': 'Mozilla/5.0'},
                                stream=True
                            )
                            resp.close()
                            if resp.status_code in (301, 302, 303, 307, 308):
                                loc = resp.headers.get('Location', '')
                                if not loc:
                                    break
                                # Handle relative redirects
                                if loc.startswith('/'):
                                    from urllib.parse import urljoin
                                    loc = urljoin(current, loc)
                                final_url = loc
                                current   = loc
                            else:
                                # No more redirects
                                if current != indicator:
                                    final_url = current
                                break
                        except Exception:
                            # Connection failed at this hop — but we have last known URL
                            if current != indicator:
                                final_url = current
                            break
                except Exception as _re:
                    print(f'[check:redir] Session error: {_re}')

                # Check if final destination is flagged
                if final_url and final_url.rstrip('/') != indicator.rstrip('/'):
                    print(f'[check:redir] {indicator} → {final_url}')
                    try:
                        _fn  = normalize_indicator(final_url)
                        _fvs = []
                        for _p in ('http://', 'https://'):
                            for _pfx in ('', 'www.'):
                                _base = _p + _pfx + _fn.split('://')[-1].lstrip('www.')
                                _fvs.append(_base)
                                _fvs.append(_base + '/')
                        _fph = ','.join(['%s'] * len(_fvs))
                        with conn.cursor() as _cur:
                            _cur.execute(
                                f"SELECT list_type, scam_type, description, severity, "
                                f"COALESCE(report_count,1) as report_count "
                                f"FROM reports WHERE indicator IN ({_fph}) "
                                f"AND status='approved' LIMIT 1",
                                _fvs
                            )
                            redir_row = _cur.fetchone()
                        if redir_row:
                            _st   = redir_row['list_type']
                            _desc = (redir_row.get('description') or '') + f' (Redirected from {indicator})'
                            return jsonify({
                                'status':       _st,
                                'indicator':    indicator,
                                'final_url':    final_url,
                                'scam_type':    redir_row.get('scam_type', 'Unknown'),
                                'description':  _desc,
                                'severity':     redir_row.get('severity') or 'high',
                                'report_count': redir_row.get('report_count', 1),
                                'redirect':     True,
                                'message':      f'Redirects to {_st} site: {final_url}'
                            }), 200
                    except Exception as _re2:
                        print(f'[check:redir:db] {_re2}')

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




@app.route('/my-reports', methods=['GET'])
def my_reports():
    """Returns reports submitted by a specific Telegram user."""
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({'error': 'user_id required'}), 400
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, indicator_type, indicator, scam_type,
                       severity, platform, status, list_type,
                       COALESCE(report_count, 1) as report_count,
                       submitted_at
                FROM reports
                WHERE telegram_user_id = %s
                ORDER BY submitted_at DESC
                LIMIT 10
            """, (user_id,))
            rows = cursor.fetchall()

        reports = [{
            'id':             r['id'],
            'indicator_type': r['indicator_type'],
            'indicator':      r['indicator'],
            'scam_type':      r['scam_type'],
            'severity':       r['severity'] or 'medium',
            'platform':       r['platform'] or 'Telegram',
            'status':         r['status'],
            'list_type':      r['list_type'],
            'report_count':   r['report_count'],
            'submitted_at':   str(r['submitted_at']),
        } for r in rows]

        return jsonify({'reports': reports, 'total': len(reports)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/notifications', methods=['GET'])
def get_notifications():
    """Return spike alerts from in-memory store — no DB needed."""
    mark_sent = request.args.get('mark_sent') == '1'
    now       = _time.time()

    # Filter to last 24 hours
    recent = [
        n for n in _pending_notifications
        if now - n['timestamp'] < 86400
    ][-20:]
    print(f'[notif] pending={len(_pending_notifications)} recent={len(recent)} mark_sent={mark_sent}')

    if mark_sent:
        for n in _pending_notifications:
            n['sent_to_bot'] = True

    notifs = [
        {
            'type':         n['type'],
            'indicator':    n['indicator'],
            'icon':         n.get('icon', '🔗'),
            'scam_type':    n['scam_type'],
            'count':        n['count'],
            'minutes_span': n['minutes_span'],
            'timestamp':    n['timestamp'],
            'age_minutes':  int((now - n['timestamp']) / 60),
        }
        for n in recent
    ]

    unread = sum(1 for n in _pending_notifications if not n.get('sent_to_bot'))
    return jsonify({'notifications': notifs, 'unread': unread}), 200


@app.route('/debug/notifications', methods=['GET'])
def debug_notifications():
    """Dev-only: inspect _pending_notifications directly."""
    return jsonify({
        'count':         len(_pending_notifications),
        'spike_tracker': {k: len(v) for k, v in _spike_tracker.items()},
        'notifications': _pending_notifications,
    }), 200

if __name__ == '__main__':
    import os
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))