// ============================================================
//  CSIP2 ScamWatch Shield — popup.js
//  Shows URL status, blocked count, report button
// ============================================================

const API_BASE = 'https://csip2-backend-production.up.railway.app';

// ── Status card configs ───────────────────────────────────
const STATUS_CONFIG = {
    blacklist: {
        cls:   'danger',
        icon:  '🚨',
        title: 'BLACKLISTED — Confirmed Scam',
        desc:  'This page is a verified scam. Do NOT enter any information.',
    },
    whitelist: {
        cls:   'warning',
        icon:  '⚠️',
        title: 'FLAGGED — Suspected Scam',
        desc:  'Community flagged this page. Proceed with extreme caution.',
    },
    pending: {
        cls:   'pending',
        icon:  '⏳',
        title: 'Under Review',
        desc:  'This page has been reported and is pending admin verification.',
    },
    clean: {
        cls:   'safe',
        icon:  '✅',
        title: 'No Threats Detected',
        desc:  'Not in CSIP2 scam database. Always stay cautious online.',
    },
    error: {
        cls:   'loading',
        icon:  '⚡',
        title: 'Backend Offline',
        desc:  'Could not reach CSIP2 backend. Start with: python backend/app.py',
    },
};

// ── Set status card UI ────────────────────────────────────
function setStatus(key, extraDesc) {
    const cfg  = STATUS_CONFIG[key] || STATUS_CONFIG.error;
    const card = document.getElementById('status-card');
    card.className = `status-card ${cfg.cls}`;

    const iconEl = document.getElementById('status-icon');
    iconEl.className = '';
    iconEl.textContent = cfg.icon;
    iconEl.style.fontSize = '1.5rem';

    document.getElementById('status-title').textContent = cfg.title;
    document.getElementById('status-desc').textContent  = extraDesc || cfg.desc;
}

// ── Main init ─────────────────────────────────────────────
async function init() {
    // 1. Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url   = tab?.url || '';

    // Show URL
    const urlEl = document.getElementById('current-url');
    urlEl.textContent = url || 'No URL detected';

    // 2. Load blocked count from storage
    chrome.storage.local.get(['blockedCount'], r => {
        document.getElementById('blocked-count').textContent = r.blockedCount || 0;
    });

    // 3. Try to get cached status from background service worker
    let cached = null;
    try {
        cached = await new Promise(resolve => {
            chrome.runtime.sendMessage(
                { action: 'getTabStatus', tabId: tab.id },
                r => resolve(r)
            );
        });
    } catch(e) {}

    if (cached) {
        // Use cached result
        setStatus(cached.status,
            cached.scam_type
                ? `Scam type: ${cached.scam_type} | ${cached.description || ''}`
                : null
        );
        if (cached.report_count > 1) {
            document.getElementById('status-desc').textContent +=
                ` | 👥 Reported by ${cached.report_count} people`;
        }
    } else {
        // No cache — fetch directly
        if (!url || url.startsWith('chrome://') || url.startsWith('about:')) {
            setStatus('clean', 'Browser internal page — no check needed');
        } else {
            try {
                const res  = await fetch(
                    `${API_BASE}/check?url=${encodeURIComponent(url)}`,
                    { signal: AbortSignal.timeout(4000) }
                );
                const data = await res.json();
                const desc = data.scam_type
                    ? `Scam type: ${data.scam_type}${data.report_count > 1 ? ` | 👥 ${data.report_count} reports` : ''}`
                    : null;
                setStatus(data.status, desc);
            } catch(e) {
                setStatus('error');
                document.getElementById('report-btn').disabled = true;
            }
        }
    }

    // 4. Fetch total DB count for stats
    try {
        const statsRes  = await fetch(`${API_BASE}/api/scams/stats`,
            { signal: AbortSignal.timeout(3000) });
        const statsData = await statsRes.json();
        document.getElementById('db-count').textContent =
            (statsData.total || 0).toLocaleString();
    } catch(e) {
        document.getElementById('db-count').textContent = '—';
    }

    // 5. Report button
    document.getElementById('report-btn').addEventListener('click', async () => {
        const btn = document.getElementById('report-btn');
        btn.disabled    = true;
        btn.textContent = '⏳ Submitting...';

        try {
            const res = await fetch(`${API_BASE}/report`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    indicator_type: 'url',
                    indicator:      url,
                    scam_type:      'Others',
                    description:    'Reported via CSIP2 ScamWatch Extension',
                    source:         'extension'
                })
            });
            const result = await res.json();

            if (res.ok) {
                btn.textContent = '✅ Reported!';
                btn.style.background = '#3fb950';
            } else if (result.duplicate) {
                btn.textContent = `👥 Already reported by ${result.report_count || '?'} people`;
                btn.style.background = '#d29922';
            } else {
                btn.textContent = '❌ ' + (result.error || 'Failed');
                btn.style.background = '#f85149';
            }
        } catch(e) {
            btn.textContent = '❌ Backend offline';
            btn.style.background = '#f85149';
        }

        setTimeout(() => {
            btn.disabled    = false;
            btn.textContent = '📢 Report This Page';
            btn.style.background = '';
        }, 3000);
    });

    // 6. Reset counter button
    document.getElementById('reset-btn').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'resetCount' }, () => {
            document.getElementById('blocked-count').textContent = '0';
            document.getElementById('reset-btn').textContent = '✅ Reset!';
            setTimeout(() => {
                document.getElementById('reset-btn').textContent = '🔄 Reset Threat Counter';
            }, 1500);
        });
    });
}

init();