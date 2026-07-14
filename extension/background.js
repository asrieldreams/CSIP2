// ============================================================
//  CSIP2 ScamWatch Shield — background.js
//  Service worker: URL checking, badge counter, auto warning
// ============================================================

const API_BASE = 'http://localhost:5000';

const SKIP_PREFIXES = [
    'chrome://', 'about:', 'chrome-extension://',
    'chrome-error://', 'edge://', 'data:'
];

const SHORTENERS = [
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl',
    'ow.ly', 'tiny.cc', 'rb.gy', 'cutt.ly',
    'short.io', 'is.gd', 't.me', 'wa.me'
];

// ── Badge counter helpers ─────────────────────────────────

async function getBlockedCount() {
    return new Promise(resolve => {
        chrome.storage.local.get(['blockedCount'], r => resolve(r.blockedCount || 0));
    });
}

async function incrementBlockedCount() {
    const count = await getBlockedCount();
    const next  = count + 1;
    chrome.storage.local.set({ blockedCount: next });
    updateBadge(next);
    return next;
}

function updateBadge(count) {
    if (count > 0) {
        chrome.action.setBadgeText({ text: String(count) });
        chrome.action.setBadgeBackgroundColor({ color: '#f85149' });
    } else {
        chrome.action.setBadgeText({ text: '' });
    }
}

chrome.storage.local.get(['blockedCount'], r => {
    if (r.blockedCount > 0) updateBadge(r.blockedCount);
});

// ── Helpers ───────────────────────────────────────────────

function normalizeUrl(url) {
    if (!url) return url;
    return url.replace(/\/+$/, '') || url;
}

function shouldSkip(url) {
    return SKIP_PREFIXES.some(p => url.startsWith(p));
}

function isShortener(url) {
    try {
        const hostname = new URL(url).hostname.replace('www.', '');
        return SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
    } catch { return false; }
}

// ── Inject warning banner for SUSPECTED sites ─────────────

async function injectSuspectedBanner(tabId, url, data) {
    try {
        // Send message to pre-loaded content.js
        await chrome.tabs.sendMessage(tabId, {
            action:      'showSuspectedBanner',
            url:         url,
            scamType:    data.scam_type    || 'Suspected Scam',
            reportCount: data.report_count || 1,
        });
        return;
    } catch(e) {
        console.log('[CSIP2] Message send failed, trying executeScript:', e.message);
    }
    // Fallback: executeScript if content script not loaded
    try {
        await chrome.scripting.executeScript({
            target: { tabId },
            files:  ['content.js']
        });
        await new Promise(r => setTimeout(r, 100));
        await chrome.tabs.sendMessage(tabId, {
            action:      'showSuspectedBanner',
            url:         url,
            scamType:    data.scam_type    || 'Suspected Scam',
            reportCount: data.report_count || 1,
        });
    } catch(e2) {
        console.log('[CSIP2] Banner inject failed:', e2.message);
    }
}

async function _unused_old_inject(tabId, url, data) {
    try {
        await chrome.scripting.executeScript({
            target: { tabId },
            func: (siteUrl, scamType, reportCount) => {
                // Don't inject twice
                if (document.getElementById('csip2-warning-banner')) return;

                const banner = document.createElement('div');
                banner.id    = 'csip2-warning-banner';
                banner.style.cssText = `
                    position: fixed;
                    top: 16px;
                    right: 16px;
                    z-index: 2147483647;
                    width: 340px;
                    background: #1c1f26;
                    border: 1px solid rgba(210,153,34,0.5);
                    border-left: 4px solid #d29922;
                    border-radius: 10px;
                    padding: 14px 16px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    font-size: 13px;
                    color: #e6edf3;
                    animation: csip2SlideIn 0.35s cubic-bezier(0.34,1.56,0.64,1);
                `;

                const style = document.createElement('style');
                style.textContent = `
                    @keyframes csip2SlideIn {
                        from { opacity:0; transform:translateX(120%); }
                        to   { opacity:1; transform:translateX(0); }
                    }
                    @keyframes csip2SlideOut {
                        from { opacity:1; transform:translateX(0); }
                        to   { opacity:0; transform:translateX(120%); }
                    }
                    #csip2-warning-banner button {
                        cursor: pointer;
                        border: none;
                        border-radius: 6px;
                        font-family: inherit;
                        font-size: 12px;
                        font-weight: 600;
                        padding: 5px 10px;
                    }
                `;
                document.head.appendChild(style);

                banner.innerHTML = `
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px">
                        <div style="display:flex;align-items:center;gap:8px">
                            <span style="font-size:18px">⚠️</span>
                            <div>
                                <div style="font-weight:700;color:#d29922;font-size:13px">SUSPECTED SCAM SITE</div>
                                <div style="font-size:11px;color:#8b949e;margin-top:1px">CSIP2 ScamWatch Shield</div>
                            </div>
                        </div>
                        <button id="csip2-dismiss-btn"
                            style="background:rgba(255,255,255,0.08);color:#8b949e;padding:3px 8px;font-size:11px">
                            ✕
                        </button>
                    </div>

                    <div style="background:rgba(210,153,34,0.1);border-radius:6px;padding:8px 10px;margin-bottom:10px">
                        <div style="font-size:11px;color:#8b949e;margin-bottom:2px">Flagged URL</div>
                        <div style="font-size:12px;color:#f0a500;word-break:break-all;font-family:monospace">${siteUrl}</div>
                    </div>

                    <div style="display:flex;gap:6px;margin-bottom:8px">
                        <div style="background:rgba(210,153,34,0.1);border-radius:5px;padding:4px 8px;font-size:11px;color:#d29922">
                            🏷️ ${scamType || 'Suspected Scam'}
                        </div>
                        <div style="background:rgba(255,255,255,0.05);border-radius:5px;padding:4px 8px;font-size:11px;color:#8b949e">
                            👥 ${reportCount} report${reportCount !== 1 ? 's' : ''}
                        </div>
                    </div>

                    <div style="font-size:12px;color:#8b949e;margin-bottom:10px;line-height:1.5">
                        This site has been flagged by the community but not yet confirmed.
                        <strong style="color:#e6edf3">Proceed with caution.</strong>
                    </div>

                    <div style="display:flex;gap:6px">
                        <button id="csip2-proceed-btn"
                            style="background:rgba(255,255,255,0.06);color:#8b949e;flex:1">
                            Proceed Anyway
                        </button>
                        <button id="csip2-report-btn"
                            style="background:#d29922;color:#fff;flex:1">
                            📢 Report This
                        </button>
                    </div>
                `;

                document.body.appendChild(banner);

                // Dismiss
                document.getElementById('csip2-dismiss-btn').addEventListener('click', () => {
                    banner.style.animation = 'csip2SlideOut 0.25s ease forwards';
                    setTimeout(() => banner.remove(), 250);
                });

                // Proceed anyway — just dismiss
                document.getElementById('csip2-proceed-btn').addEventListener('click', () => {
                    banner.style.animation = 'csip2SlideOut 0.25s ease forwards';
                    setTimeout(() => banner.remove(), 250);
                });

                // Report this
                document.getElementById('csip2-report-btn').addEventListener('click', () => {
                    fetch('http://localhost:5000/report', {
                        method:  'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body:    JSON.stringify({
                            indicator_type: 'url',
                            indicator:      siteUrl,
                            scam_type:      scamType || 'Others',
                            description:    'Reported via CSIP2 ScamWatch Extension banner',
                            source:         'extension'
                        })
                    })
                    .then(() => {
                        document.getElementById('csip2-report-btn').textContent = '✅ Reported!';
                        document.getElementById('csip2-report-btn').style.background = '#3fb950';
                        setTimeout(() => {
                            banner.style.animation = 'csip2SlideOut 0.25s ease forwards';
                            setTimeout(() => banner.remove(), 250);
                        }, 1500);
                    })
                    .catch(() => {
                        document.getElementById('csip2-report-btn').textContent = '❌ Failed';
                    });
                });

                // Auto-dismiss after 12 seconds
                setTimeout(() => {
                    if (document.getElementById('csip2-warning-banner')) {
                        banner.style.animation = 'csip2SlideOut 0.25s ease forwards';
                        setTimeout(() => banner.remove(), 250);
                    }
                }, 12000);
            },
            args: [
                url,
                data.scam_type    || 'Suspected Scam',
                data.report_count || 1,
            ]
        });
    } catch (e) {
        console.log('[CSIP2] Banner inject error:', e.message);
    }
}

// ── Core check function ───────────────────────────────────

const _warned = new Set();

async function checkUrl(tabId, rawUrl) {
    if (!rawUrl || shouldSkip(rawUrl)) return;

    const url = normalizeUrl(rawUrl);
    const key = `${tabId}:${url}`;
    if (_warned.has(key)) return;

    console.log('[CSIP2] Checking:', url);

    try {
        const response = await fetch(
            `${API_BASE}/check?url=${encodeURIComponent(url)}`,
            { signal: AbortSignal.timeout(4000) }
        );
        const data = await response.json();

        console.log('[CSIP2] Result:', data.status, 'for', url);

        if (data.status === 'blacklist') {
            // ── Full warning page for CONFIRMED scams ──────
            _warned.add(key);
            const count  = await incrementBlockedCount();
            const detail = encodeURIComponent(JSON.stringify({
                url:       url,
                scam_type: data.scam_type   || 'Unknown',
                desc:      data.description || 'Confirmed scam indicator',
                count:     count,
            }));
            const warningUrl = chrome.runtime.getURL(`warning.html?d=${detail}`);
            chrome.tabs.update(tabId, { url: warningUrl });

        } else if (data.status === 'whitelist') {
            // ── Banner warning for SUSPECTED scams ─────────
            _warned.add(key);
            chrome.action.setBadgeText({ text: '⚠', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#d29922', tabId });
            // Inject floating banner on the page
            await injectSuspectedBanner(tabId, url, data);

        } else if (data.status === 'pending') {
            // Pending — subtle amber badge only
            chrome.action.setBadgeText({ text: '?', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#8b949e', tabId });

        } else {
            chrome.action.setBadgeText({ text: '', tabId });
        }

        chrome.storage.session.set({
            [`tab_${tabId}`]: {
                url, status: data.status,
                scam_type:    data.scam_type    || null,
                description:  data.description  || null,
                report_count: data.report_count || 1,
            }
        });

    } catch (err) {
        console.log('[CSIP2] Backend unreachable:', err.message);
    }
}

// ── Listeners ─────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (shouldSkip(url)) return;
    if (isShortener(url)) {
        console.log('[CSIP2] Shortener detected:', url);
        await checkUrl(details.tabId, url);
        chrome.action.setBadgeText({ text: '⚠', tabId: details.tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#d29922', tabId: details.tabId });
        chrome.storage.session.set({ [`tab_${details.tabId}_shortener`]: { original: url, ts: Date.now() } });
    }
});

chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    await checkUrl(details.tabId, details.url);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete' || !tab.url) return;
    await checkUrl(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener(tabId => {
    chrome.storage.session.remove([`tab_${tabId}`]);
    for (const key of _warned) {
        if (key.startsWith(`${tabId}:`)) _warned.delete(key);
    }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'resetCount') {
        chrome.storage.local.set({ blockedCount: 0 });
        chrome.action.setBadgeText({ text: '' });
        sendResponse({ ok: true });
    }
    if (msg.action === 'getTabStatus') {
        chrome.storage.session.get([`tab_${msg.tabId}`], r => {
            sendResponse(r[`tab_${msg.tabId}`] || null);
        });
        return true;
    }
});