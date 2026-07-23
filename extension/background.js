// ============================================================
//  CSIP2 ScamWatch Shield — background.js
//  Service worker: URL checking, badge counter, auto warning
// ============================================================

const API_BASE = 'https://csip2-backend-production.up.railway.app';

const SKIP_PREFIXES = [
    'chrome://', 'about:', 'chrome-extension://',
    'chrome-error://', 'edge://', 'data:'
];

const MAIL_DOMAINS = [
    'mail.google.com',
    'outlook.live.com',
    'outlook.office.com',
    'outlook.office365.com',
    'mail.yahoo.com',
    'mail.proton.me',
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
    if (SKIP_PREFIXES.some(p => url.startsWith(p))) return true;
    if (url.startsWith('file://')) return true;
    try {
        const host = new URL(url).hostname;
        if (host === 'localhost' || host === '127.0.0.1' || host.startsWith('192.168.')) return true;
        if (MAIL_DOMAINS.some(d => host === d || host.endsWith('.' + d))) return true;
    } catch { return false; }
    return false;
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
        await chrome.tabs.sendMessage(tabId, {
            action:      'showSuspectedBanner',
            url:         data.indicator || data.url || url,
            scamType:    data.scam_type    || 'Suspected Scam',
            reportCount: data.report_count || 1,
        });
        return;
    } catch(e) {
        console.log('[CSIP2] Message send failed, trying executeScript:', e.message);
    }
    try {
        await chrome.scripting.executeScript({
            target: { tabId },
            files:  ['content.js']
        });
        await new Promise(r => setTimeout(r, 100));
        await chrome.tabs.sendMessage(tabId, {
            action:      'showSuspectedBanner',
            url:         data.indicator || data.url || url,
            scamType:    data.scam_type    || 'Suspected Scam',
            reportCount: data.report_count || 1,
        });
    } catch(e2) {
        console.log('[CSIP2] Banner inject failed:', e2.message);
    }
}

// ── Core check function ───────────────────────────────────

const _warned      = new Set();
const _allowedOnce = new Set();

async function checkUrl(tabId, rawUrl) {
    if (!rawUrl || shouldSkip(rawUrl)) return;

    const url = normalizeUrl(rawUrl);
    const key = `${tabId}:${url}`;

    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab && tab.url && tab.url.includes('warning.html')) return;

    const allowedData  = await chrome.storage.local.get(['csip2_allowed_once', 'csip2_allowed_until']);
    const allowedList  = allowedData.csip2_allowed_once  || [];
    const allowedUntil = allowedData.csip2_allowed_until || 0;

    if (allowedList.includes(url) && Date.now() < allowedUntil) {
        const newList = allowedList.filter(u => u !== url);
        chrome.storage.local.set({ csip2_allowed_once: newList });
        return;
    } else if (Date.now() >= allowedUntil) {
        chrome.storage.local.remove(['csip2_allowed_once', 'csip2_allowed_until']);
    }

    if (_warned.has(key)) {
        _warned.delete(key);
    }

    try {
        const response = await fetch(
            `${API_BASE}/check?url=${encodeURIComponent(url)}`,
            { signal: AbortSignal.timeout(4000) }
        );
        const data = await response.json();

        if (data.status === 'blacklist') {
            _warned.add(key);
            const count = await incrementBlockedCount();
            const warningData = {
                url:       url,
                scam_type: data.scam_type   || 'Unknown',
                desc:      data.description || 'Confirmed scam indicator',
                count:     count,
            };
            chrome.storage.local.set({ csip2_warning: warningData }, () => {
                const warningUrl = chrome.runtime.getURL('warning.html');
                chrome.tabs.update(tabId, { url: warningUrl });
            });

        } else if (data.status === 'whitelist') {
            chrome.action.setBadgeText({ text: '⚠', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#d29922', tabId });
            await injectSuspectedBanner(tabId, url, data);

        } else if (data.status === 'pending') {
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

// ══════════════════════════════════════════════════════════
//  MESSAGE HANDLERS
// ══════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

    // ── API proxy for content scripts ─────────────────────
    // Content scripts (Gmail/Outlook) can't fetch Railway directly
    // due to CORS. Background service worker has no CORS restriction.

    if (msg.action === 'csip2Check' && msg.url) {
        fetch(`${API_BASE}/check?url=${encodeURIComponent(msg.url)}`, {
            signal: AbortSignal.timeout(8000)
        })
        .then(r => r.json())
        .then(data => sendResponse({ ok: true, data }))
        .catch(err  => sendResponse({ ok: false, error: err.message }));
        return true; // keep channel open for async
    }

    if (msg.action === 'csip2Report' && msg.payload) {
        fetch(`${API_BASE}/report`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(msg.payload),
            signal:  AbortSignal.timeout(10000)
        })
        .then(r => r.json().then(data => ({ status: r.status, data })))
        .then(({ status, data }) => sendResponse({ ok: status < 300, data }))
        .catch(err => sendResponse({ ok: false, error: err.message }));
        return true;
    }

    // ── Allow URL once (Proceed Anyway on warning page) ───

    if (msg.action === 'allowUrlOnce' && msg.url) {
        const url = msg.url;
        const alt = url.startsWith('https://')
            ? url.replace('https://', 'http://')
            : url.replace('http://', 'https://');

        chrome.storage.local.get('csip2_allowed_once', (data) => {
            const allowed = data.csip2_allowed_once || [];
            allowed.push(url, alt);
            chrome.storage.local.set({
                csip2_allowed_once:  allowed,
                csip2_allowed_until: Date.now() + 30000  // 30-second window
            }, () => sendResponse({ ok: true }));
        });
        return true;
    }

    // ── Popup / misc ──────────────────────────────────────

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