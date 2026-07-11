// ============================================================
//  CSIP2 ScamWatch Shield — background.js
//  Checks EVERY URL in the navigation chain:
//  bit.ly → redirect → final URL (all get checked)
// ============================================================

const API_BASE = 'http://localhost:5000';

// Skip these — not real pages to check
const SKIP_PREFIXES = [
    'chrome://', 'about:', 'chrome-extension://',
    'chrome-error://', 'edge://', 'data:'
];

// Known URL shorteners to always expand/check
const SHORTENERS = [
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl',
    'ow.ly', 'tiny.cc', 'rb.gy', 'cutt.ly',
    'short.io', 'is.gd', 't.me', 'wa.me'
];

// ── Badge counter helpers ─────────────────────────────────

async function getBlockedCount() {
    return new Promise(resolve => {
        chrome.storage.local.get(['blockedCount'], r => {
            resolve(r.blockedCount || 0);
        });
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

// Restore badge on service worker startup
chrome.storage.local.get(['blockedCount'], r => {
    if (r.blockedCount > 0) updateBadge(r.blockedCount);
});


// ── Normalize URL ─────────────────────────────────────────
function normalizeUrl(url) {
    if (!url) return url;
    // Strip trailing slash from root domains
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


// ── Core check function ───────────────────────────────────
// Tracked tabs to avoid duplicate warnings for same URL
const _warned = new Set();

async function checkUrl(tabId, rawUrl) {
    if (!rawUrl || shouldSkip(rawUrl)) return;

    const url = normalizeUrl(rawUrl);

    // Don't warn twice for same URL in same tab session
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
            _warned.add(key);

            const count = await incrementBlockedCount();

            // Use hash fragment — always preserved in extension navigation
            const warningData = encodeURIComponent(JSON.stringify({
                url:       url,
                scam_type: data.scam_type   || 'Unknown',
                desc:      data.description || 'Confirmed scam indicator',
                count:     count,
            }));
            const warningUrl = chrome.runtime.getURL('warning.html') + '#' + warningData;
            chrome.tabs.update(tabId, { url: warningUrl });

        } else if (data.status === 'whitelist') {
            // Flagged — set amber badge on this tab
            chrome.action.setBadgeText({ text: '⚠', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#d29922', tabId });
        } else {
            chrome.action.setBadgeText({ text: '', tabId });
        }

        // Cache for popup
        chrome.storage.session.set({
            [`tab_${tabId}`]: {
                url,
                status:       data.status,
                scam_type:    data.scam_type    || null,
                description:  data.description  || null,
                report_count: data.report_count || 1,
            }
        });

    } catch (err) {
        console.log('[CSIP2] Backend unreachable:', err.message);
    }
}


// ── Listener 1: Catch URLs BEFORE redirect ────────────────
// This fires for bit.ly, tinyurl, etc. BEFORE they redirect
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // Main frame only

    const url = details.url;
    if (shouldSkip(url)) return;

    // Always check shortener URLs before redirect
    if (isShortener(url)) {
        console.log('[CSIP2] Shortener detected — checking before redirect:', url);
        await checkUrl(details.tabId, url);

        // Show amber badge warning for ANY shortener link
        // (even if not in DB — shorteners can hide scam destinations)
        chrome.action.setBadgeText({ text: '⚠', tabId: details.tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#d29922', tabId: details.tabId });

        // Store shortener flag for popup to show warning
        chrome.storage.session.set({
            [`tab_${details.tabId}_shortener`]: { 
                original: url,
                ts: Date.now()
            }
        });
    }
});


// ── Listener 2: Catch the FINAL URL after all redirects ───
// This catches the destination URL (e.g., Instagram after bit.ly redirect)
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return; // Main frame only
    await checkUrl(details.tabId, details.url);
});


// ── Listener 3: Keep backward compat with onUpdated ───────
// Belt and suspenders — catches anything the above missed
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete' || !tab.url) return;
    await checkUrl(tabId, tab.url);
});


// ── Clear tab cache and warned set on tab close ───────────
chrome.tabs.onRemoved.addListener(tabId => {
    chrome.storage.session.remove([`tab_${tabId}`]);
    // Clean up warned set for this tab
    for (const key of _warned) {
        if (key.startsWith(`${tabId}:`)) _warned.delete(key);
    }
});


// ── Message handler ───────────────────────────────────────
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
        return true; // async
    }
});