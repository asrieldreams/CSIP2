// ============================================================
//  CSIP2 ScamWatch Shield — background.js
//  Service worker: URL checking, badge counter, auto warning
// ============================================================

const API_BASE = 'http://localhost:5000';

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

// Restore badge count on service worker startup
chrome.storage.local.get(['blockedCount'], r => {
    if (r.blockedCount > 0) updateBadge(r.blockedCount);
});


// ── Tab check on load ─────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete' || !tab.url) return;
    if (tab.url.startsWith('chrome://') ||
        tab.url.startsWith('about:')    ||
        tab.url.startsWith('chrome-extension://')) return;

    try {
        const response = await fetch(
            `${API_BASE}/check?url=${encodeURIComponent(tab.url)}`,
            { signal: AbortSignal.timeout(4000) }
        );
        const data = await response.json();

        if (data.status === 'blacklist') {
            // ── Auto popup warning ────────────────────────
            const count  = await incrementBlockedCount();
            const detail = encodeURIComponent(JSON.stringify({
                url:       tab.url,
                scam_type: data.scam_type  || 'Unknown',
                desc:      data.description || 'Confirmed scam indicator',
                count:     count,
            }));

            // Redirect to our warning page
            const warningUrl = chrome.runtime.getURL(`warning.html?d=${detail}`);
            chrome.tabs.update(tabId, { url: warningUrl });

        } else if (data.status === 'whitelist') {
            // Flagged but not confirmed — show badge warning without redirect
            chrome.action.setBadgeText({ text: '⚠', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#d29922', tabId });
        } else {
            // Clean — clear any tab-specific badge
            chrome.action.setBadgeText({ text: '', tabId });
        }

        // Cache result for popup to read instantly
        chrome.storage.session.set({
            [`tab_${tabId}`]: {
                url:    tab.url,
                status: data.status,
                scam_type:   data.scam_type   || null,
                description: data.description || null,
                report_count: data.report_count || 1,
            }
        });

    } catch (err) {
        // Backend not reachable — fail silently
        console.log('[CSIP2] Backend unreachable:', err.message);
    }
});

// Clear cached tab data when tab closes
chrome.tabs.onRemoved.addListener(tabId => {
    chrome.storage.session.remove([`tab_${tabId}`]);
});

// Reset blocked count via message from popup
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