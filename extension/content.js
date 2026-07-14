
// ============================================================
//  CSIP2 ScamWatch Shield — content.js
//  Pre-loaded on all pages — listens for banner messages
// ============================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'showSuspectedBanner') {
        showBanner(msg.url, msg.scamType, msg.reportCount);
        sendResponse({ ok: true });
    }
    if (msg.action === 'dismissBanner') {
        const b = document.getElementById('csip2-warning-banner');
        if (b) dismissBanner(b);
        sendResponse({ ok: true });
    }
});

function dismissBanner(banner) {
    banner.style.animation = 'csip2SlideOut 0.25s ease forwards';
    setTimeout(() => banner.remove(), 250);
}

function showBanner(url, scamType, reportCount) {
    if (document.getElementById('csip2-warning-banner')) return;

    // Inject styles
    if (!document.getElementById('csip2-styles')) {
        const style = document.createElement('style');
        style.id    = 'csip2-styles';
        style.textContent = `
            @keyframes csip2SlideIn {
                from { opacity:0; transform:translateX(110%) scale(0.95); }
                to   { opacity:1; transform:translateX(0)   scale(1); }
            }
            @keyframes csip2SlideOut {
                from { opacity:1; transform:translateX(0); }
                to   { opacity:0; transform:translateX(110%); }
            }
            #csip2-warning-banner * { box-sizing: border-box; }
            #csip2-warning-banner button {
                cursor: pointer;
                border: none;
                border-radius: 6px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                font-size: 12px;
                font-weight: 600;
                padding: 6px 12px;
                transition: opacity 0.15s;
            }
            #csip2-warning-banner button:hover { opacity: 0.85; }
        `;
        document.head.appendChild(style);
    }

    const banner = document.createElement('div');
    banner.id    = 'csip2-warning-banner';
    banner.style.cssText = `
        position: fixed !important;
        top: 16px !important;
        right: 16px !important;
        z-index: 2147483647 !important;
        width: 340px !important;
        background: #1c1f26 !important;
        border: 1px solid rgba(210,153,34,0.5) !important;
        border-left: 4px solid #d29922 !important;
        border-radius: 10px !important;
        padding: 14px 16px !important;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5) !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
        font-size: 13px !important;
        color: #e6edf3 !important;
        line-height: 1.4 !important;
        animation: csip2SlideIn 0.35s cubic-bezier(0.34,1.56,0.64,1) !important;
    `;

    const shortUrl = url.length > 40 ? url.slice(0, 40) + '...' : url;

    banner.innerHTML = `
        <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px">
            <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:20px;line-height:1">⚠️</span>
                <div>
                    <div style="font-weight:700;color:#d29922;font-size:13px;letter-spacing:0.02em">SUSPECTED SCAM SITE</div>
                    <div style="font-size:11px;color:#6e7681;margin-top:1px">🛡️ CSIP2 ScamWatch Shield</div>
                </div>
            </div>
            <button id="csip2-x"
                style="background:rgba(255,255,255,0.06);color:#8b949e;padding:3px 8px;font-size:11px;margin-left:8px;flex-shrink:0">
                ✕
            </button>
        </div>

        <div style="background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.2);border-radius:6px;padding:8px 10px;margin-bottom:10px">
            <div style="font-size:10px;color:#6e7681;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.06em">Flagged URL</div>
            <div style="font-size:12px;color:#f0a500;font-family:monospace;word-break:break-all">${shortUrl}</div>
        </div>

        <div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
            <div style="background:rgba(210,153,34,0.12);border-radius:5px;padding:3px 8px;font-size:11px;color:#d29922;font-weight:600">
                🏷️ ${scamType || 'Suspected Scam'}
            </div>
            <div style="background:rgba(255,255,255,0.05);border-radius:5px;padding:3px 8px;font-size:11px;color:#8b949e">
                👥 ${reportCount} community report${reportCount !== 1 ? 's' : ''}
            </div>
        </div>

        <div style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">
            This site has been flagged by the community but not yet confirmed.
            <strong style="color:#e6edf3">Proceed with caution.</strong>
        </div>

        <div style="display:flex;gap:8px">
            <button id="csip2-proceed"
                style="background:rgba(255,255,255,0.06);color:#8b949e;flex:1">
                Proceed Anyway
            </button>
            <button id="csip2-report"
                style="background:#d29922;color:#fff;flex:1">
                📢 Report This
            </button>
        </div>
        <div id="csip2-status" style="text-align:center;font-size:11px;margin-top:6px;min-height:14px;color:#8b949e"></div>
    `;

    document.body.appendChild(banner);

    // Dismiss button
    document.getElementById('csip2-x').addEventListener('click', () => dismissBanner(banner));

    // Proceed
    document.getElementById('csip2-proceed').addEventListener('click', () => dismissBanner(banner));

    // Report
    document.getElementById('csip2-report').addEventListener('click', () => {
        const btn    = document.getElementById('csip2-report');
        const status = document.getElementById('csip2-status');
        btn.disabled    = true;
        btn.textContent = '⏳ Submitting...';

        fetch('http://localhost:5000/report', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                indicator_type: 'url',
                indicator:      url,
                scam_type:      scamType || 'Others',
                description:    'Reported via CSIP2 ScamWatch Extension warning banner',
                source:         'extension'
            })
        })
        .then(r => r.json())
        .then(() => {
            btn.textContent    = '✅ Reported!';
            btn.style.background = '#3fb950';
            status.textContent = 'Thank you for helping keep SG safe!';
            setTimeout(() => dismissBanner(banner), 2000);
        })
        .catch(() => {
            btn.textContent  = '❌ Failed';
            btn.disabled     = false;
            status.textContent = 'Backend offline — try again later';
        });
    });

    // Auto-dismiss after 15 seconds
    setTimeout(() => {
        if (document.getElementById('csip2-warning-banner')) dismissBanner(banner);
    }, 15000);
}