// ============================================================
//  CSIP2 ScamWatch Shield — content.js
//  Pre-loaded on all pages.
//  1. Listens for banner messages from background.js
//  2. Scans Gmail & Outlook for scam sender emails
// ============================================================

// API calls routed through background.js to avoid CORS (see background.js csip2Check/csip2Report)

// ── Message listener (from background.js) ────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'showSuspectedBanner') {
        showPageBanner(msg.url, msg.scamType, msg.reportCount);
        sendResponse({ ok: true });
    }
    if (msg.action === 'dismissBanner') {
        const b = document.getElementById('csip2-warning-banner');
        if (b) dismissBanner(b);
        sendResponse({ ok: true });
    }
});


// ══════════════════════════════════════════════════════════════
//  EMAIL PROVIDER DETECTION
// ══════════════════════════════════════════════════════════════

function getEmailProvider() {
    const host = window.location.hostname;
    if (host.includes('mail.google.com'))  return 'gmail';
    if (host.includes('outlook.live.com') ||
        host.includes('outlook.office.com') ||
        host.includes('hotmail.com'))       return 'outlook';
    return null;
}

// ── Main init ─────────────────────────────────────────────────

const provider = getEmailProvider();
if (provider) {
    console.log(`[CSIP2] Email scanner active on ${provider}`);
    initEmailScanner(provider);
}


// ══════════════════════════════════════════════════════════════
//  EMAIL SCANNER — watches for email opens and checks sender
// ══════════════════════════════════════════════════════════════

function initEmailScanner(provider) {
    let lastCheckedEmail = null;
    let debounceTimer    = null;
    let isChecking       = false;

    async function tryCheck(retries = 3) {
        if (isChecking) return;

        let email = extractSenderEmail(provider);

        // Retry if extraction failed — Gmail renders in stages
        if (!email && retries > 0) {
            setTimeout(() => tryCheck(retries - 1), 300);
            return;
        }

        if (email && email !== lastCheckedEmail) {
            lastCheckedEmail = email;
            isChecking       = true;
            await checkEmailSender(email, provider);
            isChecking = false;
        } else if (!email && lastCheckedEmail) {
            lastCheckedEmail = null;
        }
    }

    function onDomChange() {
        const email = extractSenderEmail(provider);
        if (email && email !== lastCheckedEmail) {
            clearTimeout(debounceTimer);
            tryCheck();
        } else {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(tryCheck, 250);
        }
    }

    const observer = new MutationObserver(onDomChange);
    observer.observe(document.body, { childList: true, subtree: true });

    // Run immediately on load
    setTimeout(tryCheck, 300);
}


// ── Extract sender email from DOM ─────────────────────────────

function extractSenderEmail(provider) {
    try {
        if (provider === 'gmail') {
            const selectors = [
                '.gD[email]',
                'span.gD[email]',
                'span[email].gD',
                'h3.iw span[email]',
                'span[email][data-hovercard-id]',
                '.go.gD[email]',
                '.qu[email]',
                '[data-hovercard-id][email]',
            ];
            for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (el) {
                    const e = el.getAttribute('email') || el.getAttribute('data-hovercard-id');
                    if (e && e.includes('@') && e.includes('.')) {
                        console.log(`[CSIP2] Sender extracted via "${sel}":`, e);
                        return e.toLowerCase().trim();
                    }
                }
            }

            // Any element with email attribute
            const withEmail = document.querySelectorAll('[email]');
            for (const el of withEmail) {
                const e = el.getAttribute('email');
                if (e && e.includes('@') && e.includes('.') && !e.includes('google.com')) {
                    console.log('[CSIP2] Sender via [email] attr:', e);
                    return e.toLowerCase().trim();
                }
            }

            // data-hovercard-id
            const hoverEls = document.querySelectorAll('[data-hovercard-id]');
            for (const el of hoverEls) {
                const val = el.getAttribute('data-hovercard-id') || '';
                if (val.includes('@') && val.includes('.') && !val.includes('google.com')) {
                    console.log('[CSIP2] Sender via data-hovercard-id:', val);
                    return val.toLowerCase().trim();
                }
            }

            // Regex fallback
            const fromContainers = document.querySelectorAll(
                '.iw, .ha, .hb, .gE.iv.gt, [data-message-id]'
            );
            for (const container of fromContainers) {
                const text  = container.textContent || '';
                const match = text.match(/[\w.\-+%]+@[\w.\-]+\.[a-zA-Z]{2,}/);
                if (match && !match[0].includes('google.com')) {
                    console.log('[CSIP2] Sender via text regex:', match[0]);
                    return match[0].toLowerCase().trim();
                }
            }

            console.warn('[CSIP2] Could not extract Gmail sender — no selector matched');

        } else if (provider === 'outlook') {
            const selectors = [
                '[data-testid="senderDetails"] [title*="@"]',
                '.ReadingPaneContent [title*="@"]',
                '[aria-label*="@"]',
                '[data-focuszone-id] [aria-label*="@"]',
            ];
            for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (el) {
                    const text  = el.getAttribute('title') || el.getAttribute('aria-label') || '';
                    const match = text.match(/[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}/);
                    if (match) return match[0].toLowerCase().trim();
                }
            }
            const pane = document.querySelector('[role="main"]');
            if (pane) {
                const match = (pane.innerHTML || '').match(/[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}/);
                if (match) return match[0].toLowerCase().trim();
            }
        }
    } catch (e) {
        console.error('[CSIP2] extractSenderEmail error:', e.message);
    }
    return null;
}


// ── Check sender against CSIP2 DB ────────────────────────────

const _lastEmailCheck = {};

async function checkEmailSender(email, provider) {
    const now    = Date.now();
    const lastAt = _lastEmailCheck[email] || 0;

    // Throttle: skip if checked within last 5 seconds
    if (now - lastAt < 5000) return;
    _lastEmailCheck[email] = now;

    // Remove any existing email banner
    const old = document.getElementById('csip2-email-banner');
    if (old) {
        old.style.transition = 'opacity 0.15s';
        old.style.opacity    = '0';
        setTimeout(() => old.remove(), 150);
    }

    console.log(`[CSIP2] Checking email sender: ${email}`);

    try {
        // Route through background.js — avoids CORS from Gmail/Outlook origin
        const response = await chrome.runtime.sendMessage({
            action: 'csip2Check',
            url:    email,
        });

        if (!response || !response.ok) {
            console.warn('[CSIP2] Check failed:', response?.error);
            return;
        }

        const data = response.data;
        console.log(`[CSIP2] Result for ${email}:`, data.status);

        if (data.status === 'blacklist') {
            showEmailWarning(email, data, 'danger', provider);
        } else if (data.status === 'whitelist') {
            showEmailWarning(email, data, 'warning', provider);
        } else {
            console.log(`[CSIP2] ${email} is clean (${data.status})`);
        }

    } catch (e) {
        console.error('[CSIP2] Email check error:', e.message);
    }
}


// ══════════════════════════════════════════════════════════════
//  EMAIL WARNING BANNER
// ══════════════════════════════════════════════════════════════

function showEmailWarning(email, data, severity, provider) {
    if (document.getElementById('csip2-email-banner')) return;

    const isDanger  = severity === 'danger';
    const isFlagged = severity === 'warning';

    const accent   = isDanger  ? '#f85149'
                   : isFlagged ? '#d29922' : '#8b949e';
    const bgColor  = isDanger  ? 'rgba(248,81,73,0.08)'
                   : isFlagged ? 'rgba(210,153,34,0.08)' : 'rgba(139,148,158,0.08)';
    const border   = isDanger  ? 'rgba(248,81,73,0.35)'
                   : isFlagged ? 'rgba(210,153,34,0.35)' : 'rgba(139,148,158,0.2)';
    const icon     = isDanger  ? '🚨' : '⚠️';
    const label    = isDanger  ? 'CONFIRMED SCAM SENDER' : 'FLAGGED SENDER';
    const subLabel = isDanger  ? 'Community confirmed scam'
                   : isFlagged ? 'Community suspected — use caution' : 'Reported — under review';
    const count    = data.report_count || 1;
    const scamType = data.scam_type || 'Unknown';

    if (!document.getElementById('csip2-email-styles')) {
        const style       = document.createElement('style');
        style.id          = 'csip2-email-styles';
        style.textContent = `
            #csip2-email-banner {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif !important;
                font-size: 13px !important; line-height: 1.5 !important; box-sizing: border-box !important;
            }
            #csip2-email-banner * { box-sizing: border-box !important; }
            #csip2-email-banner button {
                cursor: pointer !important; font-family: inherit !important;
                font-size: 12px !important; font-weight: 600 !important;
                border: none !important; border-radius: 6px !important;
                padding: 5px 12px !important; transition: opacity 0.15s !important;
            }
            #csip2-email-banner button:hover { opacity: 0.8 !important; }
            @keyframes csip2slideDown {
                from { opacity:0; transform:translateY(-12px); }
                to   { opacity:1; transform:translateY(0); }
            }
        `;
        document.head.appendChild(style);
    }

    const banner = document.createElement('div');
    banner.id    = 'csip2-email-banner';
    banner.style.cssText = `
        position: fixed !important; top: 12px !important; left: 50% !important;
        transform: translateX(-50%) !important; z-index: 2147483647 !important;
        width: min(540px, calc(100vw - 24px)) !important;
        background: #1a1e27 !important;
        border: 1.5px solid ${border} !important;
        border-top: 4px solid ${accent} !important;
        border-radius: 10px !important; padding: 14px 16px !important;
        box-shadow: 0 8px 32px rgba(0,0,0,0.35) !important;
        color: #e6edf3 !important;
        animation: csip2slideDown 0.3s ease !important;
    `;

    banner.innerHTML = `
        <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px">
            <div style="display:flex;align-items:center;gap:9px">
                <span style="font-size:22px;line-height:1">${icon}</span>
                <div>
                    <div style="font-weight:800;color:${accent};font-size:13px;letter-spacing:0.02em">${label}</div>
                    <div style="font-size:11px;color:#6e7681;margin-top:1px">${subLabel}</div>
                </div>
            </div>
            <button id="csip2-email-x" style="background:rgba(255,255,255,0.07);color:#8b949e;padding:3px 8px;font-size:11px;margin-left:8px;flex-shrink:0">✕ Dismiss</button>
        </div>
        <div style="background:${bgColor};border:1px solid ${border};border-radius:7px;padding:9px 12px;margin-bottom:10px">
            <div style="font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:0.07em;margin-bottom:3px">Flagged Sender</div>
            <div style="font-weight:700;color:${accent};font-family:monospace;font-size:13px;word-break:break-all">${email}</div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">
            <span style="background:${bgColor};border:1px solid ${border};border-radius:5px;padding:3px 9px;font-size:11px;font-weight:600;color:${accent}">🏷️ ${scamType}</span>
            <span style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:5px;padding:3px 9px;font-size:11px;color:#8b949e">👥 ${count} community report${count !== 1 ? 's' : ''}</span>
            <span style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:5px;padding:3px 9px;font-size:11px;color:#8b949e">📧 Email sender</span>
        </div>
        <div style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">
            ${isDanger
                ? '⛔ <strong style="color:#e6edf3">Do NOT</strong> click links or attachments. Report to ScamAlert.sg or call <strong style="color:#e6edf3">1800-722-6688</strong>.'
                : isFlagged
                    ? '⚠️ Community flagged — not yet confirmed. <strong style="color:#e6edf3">Do not share personal info</strong> or click unknown links.'
                    : '⏳ This sender has been reported and is under admin review.'}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button id="csip2-email-report" style="background:#2f81f7;color:#fff;flex:1;min-width:120px">📢 Report Sender</button>
            <button id="csip2-email-ignore" style="background:rgba(255,255,255,0.06);color:#8b949e;flex:1;min-width:100px">Proceed Anyway</button>
        </div>
        <div id="csip2-email-status" style="margin-top:6px;font-size:11px;color:#8b949e;min-height:14px;text-align:center"></div>
    `;

    document.body.appendChild(banner);
    console.log('[CSIP2] Email warning banner injected for', email);

    document.getElementById('csip2-email-x').addEventListener('click', () => {
        banner.style.transition = 'opacity 0.2s';
        banner.style.opacity    = '0';
        setTimeout(() => banner.remove(), 200);
    });

    document.getElementById('csip2-email-ignore').addEventListener('click', () => {
        banner.style.transition = 'opacity 0.2s';
        banner.style.opacity    = '0';
        setTimeout(() => banner.remove(), 200);
    });

    document.getElementById('csip2-email-report').addEventListener('click', async () => {
        const btn    = document.getElementById('csip2-email-report');
        const status = document.getElementById('csip2-email-status');
        btn.disabled    = true;
        btn.textContent = '⏳ Submitting...';
        try {
            const resp = await chrome.runtime.sendMessage({
                action:  'csip2Report',
                payload: {
                    indicator_type: 'email',
                    indicator:      email,
                    scam_type:      scamType || 'Others',
                    description:    'Reported via CSIP2 ScamWatch email scanner',
                    source:         'extension',
                }
            });
            const result = resp?.data || {};
            if (resp?.ok || result.message) {
                btn.textContent      = '✅ Reported!';
                btn.style.background = '#3fb950';
                status.textContent   = 'Thank you! Report submitted to CSIP2 database.';
                status.style.color   = '#3fb950';
            } else {
                throw new Error(result.error || 'Failed');
            }
        } catch (e) {
            btn.textContent = '❌ Failed';
            btn.disabled    = false;
            status.textContent = `Error: ${e.message}`;
        }
    });

    // Auto-dismiss after 20s for suspected only
    if (!isDanger) {
        setTimeout(() => {
            if (document.getElementById('csip2-email-banner')) {
                banner.style.transition = 'opacity 0.3s';
                banner.style.opacity    = '0';
                setTimeout(() => banner.remove(), 300);
            }
        }, 20000);
    }
}


// ══════════════════════════════════════════════════════════════
//  PAGE BANNER (for suspected websites — from background.js)
// ══════════════════════════════════════════════════════════════

function dismissBanner(banner) {
    banner.style.animation = 'csip2SlideOut 0.25s ease forwards';
    setTimeout(() => banner.remove(), 250);
}

function showPageBanner(url, scamType, reportCount) {
    if (document.getElementById('csip2-warning-banner')) return;

    if (!document.getElementById('csip2-styles')) {
        const style = document.createElement('style');
        style.id    = 'csip2-styles';
        style.textContent = `
            @keyframes csip2SlideIn {
                from { opacity:0; transform:translateX(110%) scale(0.95); }
                to   { opacity:1; transform:translateX(0) scale(1); }
            }
            @keyframes csip2SlideOut {
                from { opacity:1; transform:translateX(0); }
                to   { opacity:0; transform:translateX(110%); }
            }
            #csip2-warning-banner * { box-sizing: border-box; }
            #csip2-warning-banner button {
                cursor: pointer; border: none; border-radius: 6px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                font-size: 12px; font-weight: 600; padding: 6px 12px;
                transition: opacity 0.15s;
            }
            #csip2-warning-banner button:hover { opacity: 0.85; }
        `;
        document.head.appendChild(style);
    }

    const banner = document.createElement('div');
    banner.id    = 'csip2-warning-banner';
    banner.style.cssText = `
        position: fixed !important; top: 16px !important; right: 16px !important;
        z-index: 2147483647 !important; width: 340px !important;
        background: #1c1f26 !important;
        border: 1px solid rgba(210,153,34,0.5) !important;
        border-left: 4px solid #d29922 !important; border-radius: 10px !important;
        padding: 14px 16px !important; box-shadow: 0 8px 32px rgba(0,0,0,0.5) !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
        font-size: 13px !important; color: #e6edf3 !important; line-height: 1.4 !important;
        animation: csip2SlideIn 0.35s cubic-bezier(0.34,1.56,0.64,1) !important;
    `;

    const shortUrl = url.length > 40 ? url.slice(0, 40) + '...' : url;
    banner.innerHTML = `
        <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px">
            <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:20px;line-height:1">⚠️</span>
                <div>
                    <div style="font-weight:700;color:#d29922;font-size:13px">SUSPECTED SCAM SITE</div>
                    <div style="font-size:11px;color:#6e7681;margin-top:1px">🛡️ CSIP2 ScamWatch Shield</div>
                </div>
            </div>
            <button id="csip2-x" style="background:rgba(255,255,255,0.06);color:#8b949e;padding:3px 8px;font-size:11px;margin-left:8px;flex-shrink:0">✕</button>
        </div>
        <div style="background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.2);border-radius:6px;padding:8px 10px;margin-bottom:10px">
            <div style="font-size:10px;color:#6e7681;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.06em">Flagged URL</div>
            <div style="font-size:12px;color:#f0a500;font-family:monospace;word-break:break-all">${shortUrl}</div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
            <div style="background:rgba(210,153,34,0.12);border-radius:5px;padding:3px 8px;font-size:11px;color:#d29922;font-weight:600">🏷️ ${scamType || 'Suspected Scam'}</div>
            <div style="background:rgba(255,255,255,0.05);border-radius:5px;padding:3px 8px;font-size:11px;color:#8b949e">👥 ${reportCount} community report${reportCount !== 1 ? 's' : ''}</div>
        </div>
        <div style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">Community flagged. <strong style="color:#e6edf3">Proceed with caution.</strong></div>
        <div style="display:flex;gap:8px">
            <button id="csip2-proceed" style="background:rgba(255,255,255,0.06);color:#8b949e;flex:1">Proceed Anyway</button>
            <button id="csip2-report"  style="background:#d29922;color:#fff;flex:1">📢 Report This</button>
        </div>
        <div id="csip2-status" style="text-align:center;font-size:11px;margin-top:6px;min-height:14px;color:#8b949e"></div>
    `;

    document.body.appendChild(banner);

    document.getElementById('csip2-x').addEventListener('click',       () => dismissBanner(banner));
    document.getElementById('csip2-proceed').addEventListener('click', () => dismissBanner(banner));

    document.getElementById('csip2-report').addEventListener('click', async () => {
        const btn    = document.getElementById('csip2-report');
        const status = document.getElementById('csip2-status');
        btn.disabled    = true;
        btn.textContent = '⏳ Submitting...';
        try {
            const resp = await chrome.runtime.sendMessage({
                action:  'csip2Report',
                payload: { indicator_type:'url', indicator:url,
                    scam_type: scamType||'Others',
                    description:'Reported via CSIP2 ScamWatch banner', source:'extension' }
            });
            btn.textContent      = '✅ Reported!';
            btn.style.background = '#3fb950';
            status.textContent   = 'Thank you! Report submitted.';
            status.style.color   = '#3fb950';
            setTimeout(() => dismissBanner(banner), 2000);
        } catch(e) {
            btn.textContent = '❌ Failed'; btn.disabled = false;
        }
    });

    setTimeout(() => {
        if (document.getElementById('csip2-warning-banner')) dismissBanner(banner);
    }, 15000);
}