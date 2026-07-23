// ── Data variables ────────────────────────────────────────
let blockedUrl  = '';
let scamType    = 'Unknown';
let scamDesc    = 'Confirmed scam in CSIP2 database';
let threatCount = 1;

// ── Read from chrome.storage (set by background.js) ─────────
function loadData() {
    // Read warning data stored by background.js
    chrome.storage.local.get('csip2_warning', (result) => {
        const d = result.csip2_warning;
        if (d) {
            blockedUrl  = d.url       || '';
            scamType    = d.scam_type || 'Unknown';
            scamDesc    = d.desc      || 'Confirmed scam in CSIP2 database';
            threatCount = d.count     || 1;
        }

        // Update UI
        document.getElementById('url-box').textContent     = blockedUrl  || 'URL not available';
        document.getElementById('scam-type').textContent   = scamType;
        document.getElementById('scam-desc').textContent   = scamDesc;
        document.getElementById('count-badge').textContent = '🚨 Threats blocked this session: ' + threatCount;
    });
}

// Run on load
document.addEventListener('DOMContentLoaded', loadData);

// ── Button handlers ────────────────────────────────────────

// Back to Safety
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btn-back').addEventListener('click', function() {
        // Go to a safe page — Google as default
        window.location.href = 'https://www.google.com';
    });

    // Report This Site
    document.getElementById('btn-report').addEventListener('click', async function() {
        if (!blockedUrl) {
            document.getElementById('report-status').textContent = '❌ No URL to report.';
            return;
        }
        const btn = this;
        btn.disabled    = true;
        btn.textContent = '⏳ Submitting...';

        try {
            const res = await fetch('https://csip2-backend-production.up.railway.app/report', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    indicator_type: 'url',
                    indicator:      blockedUrl,
                    scam_type:      (scamType !== 'Unknown' ? scamType : 'Others'),
                    description:    'Reported via CSIP2 ScamWatch Extension warning page',
                    source:         'extension'
                })
            });
            const result = await res.json();

            if (res.status === 201) {
                btn.textContent      = '✅ Reported!';
                btn.style.background = '#3fb950';
                document.getElementById('report-status').innerHTML =
                    '<span style="color:#3fb950">✅ Thank you! Report submitted.</span>';
            } else if (result.duplicate) {
                btn.textContent      = '👥 Already Reported';
                btn.style.background = '#d29922';
                document.getElementById('report-status').innerHTML =
                    '<span style="color:#d29922">Already reported by ' + (result.report_count || 'multiple') + ' people.</span>';
            } else {
                throw new Error(result.error || 'Unknown error');
            }
        } catch(e) {
            btn.textContent      = '❌ Failed';
            btn.style.background = '#f85149';
            document.getElementById('report-status').innerHTML =
                '<span style="color:#f85149">Error: ' + e.message + '</span>';
        }

        setTimeout(function() {
            btn.disabled         = false;
            btn.textContent      = '📢 Report This Site';
            btn.style.background = '';
        }, 3000);
    });

    // Proceed Anyway
    document.getElementById('btn-proceed').addEventListener('click', function() {
        if (!blockedUrl) {
            document.getElementById('report-status').textContent = '❌ No URL to proceed to.';
            return;
        }
        const confirmed = confirm(
            '⚠️ WARNING: This site is confirmed as a SCAM.\n\n' +
            'Proceeding is extremely risky. Do NOT enter any personal or financial information.\n\n' +
            'Are you absolutely sure you want to continue?'
        );
        if (confirmed) {
            // Tell background.js to allow this URL once (skip re-warning)
            chrome.runtime.sendMessage({
                action: 'allowUrlOnce',
                url:    blockedUrl
            }, () => {
                window.location.href = blockedUrl;
            });
        }
    });
});