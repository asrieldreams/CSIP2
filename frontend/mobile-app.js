// ============================================================
//  CSIP2 ScamWatch — mobile-app.js v2
//  Injects topbar + bottom nav + quick-check sheet on mobile
//  Add <script src="mobile-app.js"></script> to all 3 pages
// ============================================================

(function () {
  if (window.innerWidth > 768) return;

  const page = window.location.pathname.split('/').pop() || 'introduction.html';
  const API  = 'http://localhost:5000';

  // ── Inject topbar ────────────────────────────────────────
  const topbar = document.createElement('div');
  topbar.className = 'mobile-topbar';
  topbar.innerHTML = `
    <a class="mobile-topbar-logo" href="introduction.html">
      <svg viewBox="0 0 24 24">
        <path d="M12 2L2 7l10 5 10-5-10-5z"/>
        <path d="M2 17l10 5 10-5"/>
        <path d="M2 12l10 5 10-5"/>
      </svg>
      CSIP2 ScamWatch
    </a>
    <div class="mobile-topbar-actions">
      <a class="mobile-topbar-btn" href="reportscam.html" title="Report Scam">📢</a>
    </div>
  `;
  document.body.prepend(topbar);

  // ── Inject bottom nav ─────────────────────────────────────
  const navItems = [
    { icon: '🏠', label: 'Home',     href: 'introduction.html',   id: 'introduction.html' },
    { icon: '🗂️',  label: 'Database', href: 'existingscams.html',  id: 'existingscams.html' },
    { icon: '📢',  label: 'Report',   href: 'reportscam.html',     id: 'reportscam.html' },
    { icon: '🔍',  label: 'Check',    href: '#',                   id: 'check', action: 'openCheck' },
  ];

  const nav = document.createElement('div');
  nav.className = 'mobile-bottom-nav';
  nav.innerHTML = navItems.map(item => `
    <button class="mobile-nav-item ${page === item.id ? 'active' : ''}"
      onclick="mobileNavTo('${item.href}', '${item.id}', ${!!item.action})"
      aria-label="${item.label}">
      <span class="mobile-nav-icon">${item.icon}</span>
      ${item.label}
    </button>
  `).join('');
  document.body.appendChild(nav);

  // ── Inject quick-check sheet ──────────────────────────────
  const sheet = document.createElement('div');
  sheet.className = 'mobile-check-sheet';
  sheet.id = 'mobile-check-sheet';
  sheet.innerHTML = `
    <div class="mobile-check-panel">
      <div class="mobile-check-handle"></div>
      <div class="mobile-check-title">🔍 Quick Check</div>
      <div class="mobile-check-input-row">
        <input
          class="mobile-check-input"
          id="mobile-check-input"
          type="url"
          placeholder="URL, phone, or email…"
          inputmode="url"
          autocapitalize="none"
          autocorrect="off"
        />
        <button class="mobile-check-btn" onclick="mobileRunCheck()">Check</button>
      </div>
      <div class="mobile-check-result" id="mobile-check-result">
        <span class="mobile-check-result-icon">🔎</span>
        <span>Enter a URL, phone number, or email to check against the CSIP2 scam database.</span>
      </div>
    </div>
  `;
  document.body.appendChild(sheet);

  // Close sheet when tapping backdrop
  sheet.addEventListener('click', e => {
    if (e.target === sheet) mobileCloseCheck();
  });

  // Allow Enter key to trigger check
  sheet.querySelector('#mobile-check-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') mobileRunCheck();
  });

  // ── Sheet open/close ──────────────────────────────────────
  // ── Navigate safely (skip if already on page) ────────────
  window.mobileNavTo = function (href, id, isAction) {
    if (isAction) { mobileOpenCheck(); return; }
    if (page === id) return;  // already here — do nothing
    window.location.href = href;
  };

  window.mobileOpenCheck = function () {
    sheet.classList.add('open');
    setTimeout(() => sheet.querySelector('#mobile-check-input').focus(), 350);
  };

  window.mobileCloseCheck = function () {
    sheet.classList.remove('open');
  };

  // ── Run the check ─────────────────────────────────────────
  window.mobileRunCheck = async function () {
    const input  = document.getElementById('mobile-check-input');
    const result = document.getElementById('mobile-check-result');
    const value  = input.value.trim();

    if (!value) {
      input.focus();
      return;
    }

    // Show loading state
    result.className = 'mobile-check-result';
    result.innerHTML = `<span class="mobile-check-result-icon">⏳</span><span>Checking…</span>`;

    try {
      const r = await fetch(`${API}/check?url=${encodeURIComponent(value)}`, {
        signal: AbortSignal.timeout(8000)
      });
      const d = await r.json();

      if (d.status === 'blacklist') {
        result.className = 'mobile-check-result danger';
        result.innerHTML = `
          <span class="mobile-check-result-icon">🚨</span>
          <span>
            <strong>CONFIRMED SCAM</strong><br>
            ${d.scam_type || 'Scam'} · ${d.report_count || 1} report${d.report_count !== 1 ? 's' : ''}
            <br><a href="reportscam.html" style="color:inherit;font-size:0.8rem;text-decoration:underline">📢 Report This</a>
          </span>
        `;
      } else if (d.status === 'whitelist') {
        result.className = 'mobile-check-result warning';
        result.innerHTML = `
          <span class="mobile-check-result-icon">⚠️</span>
          <span>
            <strong>Suspected Scam</strong><br>
            ${d.scam_type || 'Flagged'} · ${d.report_count || 1} report${d.report_count !== 1 ? 's' : ''}
          </span>
        `;
      } else if (d.status === 'pending') {
        result.className = 'mobile-check-result warning';
        result.innerHTML = `
          <span class="mobile-check-result-icon">⏳</span>
          <span><strong>Under Review</strong><br>Reported and awaiting admin review.</span>
        `;
      } else if (d.status === 'typosquat') {
        result.className = 'mobile-check-result warning';
        result.innerHTML = `
          <span class="mobile-check-result-icon">⚠️</span>
          <span>
            <strong>Possible Fake Site</strong><br>
            Looks like <strong>${d.trusted}</strong>
          </span>
        `;
      } else if (d.status === 'rate_limited') {
        result.className = 'mobile-check-result';
        result.innerHTML = `
          <span class="mobile-check-result-icon">⏱️</span>
          <span>Too many checks. Try again in ${Math.ceil((d.reset_in || 60) / 60)} min.</span>
        `;
      } else {
        result.className = 'mobile-check-result safe';
        result.innerHTML = `
          <span class="mobile-check-result-icon">✅</span>
          <span><strong>Not in database</strong><br>Stay cautious. Report if suspicious.</span>
        `;
      }
    } catch (e) {
      result.className = 'mobile-check-result';
      result.innerHTML = `
        <span class="mobile-check-result-icon">❌</span>
        <span>Could not reach server. Is the backend running?</span>
      `;
    }
  };

})();