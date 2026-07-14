// ============================================================
//  CSIP2 ScamWatch — mobile-app.js
//  Injects mobile top bar + bottom navigation on phones
//  Add <script src="mobile-app.js"></script> to all 3 pages
// ============================================================

(function () {
  if (window.innerWidth > 768) return; // desktop only gets this on resize too

  // ── Detect current page ─────────────────────────────────
  const page = window.location.pathname.split('/').pop() || 'introduction.html';
  const isHome     = page.includes('introduction') || page === '' || page === 'index.html';
  const isDatabase = page.includes('existingscams');
  const isReport   = page.includes('reportscam');

  // ── Inject top bar ──────────────────────────────────────
  function injectTopBar() {
    const topbar = document.createElement('div');
    topbar.className = 'mobile-topbar';
    topbar.innerHTML = `
      <a href="introduction.html" class="mobile-topbar-logo">
        <svg viewBox="0 0 24 24">
          <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6l-8-4z"/>
        </svg>
        ScamWatch
      </a>
      <div class="mobile-topbar-actions">
        <button class="mobile-topbar-btn" id="mobile-theme-toggle" title="Toggle theme">🌙</button>
        <a href="admindashboard.html" class="mobile-topbar-btn" title="Admin">🔒</a>
      </div>
    `;
    document.body.insertBefore(topbar, document.body.firstChild);

    // Theme toggle
    document.getElementById('mobile-theme-toggle').addEventListener('click', () => {
      const html  = document.documentElement;
      const theme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', theme);
      localStorage.setItem('csip2-theme', theme);
      document.getElementById('mobile-theme-toggle').textContent = theme === 'dark' ? '☀️' : '🌙';
    });
    // Apply saved theme
    const saved = localStorage.getItem('csip2-theme');
    if (saved) {
      document.documentElement.setAttribute('data-theme', saved);
      document.getElementById('mobile-theme-toggle').textContent = saved === 'dark' ? '☀️' : '🌙';
    }
  }

  // ── Inject bottom navigation ────────────────────────────
  function injectBottomNav() {
    const nav = document.createElement('nav');
    nav.className = 'mobile-bottom-nav';
    nav.innerHTML = `
      <a href="introduction.html" class="mobile-nav-item ${isHome ? 'active' : ''}">
        <span class="mobile-nav-icon">🏠</span>
        <span>Home</span>
      </a>
      <a href="existingscams.html" class="mobile-nav-item ${isDatabase ? 'active' : ''}">
        <span class="mobile-nav-icon">🗂️</span>
        <span>Database</span>
      </a>
      <a href="reportscam.html" class="mobile-nav-item ${isReport ? 'active' : ''}">
        <span class="mobile-nav-icon" style="font-size:24px">📢</span>
        <span>Report</span>
      </a>
      <a href="existingscams.html" class="mobile-nav-item" id="mobile-check-btn">
        <span class="mobile-nav-icon">🔍</span>
        <span>Check</span>
      </a>
    `;
    document.body.appendChild(nav);

    // Check button → open quick check sheet
    document.getElementById('mobile-check-btn').addEventListener('click', (e) => {
      e.preventDefault();
      showCheckSheet();
    });
  }

  // ── Quick check bottom sheet ────────────────────────────
  function showCheckSheet() {
    if (document.getElementById('csip2-check-sheet')) return;

    const sheet = document.createElement('div');
    sheet.id = 'csip2-check-sheet';
    sheet.style.cssText = `
      position: fixed; inset: 0; z-index: 500;
      background: rgba(0,0,0,0.6);
      backdrop-filter: blur(4px);
      display: flex; align-items: flex-end;
      animation: fadeIn 0.2s ease;
    `;
    sheet.innerHTML = `
      <style>
        @keyframes fadeIn { from{opacity:0} to{opacity:1} }
        @keyframes slideUp { from{transform:translateY(100%)} to{transform:translateY(0)} }
        #csip2-check-inner { animation: slideUp 0.3s cubic-bezier(0.34,1.56,0.64,1); }
      </style>
      <div id="csip2-check-inner" style="
        background: var(--surface, #161b22);
        width: 100%;
        border-radius: 24px 24px 0 0;
        padding: 0 1.25rem 2rem;
        border-top: 1px solid rgba(255,255,255,0.08);
      ">
        <div style="width:40px;height:4px;background:rgba(255,255,255,0.15);border-radius:2px;margin:12px auto 1.25rem"></div>
        <div style="font-size:1.1rem;font-weight:800;color:var(--ink,#e6edf3);margin-bottom:4px">🔍 Quick Check</div>
        <div style="font-size:0.82rem;color:var(--ink-muted,#6e7681);margin-bottom:1rem">
          Check any URL, phone or email against the scam database
        </div>
        <input id="csip2-check-input"
          style="
            width:100%; background:rgba(255,255,255,0.06);
            border:1px solid rgba(255,255,255,0.12); border-radius:12px;
            padding:13px 14px; font-size:16px; color:var(--ink,#e6edf3);
            outline:none; margin-bottom:0.75rem;
          "
          placeholder="Paste URL, phone or email..."
          autocomplete="off" autocorrect="off" autocapitalize="off"
        />
        <div id="csip2-check-result" style="margin-bottom:0.75rem;min-height:44px"></div>
        <div style="display:flex;gap:0.6rem">
          <button id="csip2-check-cancel" style="
            flex:1; padding:13px; border-radius:12px;
            background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.1);
            color:var(--ink-soft,#8b949e); font-size:0.88rem; font-weight:600;
            cursor:pointer; font-family:inherit;
          ">Cancel</button>
          <button id="csip2-check-go" style="
            flex:2; padding:13px; border-radius:12px;
            background:var(--accent,#1a3cf8); border:none;
            color:#fff; font-size:0.88rem; font-weight:700;
            cursor:pointer; font-family:inherit;
          ">Check Now</button>
        </div>
      </div>
    `;

    document.body.appendChild(sheet);
    setTimeout(() => document.getElementById('csip2-check-input')?.focus(), 300);

    const close = () => sheet.remove();
    sheet.addEventListener('click', (e) => { if (e.target === sheet) close(); });
    document.getElementById('csip2-check-cancel').addEventListener('click', close);

    document.getElementById('csip2-check-go').addEventListener('click', async () => {
      const val    = document.getElementById('csip2-check-input').value.trim();
      const resEl  = document.getElementById('csip2-check-result');
      const btn    = document.getElementById('csip2-check-go');
      if (!val) return;

      btn.textContent = 'Checking...';
      btn.disabled    = true;
      resEl.innerHTML = '<div style="color:var(--ink-muted,#6e7681);font-size:0.82rem">Scanning database...</div>';

      // Normalize
      let url = val;
      if (!url.startsWith('http') && url.includes('.') && !url.includes('@') && !url.includes(' ')) {
        url = 'http://' + url;
      }

      try {
        const res  = await fetch(`http://localhost:5000/check?url=${encodeURIComponent(url)}`);
        const data = await res.json();

        const STATUS_MAP = {
          blacklist: {
            bg:    'rgba(248,81,73,0.12)',
            border:'rgba(248,81,73,0.3)',
            icon:  '🚨',
            label: 'BLACKLISTED — Confirmed Scam',
            color: '#f85149',
          },
          whitelist: {
            bg:    'rgba(210,153,34,0.1)',
            border:'rgba(210,153,34,0.3)',
            icon:  '⚠️',
            label: 'SUSPECTED — Community Flagged',
            color: '#d29922',
          },
          pending: {
            bg:    'rgba(47,129,247,0.1)',
            border:'rgba(47,129,247,0.3)',
            icon:  '⏳',
            label: 'Under Review',
            color: '#2f81f7',
          },
        };

        const s = STATUS_MAP[data.status];
        if (s) {
          resEl.innerHTML = `
            <div style="
              background:${s.bg}; border:1px solid ${s.border};
              border-radius:10px; padding:10px 12px;
            ">
              <div style="font-weight:700;color:${s.color};font-size:0.85rem;margin-bottom:4px">
                ${s.icon} ${s.label}
              </div>
              ${data.scam_type ? `<div style="font-size:0.78rem;color:var(--ink-muted,#6e7681)">📌 ${data.scam_type} · 👥 ${data.report_count||1} report${data.report_count!==1?'s':''}</div>` : ''}
            </div>
          `;
        } else {
          resEl.innerHTML = `
            <div style="
              background:rgba(63,185,80,0.1); border:1px solid rgba(63,185,80,0.25);
              border-radius:10px; padding:10px 12px;
            ">
              <div style="font-weight:700;color:#3fb950;font-size:0.85rem">✅ Not Found in Database</div>
              <div style="font-size:0.78rem;color:var(--ink-muted,#6e7681)">Always stay cautious online</div>
            </div>
          `;
        }
      } catch (e) {
        resEl.innerHTML = `<div style="color:#f85149;font-size:0.82rem">❌ Backend offline — start with: python backend/app.py</div>`;
      }

      btn.textContent = 'Check Another';
      btn.disabled    = false;
      btn.onclick     = () => {
        document.getElementById('csip2-check-input').value = '';
        resEl.innerHTML = '';
        btn.textContent = 'Check Now';
        document.getElementById('csip2-check-input').focus();
      };
    });

    // Enter key
    document.getElementById('csip2-check-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') document.getElementById('csip2-check-go').click();
    });
  }

  // ── Run on DOM ready ────────────────────────────────────
  function init() {
    injectTopBar();
    injectBottomNav();

    // Apply saved theme
    const saved = localStorage.getItem('csip2-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Re-run on resize
  window.addEventListener('resize', () => {
    const hasMobileNav = document.querySelector('.mobile-bottom-nav');
    if (window.innerWidth <= 768 && !hasMobileNav) init();
  });
})();