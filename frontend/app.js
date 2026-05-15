// ============================================================
//  CSIP2 — Frontend JavaScript
//  Owner: Caden (Frontend Lead)
// ============================================================

const API_BASE = 'http://localhost:5000';   // change to deployed URL later

// ── Pagination ────────────────────────────────────────────
const ITEMS_PER_PAGE = 10;
let allReports  = [];
let currentPage = 1;


// ============================================================
//  REPORT SUBMISSION (index.html)
// ============================================================

async function submitReport() {
  const indicator_type = document.getElementById('indicator_type')?.value;
  const indicator      = document.getElementById('indicator')?.value?.trim();
  const scam_type      = document.getElementById('scam_type')?.value;
  const description    = document.getElementById('description')?.value?.trim();

  const successBanner = document.getElementById('success-banner');
  const errorBanner   = document.getElementById('error-banner');
  const submitBtn     = document.getElementById('submit-btn');

  // Hide any previous banners
  successBanner.style.display = 'none';
  errorBanner.style.display   = 'none';

  // ── Client-side validation ─────────────────────────────
  if (!indicator_type) return showError('Please select what you are reporting.');
  if (!indicator)      return showError('Please enter the scam indicator.');
  if (!scam_type)      return showError('Please select a scam type.');
  if (indicator.length > 500) return showError('Indicator is too long (max 500 characters).');

  // Disable button while submitting
  submitBtn.disabled    = true;
  submitBtn.textContent = 'Submitting...';

  try {
    const response = await fetch(`${API_BASE}/report`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator_type, indicator, scam_type, description, source: 'website' })
    });

    const data = await response.json();

    if (response.ok) {
      successBanner.style.display = 'block';
      // Clear the form
      document.getElementById('indicator_type').value = '';
      document.getElementById('indicator').value      = '';
      document.getElementById('scam_type').value      = '';
      document.getElementById('description').value    = '';
      document.querySelector('.char-count').textContent = '0 / 500 characters';
    } else {
      showError(data.error || 'Submission failed. Please try again.');
    }

  } catch (err) {
    showError('Could not reach the server. Please check your connection.');
  }

  submitBtn.disabled    = false;
  submitBtn.textContent = 'Submit Report';
}

function showError(message) {
  const errorBanner = document.getElementById('error-banner');
  errorBanner.textContent = '⚠️ ' + message;
  errorBanner.style.display = 'block';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Character counter for description textarea
document.addEventListener('DOMContentLoaded', () => {
  const desc      = document.getElementById('description');
  const charCount = document.querySelector('.char-count');
  if (desc && charCount) {
    desc.addEventListener('input', () => {
      charCount.textContent = `${desc.value.length} / 500 characters`;
    });
  }
});


// ============================================================
//  PUBLIC SCAM FEED (feed.html)
// ============================================================

async function loadReports() {
  const keyword  = document.getElementById('search')?.value?.trim();
  const scamType = document.getElementById('filter-type')?.value;
  const listType = document.getElementById('filter-list')?.value;
  const container = document.getElementById('reports-container');

  if (!container) return;

  container.innerHTML = '<div class="loading">Loading scam reports...</div>';
  currentPage = 1;

  // Build query string
  const params = new URLSearchParams();
  if (keyword)  params.append('keyword',   keyword);
  if (scamType) params.append('scam_type', scamType);
  if (listType) params.append('list_type', listType);

  try {
    const response = await fetch(`${API_BASE}/reports?${params.toString()}`);
    const data     = await response.json();

    allReports = data.reports || [];

    // Update stats bar
    const statsBar = document.getElementById('stats-bar');
    if (statsBar) {
      statsBar.innerHTML = `Showing <strong>${allReports.length}</strong> report${allReports.length !== 1 ? 's' : ''}`;
      if (keyword || scamType || listType) {
        statsBar.innerHTML += ` matching your filters`;
      }
    }

    renderPage(currentPage);

  } catch (err) {
    container.innerHTML = '<div class="empty">⚠️ Could not load reports. Please try again later.</div>';
  }
}

function renderPage(page) {
  const container = document.getElementById('reports-container');
  const pagination = document.getElementById('pagination');

  if (allReports.length === 0) {
    container.innerHTML = '<div class="empty">No scam reports found. Be the first to <a href="index.html">report one</a>!</div>';
    if (pagination) pagination.innerHTML = '';
    return;
  }

  const start    = (page - 1) * ITEMS_PER_PAGE;
  const end      = start + ITEMS_PER_PAGE;
  const pageData = allReports.slice(start, end);

  container.innerHTML = pageData.map(report => renderReportCard(report)).join('');

  // Render pagination
  const totalPages = Math.ceil(allReports.length / ITEMS_PER_PAGE);
  if (pagination) {
    pagination.innerHTML = '';
    for (let i = 1; i <= totalPages; i++) {
      const btn = document.createElement('button');
      btn.textContent = i;
      if (i === page) btn.classList.add('active');
      btn.onclick = () => { currentPage = i; renderPage(i); window.scrollTo({ top: 0, behavior: 'smooth' }); };
      pagination.appendChild(btn);
    }
  }
}

function renderReportCard(report) {
  const listType   = report.list_type || 'pending';
  const badgeClass = listType === 'blacklist' ? 'badge-blacklist'
                   : listType === 'whitelist' ? 'badge-whitelist'
                   : 'badge-pending';
  const badgeLabel = listType === 'blacklist' ? '🔴 Blacklisted'
                   : listType === 'whitelist' ? '🟡 Whitelisted'
                   : '⏳ Under Review';

  const typeIcon = report.indicator_type === 'url'     ? '🔗'
                 : report.indicator_type === 'phone'   ? '📞'
                 : report.indicator_type === 'email'   ? '📧'
                 : '💬';

  const date = new Date(report.submitted_at).toLocaleDateString('en-SG', {
    day: 'numeric', month: 'short', year: 'numeric'
  });

  return `
    <div class="report-card ${listType}">
      <div class="report-header">
        <span class="report-indicator">${typeIcon} ${escapeHtml(report.indicator)}</span>
        <span class="badge ${badgeClass}">${badgeLabel}</span>
      </div>
      <div class="report-meta">
        <span>📌 ${escapeHtml(report.scam_type)}</span>
        <span>📅 ${date}</span>
        <span>📤 Via ${capitalise(report.source)}</span>
      </div>
      ${report.description ? `<div class="report-description">${escapeHtml(report.description)}</div>` : ''}
    </div>
  `;
}

// ── Helpers ───────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function capitalise(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// Allow pressing Enter in the search box to search
document.addEventListener('DOMContentLoaded', () => {
  const searchBox = document.getElementById('search');
  if (searchBox) {
    searchBox.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') loadReports();
    });
  }
});
