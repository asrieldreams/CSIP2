# ScamWatch — Flask Backend

Complete backend for the ScamWatch crowdsourced scam intelligence platform.
Connects to MySQL Workbench via `.env` configuration.

---

## Project Structure

```
scamwatch/
├── app.py              # Flask app factory — entry point
├── config.py           # Reads .env → DB URI, secrets, JWT config
├── extensions.py       # Shared SQLAlchemy db instance
├── requirements.txt    # Python packages
├── .env.example        # Copy to .env and fill in your values
├── seed.py             # Creates all 7 tables + seeds demo data
├── models/
│   └── __init__.py     # All 7 SQLAlchemy models
├── routes/
│   ├── __init__.py
│   ├── auth.py         # POST /api/auth/login, GET /api/auth/me
│   ├── scams.py        # Public scam browse + anonymous report submit
│   ├── admin.py        # All admin dashboard endpoints (JWT protected)
│   └── scanner.py      # POST /api/scanner/check
└── utils/
    └── __init__.py     # JWT decorator, audit logger, rate limiter, auto-indicators
```

---

## Setup (Step by Step)

### 1. Create the database in MySQL Workbench
Open MySQL Workbench, connect to your server, and run:
```sql
CREATE DATABASE scamwatch CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 2. Install Python packages
```bash
pip install -r requirements.txt
```

### 3. Create your .env file
```bash
cp .env.example .env
```
Then open `.env` and fill in your MySQL Workbench credentials:
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_actual_password
DB_NAME=scamwatch
SECRET_KEY=any-random-string
JWT_SECRET=another-random-string
```

### 4. Seed the database (creates tables + demo data)
```bash
python seed.py
```
This creates all 7 tables and inserts 15 scam reports, 8 scanner indicators,
3 admin accounts, spam sessions, rules, settings, and audit log entries.

### 5. Start the server
```bash
python app.py
```
Server runs at **http://localhost:5000**

---

## API Endpoints Quick Reference

### Public (no auth required)
| Method | URL | Used by |
|--------|-----|---------|
| GET | `/api/scams` | existingscams.html — browse verified scams |
| GET | `/api/scams/stats` | introduction.html + existingscams.html stat cards |
| GET | `/api/scams/<id>` | existingscams.html detail modal |
| POST | `/api/scams` | reportscam.html — submit anonymous report |
| POST | `/api/scanner/check` | Scanner tool — check URL or number |

### Admin (add `Authorization: Bearer <token>` header)
| Method | URL | Used by |
|--------|-----|---------|
| POST | `/api/auth/login` | Admin login modal |
| GET | `/api/auth/me` | Verify stored token |
| GET | `/api/admin/stats` | Dashboard stat cards |
| GET | `/api/admin/reports` | Scam Reports table |
| PATCH | `/api/admin/reports/<id>` | Verify / flag / remove one report |
| DELETE | `/api/admin/reports/<id>` | Permanently delete |
| PATCH | `/api/admin/reports/bulk` | Bulk verify / flag / remove |
| GET | `/api/admin/indicators` | Scanner Indicators page |
| POST | `/api/admin/indicators` | Manually add indicator |
| DELETE | `/api/admin/indicators/<id>` | Remove indicator |
| GET | `/api/admin/spam` | Spam & Abuse Control page |
| DELETE | `/api/admin/spam/<id>` | Dismiss spam session |
| PATCH | `/api/admin/spam/<id>/block` | Block IP |
| DELETE | `/api/admin/spam/all` | Clear all spam sessions |
| GET | `/api/admin/admins` | List admin accounts |
| POST | `/api/admin/admins` | Add new admin (super admin only) |
| DELETE | `/api/admin/admins/<id>` | Remove admin (super admin only) |
| GET | `/api/admin/rate-rules` | Get rate limit rules |
| PATCH | `/api/admin/rate-rules` | Update rate limit rules |
| GET | `/api/admin/settings` | Get site settings |
| PATCH | `/api/admin/settings` | Update settings |
| GET | `/api/admin/audit-log` | Full audit history |
| GET | `/api/admin/analytics` | Analytics charts data |
| DELETE | `/api/admin/purge-removed` | Purge removed reports (super admin) |
| DELETE | `/api/admin/clear-pending` | Clear pending queue (super admin) |

---

## Connecting the Frontend HTML Files

### 1. reportscam.html — submit form
In the `submitReport()` function, replace the mock timeout with:
```javascript
const res  = await fetch('http://localhost:5000/api/scams', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        type:         selectedType,
        title:        document.getElementById('scam-desc').value.split('\n')[0],
        description:  document.getElementById('scam-desc').value,
        platform:     document.getElementById('platform').value,
        url:          document.getElementById('scam-url').value,
        phone_number: document.getElementById('scammer-num').value,
        amount_lost:  document.getElementById('amount-lost').value || null,
        severity:     selectedSeverity || 'medium',
    })
});
const data = await res.json();
document.getElementById('report-id-text').textContent = data.report_id;
```

### 2. existingscams.html — browse + stats
```javascript
const API_BASE = 'http://localhost:5000/api';

// In fetchScams() — replace mock block with:
const res  = await fetch(`${API_BASE}/scams?${params}`);
return await res.json();

// In fetchStats() — replace mock block with:
const res  = await fetch(`${API_BASE}/scams/stats`);
return await res.json();

// In fetchScamById(id) — replace mock block with:
const res  = await fetch(`${API_BASE}/scams/${id}`);
return await res.json();
```

### 3. introduction.html — admin login modal
In `attemptLogin()`, replace the mock timeout with:
```javascript
const res  = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email:    document.getElementById('admin-username').value + '@scamwatch.sg',
        password: document.getElementById('admin-password').value,
    })
});
const data = await res.json();
if (res.ok) {
    localStorage.setItem('sw_token', data.token);
    window.location.href = 'admindashboard.html';
} else {
    // show error — data.error contains the message
}
```

### 4. admindashboard.html — all admin calls
Change the API constant at the top:
```javascript
const API = 'http://localhost:5000/api';
```

Then for every `fetch()` in the admin dashboard, add the auth header:
```javascript
headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${localStorage.getItem('sw_token')}`
}
```

---

## Demo Credentials (seeded by seed.py)
| Email | Password | Role |
|-------|----------|------|
| admin@scamwatch.sg | admin123 | Super Admin |
| sarah.t@scamwatch.sg | sarah456 | Moderator |
| m.lim@scamwatch.sg | marcus789 | Analyst |
