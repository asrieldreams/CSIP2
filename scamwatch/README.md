# ScamWatch — Flask Backend

## Quick Start

### 1. Create MySQL database
```sql
CREATE DATABASE scamwatch CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 2. Configure .env
Edit `.env` and set your MySQL credentials:
```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=scamwatch
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Seed database (creates tables + sample data)
```bash
python seed.py
```

### 5. Run the server
```bash
python app.py
```
Server runs at **http://localhost:5000**

---

## API Reference

### Public (no auth needed)
| Method | Endpoint | Used by |
|--------|----------|---------|
| GET | `/api/scams` | existingscams.html |
| GET | `/api/scams/stats` | introduction.html, existingscams.html |
| GET | `/api/scams/<id>` | existingscams.html modal |
| POST | `/api/scams` | reportscam.html form |
| POST | `/api/scanner/check` | scanner tool |

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Admin login → returns JWT token |
| GET | `/api/auth/me` | Get current admin profile |

### Admin (requires JWT in Authorization header)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/stats` | Dashboard stats |
| GET | `/api/admin/reports` | All reports with filters |
| PATCH | `/api/admin/reports/<id>` | Update status/severity |
| DELETE | `/api/admin/reports/<id>` | Hard delete (super_admin only) |
| POST | `/api/admin/reports/bulk` | Bulk verify/flag/remove |
| GET | `/api/admin/spam` | Spam sessions |
| DELETE | `/api/admin/spam/<id>` | Dismiss spam session |
| POST | `/api/admin/spam/<id>/block` | Block IP |
| GET | `/api/admin/admins` | List admin accounts |
| POST | `/api/admin/admins` | Add admin (super_admin only) |
| PATCH | `/api/admin/admins/<id>` | Edit role (super_admin only) |
| DELETE | `/api/admin/admins/<id>` | Remove admin (super_admin only) |
| GET | `/api/admin/indicators` | Scanner indicators |
| POST | `/api/admin/indicators` | Add indicator manually |
| DELETE | `/api/admin/indicators/<id>` | Remove indicator |
| GET | `/api/admin/rate-rules` | Get rate limit rules |
| PATCH | `/api/admin/rate-rules` | Update rate limit rules |
| GET | `/api/admin/settings` | Site settings |
| PATCH | `/api/admin/settings` | Update site settings |
| GET | `/api/admin/analytics` | Analytics data |
| GET | `/api/admin/audit-log` | Audit log |
| DELETE | `/api/admin/purge/removed` | Purge removed reports |
| DELETE | `/api/admin/purge/pending` | Clear pending queue |

---

## Connecting the HTML frontend

In each HTML file, update the API base URL and uncomment the fetch calls:

**existingscams.html / scam-database.html**
```javascript
const API_BASE = 'http://localhost:5000/api';
// Then uncomment the real fetch() inside fetchScams(), fetchStats(), fetchScamById()
```

**admindashboard.html**
```javascript
const API = 'http://localhost:5000/api';
// Each action function has a commented fetch() call — uncomment and remove mock logic
// Also add JWT token to headers:
const token = localStorage.getItem('scamwatch_token');
headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
```

**Admin login modal (introduction.html)**
```javascript
// Replace the fake credential check with:
const res = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: user + '@scamwatch.sg', password: pass })
});
const data = await res.json();
if (res.ok) {
    localStorage.setItem('scamwatch_token', data.token);
    window.location.href = 'admindashboard.html';
}
```

---

## Default admin credentials (seeded)
| Name | Email | Password | Role |
|------|-------|----------|------|
| Admin | admin@scamwatch.sg | admin123 | super_admin |
| Sarah Tan | sarah.t@scamwatch.sg | sarah123 | moderator |
| Marcus Lim | m.lim@scamwatch.sg | marcus123 | analyst |
