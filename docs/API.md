# API Documentation

Base URL: `http://localhost:8000/api/v1`

## Authentication

All endpoints (except register/login) require a Bearer token:
Authorization: Bearer <jwt_token>

### POST /auth/register
Create a new user account.

**Request:**
```json
{ "email": "user@example.com", "password": "securepass123", "full_name": "John Doe" }
```

**Response (201):**
```json
{ "access_token": "eyJ...", "token_type": "bearer", "user": { "id": "uuid", "email": "...", "full_name": "..." } }
```

### POST /auth/login
**Request:** `{ "email": "...", "password": "..." }`
**Response:** Same as register.

### GET /auth/me
Returns current user info.

---

## Projects

### GET /projects
List all projects. Query: `?page=1&limit=20`

### POST /projects
Create project. Body: `{ "name": "My App", "language": "python" }`

### GET /projects/{id}
Get single project with stats.

### PATCH /projects/{id}
Update project fields.

### DELETE /projects/{id}
Delete project and all related data.

---

## Scans

### POST /projects/{id}/scans
Start a scan. Accepts `multipart/form-data` with either:
- `file`: ZIP or .py file upload
- `source_code`: Raw code string

### GET /scans/{id}
Get scan details with vulnerability counts.

### GET /scans/{id}/status
Lightweight polling endpoint.

### GET /projects/{id}/scans
List all scans for a project.

---

## Vulnerabilities

### GET /scans/{id}/vulnerabilities
List vulnerabilities. Query: `?severity=critical&type=sql_injection&page=1&limit=50`

### GET /vulnerabilities/{id}
Full vulnerability details with AI analysis.

### PATCH /vulnerabilities/{id}
Mark false positive: `{ "is_false_positive": true, "false_positive_reason": "..." }`

### POST /vulnerabilities/{id}/regenerate-fix
Re-run AI to generate a new fix.

---

## Reports

### POST /scans/{id}/reports
Generate PDF report: `{ "report_type": "pdf" }`

### GET /reports/{id}/download
Download generated PDF.

---

## Analytics

### GET /analytics/risk-trend?project_id=...
Risk score over time.

### GET /analytics/vulnerability-distribution?project_id=...
Vulnerability types in latest scan.

### GET /analytics/summary?project_id=...
Project summary metrics.