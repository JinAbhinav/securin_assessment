# 🔧 NVD API Dashboard - Complete API Documentation

*Created by Abhinav U*

## 📋 Table of Contents

- [Base URL & Authentication](#-base-url--authentication)
- [Response Formats](#-response-formats)
- [Error Handling](#-error-handling)
- [CVE Endpoints](#-cve-endpoints)
- [Sync Endpoints](#-sync-endpoints)
- [Health & Status](#-health--status)
- [Rate Limiting](#-rate-limiting)
- [Code Examples](#-code-examples)

---

## 🌐 Base URL & Authentication

### Base URL
```
http://localhost:8000/api/v1
```

### Authentication
Currently, no authentication is required for API access. All endpoints are publicly accessible.

### Content Type
All requests and responses use `application/json` content type.

---

## 📤 Response Formats

### Standard Success Response
```json
{
  "data": [...],
  "total": 1250,
  "page": 1,
  "size": 20,
  "pages": 63
}
```

### Single Item Response
```json
{
  "cve_id": "CVE-2023-12345",
  "published_date": "2023-08-15T10:30:00Z",
  "last_modified": "2023-08-20T14:45:00Z",
  "description": "A vulnerability description...",
  "cvss_v3_score": 7.5,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cpe_data": [...],
  "references": [...]
}
```

---

## ❌ Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "CVE_NOT_FOUND",
    "message": "CVE with ID CVE-2023-99999 not found",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### HTTP Status Codes
| Code | Description |
|------|-------------|
| `200` | Success |
| `400` | Bad Request - Invalid parameters |
| `404` | Not Found - Resource doesn't exist |
| `422` | Validation Error - Invalid input format |
| `500` | Internal Server Error |
| `503` | Service Unavailable - Database connection issues |

---

## 🔍 CVE Endpoints

### 1. List CVEs with Filtering

**GET** `/cves/`

Get a paginated list of CVEs with optional filtering.

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-based) |
| `size` | integer | 20 | Items per page (max: 100) |
| `year` | integer | - | Filter by publication year |
| `min_score` | float | - | Minimum CVSS score (0.0-10.0) |
| `max_score` | float | - | Maximum CVSS score (0.0-10.0) |
| `sort` | string | "published_date" | Sort field |
| `order` | string | "desc" | Sort order (asc/desc) |

#### Example Request
```bash
GET /api/v1/cves/?page=1&size=10&year=2023&min_score=7.0&sort=cvss_v3_score&order=desc
```

#### Example Response
```json
{
  "data": [
    {
      "cve_id": "CVE-2023-45678",
      "published_date": "2023-12-01T08:00:00Z",
      "last_modified": "2023-12-02T10:00:00Z",
      "description": "Critical vulnerability in XYZ software allowing remote code execution...",
      "cvss_v3_score": 9.8,
      "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_v3_severity": "CRITICAL",
      "cvss_v2_score": 10.0,
      "cvss_v2_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
      "cwe_id": "CWE-787",
      "cpe_data": [
        {
          "cpe23Uri": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
          "vulnerable": true
        }
      ],
      "references": [
        {
          "url": "https://vendor.com/security-advisory",
          "source": "vendor"
        }
      ]
    }
  ],
  "total": 150,
  "page": 1,
  "size": 10,
  "pages": 15
}
```

### 2. Get Specific CVE

**GET** `/cves/{cve_id}`

Get detailed information about a specific CVE.

#### Path Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `cve_id` | string | CVE identifier (e.g., CVE-2023-12345) |

#### Example Request
```bash
GET /api/v1/cves/CVE-2023-12345
```

#### Example Response
```json
{
  "cve_id": "CVE-2023-12345",
  "published_date": "2023-08-15T10:30:00Z",
  "last_modified": "2023-08-20T14:45:00Z",
  "description": "A buffer overflow vulnerability in the ABC library allows...",
  "cvss_v3_score": 7.5,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cvss_v3_severity": "HIGH",
  "cvss_v2_score": 7.5,
  "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
  "cwe_id": "CWE-120",
  "cpe_data": [
    {
      "cpe23Uri": "cpe:2.3:a:abc:library:1.0:*:*:*:*:*:*:*",
      "vulnerable": true,
      "versionStartIncluding": "1.0",
      "versionEndExcluding": "1.2"
    }
  ],
  "references": [
    {
      "url": "https://abc.com/security/advisory-123",
      "source": "vendor",
      "tags": ["Patch", "Vendor Advisory"]
    },
    {
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
      "source": "nvd",
      "tags": ["Third Party Advisory", "US Government Resource"]
    }
  ]
}
```

### 3. Get CVEs by Year

**GET** `/cves/year/{year}`

Get all CVEs published in a specific year.

#### Path Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `year` | integer | Publication year (1999-2025) |

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `size` | integer | 20 | Items per page |

#### Example Request
```bash
GET /api/v1/cves/year/2023?page=1&size=50
```

### 4. Get CVEs by CVSS Score Range

**GET** `/cves/score/{min_score}/{max_score}`

Get CVEs within a specific CVSS score range.

#### Path Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `min_score` | float | Minimum CVSS score (0.0-10.0) |
| `max_score` | float | Maximum CVSS score (0.0-10.0) |

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `size` | integer | 20 | Items per page |

#### Example Request
```bash
GET /api/v1/cves/score/7.0/10.0?page=1&size=25
```

### 5. Get Recently Modified CVEs

**GET** `/cves/modified/{days}`

Get CVEs modified within the last N days.

#### Path Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | integer | Number of days to look back (1-365) |

#### Example Request
```bash
GET /api/v1/cves/modified/30
```

### 6. Search CVEs by Keyword

**GET** `/cves/search/`

Search CVEs by keyword in description.

#### Query Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search keyword/phrase |
| `limit` | integer | No | Maximum results (default: 100) |

#### Example Request
```bash
GET /api/v1/cves/search/?q=buffer%20overflow&limit=50
```

#### Example Response
```json
{
  "data": [
    {
      "cve_id": "CVE-2023-11111",
      "description": "A buffer overflow vulnerability allows...",
      "cvss_v3_score": 8.1,
      "published_date": "2023-10-15T09:00:00Z"
    }
  ],
  "total": 45,
  "query": "buffer overflow",
  "limit": 50
}
```

### 7. Get CVE Count

**GET** `/cves/count`

Get the total number of CVEs in the database.

#### Example Request
```bash
GET /api/v1/cves/count
```

#### Example Response
```json
{
  "total": 8247,
  "last_updated": "2024-01-15T10:30:00Z"
}
```

### 8. Update CVE (Admin)

**PUT** `/cves/{cve_id}`

Update an existing CVE record.

#### Request Body
```json
{
  "description": "Updated description...",
  "cvss_v3_score": 8.5,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
}
```

### 9. Delete CVE (Admin)

**DELETE** `/cves/{cve_id}`

Delete a CVE record from the database.

#### Example Request
```bash
DELETE /api/v1/cves/CVE-2023-12345
```

---

## 🔄 Sync Endpoints

### 1. Trigger Manual Sync

**POST** `/sync/`

Manually trigger CVE data synchronization from NVD.

#### Request Body
```json
{
  "sync_type": "incremental",
  "force": false
}
```

#### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `sync_type` | string | "incremental" or "full" |
| `force` | boolean | Force sync even if one is running |

#### Example Response
```json
{
  "sync_id": "sync_20240115_103045",
  "status": "started",
  "sync_type": "incremental",
  "started_at": "2024-01-15T10:30:45Z",
  "estimated_duration": "5-10 minutes"
}
```

### 2. Get Sync Status

**GET** `/sync/status`

Get the current synchronization status.

#### Example Response
```json
{
  "status": "running",
  "sync_id": "sync_20240115_103045",
  "sync_type": "incremental",
  "started_at": "2024-01-15T10:30:45Z",
  "progress": {
    "processed": 1500,
    "total": 3000,
    "percentage": 50
  },
  "last_completed": "2024-01-14T22:00:00Z"
}
```

### 3. Check if Sync is Running

**GET** `/sync/running`

Check if a synchronization is currently in progress.

#### Example Response
```json
{
  "is_running": true,
  "sync_id": "sync_20240115_103045",
  "started_at": "2024-01-15T10:30:45Z"
}
```

---

## 🏥 Health & Status

### Health Check

**GET** `/health`

Check the overall health of the API and its dependencies.

#### Example Response
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "dependencies": {
    "database": "healthy",
    "nvd_api": "healthy"
  },
  "uptime": "2 days, 5 hours, 30 minutes"
}
```

---

## ⚡ Rate Limiting

### NVD API Compliance
- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds
- Automatic retry with exponential backoff
- Request queuing during high load

### Internal Rate Limits
- **Search endpoints**: 100 requests per minute per IP
- **Sync endpoints**: 1 request per minute per IP
- **Other endpoints**: 1000 requests per minute per IP

---

## 💻 Code Examples

### Python (requests)
```python
import requests

# Base configuration
BASE_URL = "http://localhost:8000/api/v1"
headers = {"Content-Type": "application/json"}

# Get CVEs by year with pagination
response = requests.get(
    f"{BASE_URL}/cves/",
    params={
        "year": 2023,
        "min_score": 7.0,
        "page": 1,
        "size": 20
    }
)
cves = response.json()

# Get specific CVE
cve_response = requests.get(f"{BASE_URL}/cves/CVE-2023-12345")
cve_detail = cve_response.json()

# Search CVEs
search_response = requests.get(
    f"{BASE_URL}/cves/search/",
    params={"q": "buffer overflow", "limit": 50}
)
search_results = search_response.json()

# Trigger sync
sync_response = requests.post(
    f"{BASE_URL}/sync/",
    json={"sync_type": "incremental", "force": False},
    headers=headers
)
sync_status = sync_response.json()
```

### JavaScript (fetch)
```javascript
const BASE_URL = 'http://localhost:8000/api/v1';

// Get CVEs with filtering
async function getCVEs(filters = {}) {
    const params = new URLSearchParams(filters);
    const response = await fetch(`${BASE_URL}/cves/?${params}`);
    return await response.json();
}

// Get specific CVE
async function getCVE(cveId) {
    const response = await fetch(`${BASE_URL}/cves/${cveId}`);
    if (!response.ok) {
        throw new Error(`CVE not found: ${cveId}`);
    }
    return await response.json();
}

// Search CVEs
async function searchCVEs(query, limit = 100) {
    const params = new URLSearchParams({ q: query, limit });
    const response = await fetch(`${BASE_URL}/cves/search/?${params}`);
    return await response.json();
}

// Trigger sync
async function triggerSync(syncType = 'incremental') {
    const response = await fetch(`${BASE_URL}/sync/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sync_type: syncType, force: false })
    });
    return await response.json();
}

// Usage examples
(async () => {
    // Get high-severity 2023 CVEs
    const highSeverityCVEs = await getCVEs({
        year: 2023,
        min_score: 7.0,
        sort: 'cvss_v3_score',
        order: 'desc'
    });

    // Search for buffer overflow vulnerabilities
    const bufferOverflows = await searchCVEs('buffer overflow');

    // Get recently modified CVEs
    const recentCVEs = await fetch(`${BASE_URL}/cves/modified/7`)
        .then(res => res.json());
})();
```

### cURL Examples
```bash
# Get paginated CVE list
curl "http://localhost:8000/api/v1/cves/?page=1&size=10&year=2023"

# Get specific CVE
curl "http://localhost:8000/api/v1/cves/CVE-2023-12345"

# Search CVEs
curl "http://localhost:8000/api/v1/cves/search/?q=buffer%20overflow&limit=50"

# Get CVEs by score range
curl "http://localhost:8000/api/v1/cves/score/7.0/10.0"

# Get recently modified CVEs
curl "http://localhost:8000/api/v1/cves/modified/30"

# Trigger sync
curl -X POST "http://localhost:8000/api/v1/sync/" \
     -H "Content-Type: application/json" \
     -d '{"sync_type": "incremental", "force": false}'

# Check sync status
curl "http://localhost:8000/api/v1/sync/status"

# Health check
curl "http://localhost:8000/health"
```

---

## 📊 OpenAPI/Swagger Documentation

Interactive API documentation is available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## 🔗 Related Resources

- **Frontend Dashboard**: http://localhost:3000
- **GitHub Repository**: https://github.com/JinAbhinav/securin_assessment
- **NVD CVE API**: https://nvd.nist.gov/developers/vulnerabilities
- **CVSS Calculator**: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

---

*Created by Abhinav U - Complete API documentation for NVD Dashboard*
