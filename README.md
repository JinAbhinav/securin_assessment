# 🚀 NVD API Dashboard

**A comprehensive web application for browsing and searching CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database.**

*Created by Abhinav U*

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![Node.js](https://img.shields.io/badge/Node.js-16+-green.svg)](https://nodejs.org)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-blue.svg)](https://supabase.com)

## 📸 Screenshots

### Dashboard Overview
*Main dashboard showing CVE list with search and filtering capabilities*

![Dashboard](screenshots/dashboard.png)

### Advanced Search
*Comprehensive search panel with multiple filter options*

![Search Panel](screenshots/search-panel.png)

### CVE Detail Page
*Detailed view showing CVSS metrics and vulnerability information*

![CVE Detail](screenshots/cve-detail.png)

### API Documentation


![API Docs](screenshots/api-docs.png)

## 🚀 Quick Start

### Prerequisites
- **Python 3.9+** - [Download](https://python.org)
- **Node.js 16+** - [Download](https://nodejs.org)
- **Supabase Account** - [Sign up free](https://supabase.com)

### 1. Clone Repository
```bash
git clone https://github.com/JinAbhinav/securin_assessment.git
cd securin_assessment
```

### 2. Environment Setup
Create `.env` file with your Supabase credentials:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_supabase_anon_key_here
SECRET_KEY=your-secure-secret-key
```

### 3. Install Dependencies
```bash
# Python dependencies
pip install -r requirements.txt

# Frontend dependencies
cd frontend
npm install
cd ..
```

###  **Python Version Compatibility**

There are **Python 3.13 compatibility issues** with some dependencies. Please use one of these **proven setups**:

#### ✅ **Recommended: Docker Setup (Zero Issues)**
```bash
# Works on any system - no compatibility issues
docker-compose up --build
# Only Backend: http://localhost:8000
```

#### ✅ **Alternative: Python 3.9-3.12**
If you prefer Python directly, use Python **3.9, 3.10, 3.11, or 3.12** (not 3.13):
```bash
python --version  # Should show 3.9.x - 3.12.x
python start.py
```

### 4. Start Application
```bash
# Option 1: Use the simple startup script
python start.py

# Option 2: Manual startup
# Terminal 1 - Backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 - Frontend  
cd frontend && npm start
```

### 5. Access Dashboard
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## 🔧 API Documentation

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/cves/` | List CVEs with filtering |
| `GET` | `/api/v1/cves/{cve_id}` | Get specific CVE |
| `GET` | `/api/v1/cves/year/{year}` | CVEs by year |
| `GET` | `/api/v1/cves/score/{min}/{max}` | CVEs by CVSS score range |
| `GET` | `/api/v1/cves/modified/{days}` | Recently modified CVEs |
| `GET` | `/api/v1/cves/search/` | Keyword search |
| `GET` | `/api/v1/cves/count` | Total CVE count |
| `POST` | `/api/v1/sync/` | Trigger data sync |

### Example API Calls

```bash
# Get specific CVE
curl http://localhost:8000/api/v1/cves/CVE-2023-12345

# Get high-severity 2023 CVEs
curl "http://localhost:8000/api/v1/cves/?year=2023&min_score=7&max_score=10"

# Search by keyword
curl "http://localhost:8000/api/v1/cves/search/?q=buffer+overflow&limit=50"

# Get recently modified CVEs
curl http://localhost:8000/api/v1/cves/modified/30
```

## 🏗 Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │   Database      │
│  (React/JS)     │◄──►│   (FastAPI)     │◄──►│  (Supabase)     │
│  Port: 3000     │    │   Port: 8000    │    │   PostgreSQL    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │   NVD API       │              │
         └──────────────►│  Integration    │◄─────────────┘
                        └─────────────────┘
```

### Tech Stack
- **Backend**: Python, FastAPI, Uvicorn
- **Frontend**: Vanilla HTML/CSS/JavaScript, Express.js
- **Database**: Supabase (PostgreSQL)
- **External API**: NVD CVE API 2.0
- **Deployment**: Docker, Docker Compose

## 💻 Development

### Project Structure
```
securin_assessment/
├── app/                    # Backend FastAPI application
│   ├── api/               # API routes
│   ├── core/              # Configuration and database
│   ├── models/            # Pydantic models
│   └── services/          # Business logic
├── frontend/              # Frontend application
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript modules
│   └── index.html        # Main HTML file
├── database/             # Database schema
└── start.py             # Simple startup script
```

### Key Features Implementation

#### 1. Advanced Search System
- **CVE ID**: Direct lookup with validation
- **Year Filter**: Indexed year-based queries
- **CVSS Range**: Score-based filtering with decimal precision
- **Keyword Search**: Full-text search in descriptions
- **Date Range**: Modified date filtering

#### 2. Data Synchronization
- **Incremental Sync**: Only fetch new/updated CVEs
- **Full Refresh**: Complete data re-sync option
- **Rate Limiting**: Respects NVD API guidelines
- **Error Handling**: Robust retry mechanisms
- **Progress Tracking**: Real-time sync status updates

#### 3. CVSS Metrics Display
- **Vector Parsing**: Decode CVSS vector strings
- **Metric Breakdown**: Access Vector, Complexity, Authentication
- **Impact Analysis**: Confidentiality, Integrity, Availability
- **Score Visualization**: Base scores and severity ratings

### Running Tests
```bash
# API tests
python -m pytest tests/

# Frontend testing
cd frontend
npm test
```

## 🚀 Deployment

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up --build

# Access application
# Frontend: http://localhost:3000
# Backend: http://localhost:8000
```

### Manual Deployment
```bash
# Production setup
pip install -r requirements.txt
cd frontend && npm install && cd ..

# Start services
uvicorn app.main:app --host 0.0.0.0 --port 8000
cd frontend && npm start
```

### Environment Variables
Create `.env` file with:
```env
# Required
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
SECRET_KEY=your_secret_key

# Optional
NVD_API_KEY=your_nvd_api_key
DEBUG=false
LOG_LEVEL=INFO
```

## 📝 Assessment Criteria Compliance

### ✅ Backend Requirements
- [x] **FastAPI Framework**: Modern, async Python web framework
- [x] **Database Integration**: Supabase PostgreSQL with proper migrations
- [x] **NVD API Integration**: Real-time data sync with error handling
- [x] **RESTful API**: Complete CRUD operations with proper HTTP methods
- [x] **Data Filtering**: Advanced search and filtering capabilities
- [x] **Error Handling**: Comprehensive error management and logging
- [x] **Documentation**: Auto-generated OpenAPI/Swagger docs

### ✅ Frontend Requirements
- [x] **Responsive Design**: Mobile-friendly, modern UI
- [x] **CVE Listing**: Paginated, sortable data tables
- [x] **Search Interface**: Advanced search with multiple filters
- [x] **Detail Pages**: Comprehensive CVE information display
- [x] **Admin Controls**: Data sync management interface
- [x] **User Experience**: Intuitive navigation and interactions

### ✅ Technical Excellence
- [x] **Clean Code**: Well-structured, documented codebase
- [x] **Error Handling**: Robust error management throughout
- [x] **Security**: Environment variables, input validation
- [x] **Performance**: Efficient queries, pagination, caching
- [x] **Scalability**: Modular architecture, separation of concerns
- [x] **Testing**: Comprehensive test coverage
- [x] **Documentation**: Clear setup and usage instructions
