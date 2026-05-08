<div align="center">

<img src="https://img.shields.io/badge/version-1.0.0-00d4ff?style=for-the-badge&logo=shield&logoColor=white" />
<img src="https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
<img src="https://img.shields.io/badge/Streamlit-1.35-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" />
<img src="https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
<img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" />

<br /><br />

```
███████╗ ██████╗  ██████╗    ██╗      ██████╗  ██████╗
██╔════╝██╔═══██╗██╔════╝    ██║     ██╔═══██╗██╔════╝
███████╗██║   ██║██║         ██║     ██║   ██║██║  ███╗
╚════██║██║   ██║██║         ██║     ██║   ██║██║   ██║
███████║╚██████╔╝╚██████╗    ███████╗╚██████╔╝╚██████╔╝
╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝ ╚═════╝  ╚═════╝
         A N A L Y Z E R
```

### **AI-Powered Security Operations Center — Log Intelligence Platform**

*Parse. Detect. Visualize. Respond.*

<br />

[🚀 Quick Start](#-quick-start) · [📐 Architecture](#-architecture) · [🔍 Detection Engine](#-detection-engine) · [📊 Dashboard](#-dashboard) · [🌐 API Reference](#-api-reference) · [⚙️ Configuration](#%EF%B8%8F-configuration)

</div>

---

## 📌 Overview

**SOC Log Analyzer** is a production-grade, full-stack cybersecurity tool that transforms raw server logs into actionable threat intelligence. It combines deterministic rule-based detection with unsupervised machine learning to surface brute-force attacks, DDoS patterns, suspicious HTTP behavior, and zero-day behavioral anomalies — all surfaced through a real-time analyst dashboard.

The system is designed as a **lightweight, transparent alternative to commercial SIEM platforms** (Splunk, IBM QRadar, Microsoft Sentinel), suitable for academic environments, small-to-medium organizations, and security research.

```
Raw Logs  ──►  Parser  ──►  Detection Engine  ──►  Risk Scorer  ──►  Dashboard
               (3 formats)  (Rules + ML)          (0–100 score)      (Streamlit)
```

### Why This Project Exists

> Commercial SIEM tools cost thousands of dollars per month and obscure their detection logic. Security engineers deserve to understand and control their own threat detection. This tool is open, auditable, and built to teach.

---

## 🎯 Core Capabilities

| Capability | Description |
|---|---|
| **Multi-Format Log Parsing** | Apache Combined Log, OpenSSH auth.log, RFC 3164 syslog — auto-detected |
| **Rule-Based Detection** | 5 deterministic detectors with sliding time-window analysis |
| **ML Anomaly Detection** | Isolation Forest on 7-dimensional per-IP behavioral feature vectors |
| **Risk Scoring** | Quantitative 0–100 score + qualitative LOW / MEDIUM / HIGH severity bands |
| **SOC Dashboard** | 5-page Streamlit UI with Plotly charts, alert triage, and live log streaming |
| **GeoIP Enrichment** | Country/city/ISP lookup via ip-api.com with LRU caching |
| **REST API** | 12 documented FastAPI endpoints with OpenAPI/Swagger UI |
| **Export** | CSV and PDF report generation for incident documentation |
| **Real-Time Streaming** | Server-Sent Events (SSE) endpoint for live log replay |

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SOC LOG ANALYZER                                   │
├──────────────────────────────┬──────────────────────────────────────────────┤
│     STREAMLIT DASHBOARD      │              FASTAPI BACKEND                 │
│                              │                                              │
│  ┌────────────────────────┐  │   ┌──────────────────────────────────────┐  │
│  │  📊 Dashboard          │  │   │           API LAYER                  │  │
│  │  🚨 Alert Management   │◄─┼──►│  POST /logs/upload                   │  │
│  │  📋 Log Explorer       │  │   │  GET  /logs/stats                    │  │
│  │  📤 Upload Center      │  │   │  GET  /logs/stream  (SSE)            │  │
│  │  📈 Reports & Export   │  │   │  GET  /alerts/                       │  │
│  └────────────────────────┘  │   │  GET  /alerts/summary                │  │
│                              │   │  PATCH /alerts/{id}/resolve          │  │
│                              │   │  GET  /reports/alerts/csv|pdf        │  │
│                              │   └─────────────┬────────────────────────┘  │
│                              │                 │                            │
│                              │   ┌─────────────▼────────────────────────┐  │
│                              │   │         PARSER LAYER                 │  │
│                              │   │                                      │  │
│                              │   │  ┌──────────┐ ┌────────┐ ┌───────┐  │  │
│                              │   │  │  Apache  │ │  SSH   │ │Syslog │  │  │
│                              │   │  │  Parser  │ │ Parser │ │Parser │  │  │
│                              │   │  └──────────┘ └────────┘ └───────┘  │  │
│                              │   │         Auto-Detection               │  │
│                              │   │         Normalizer + GeoIP           │  │
│                              │   └─────────────┬────────────────────────┘  │
│                              │                 │                            │
│                              │   ┌─────────────▼────────────────────────┐  │
│                              │   │       DETECTION ENGINE               │  │
│                              │   │                                      │  │
│                              │   │  RULE ENGINE          ML ENGINE      │  │
│                              │   │  ┌──────────────┐  ┌──────────────┐ │  │
│                              │   │  │ Brute-Force  │  │  Isolation   │ │  │
│                              │   │  │ DDoS Detect  │  │   Forest     │ │  │
│                              │   │  │ Status Spike │  │ (7-feature   │ │  │
│                              │   │  │ Susp. Paths  │  │  IP vectors) │ │  │
│                              │   │  │ Syslog Anom. │  └──────────────┘ │  │
│                              │   │  └──────────────┘                   │  │
│                              │   │         Risk Scorer (0–100)         │  │
│                              │   └─────────────┬────────────────────────┘  │
│                              │                 │                            │
│                              │   ┌─────────────▼────────────────────────┐  │
│                              │   │      PERSISTENCE LAYER               │  │
│                              │   │   SQLite  ·  SQLAlchemy ORM          │  │
│                              │   │   log_entries  ·  alerts             │  │
│                              │   └──────────────────────────────────────┘  │
└──────────────────────────────┴──────────────────────────────────────────────┘
```

### Folder Structure

```
soc-log-analyzer/
│
├── backend/                          # Python FastAPI application
│   ├── main.py                       # App entry point, CORS, startup lifecycle
│   ├── config.py                     # All thresholds, constants, env overrides
│   ├── database.py                   # SQLAlchemy models: LogEntry, Alert
│   │
│   ├── parser/
│   │   ├── log_parser.py             # Apache / SSH / syslog regex parsers
│   │   └── normalizer.py             # ORM conversion + GeoIP enrichment
│   │
│   ├── detection/
│   │   ├── rule_engine.py            # 5 rule-based threat detectors
│   │   ├── ml_engine.py              # Isolation Forest anomaly detection
│   │   └── risk_scorer.py            # Score normalization + alert persistence
│   │
│   ├── api/
│   │   ├── routes_logs.py            # /logs/* endpoints (upload, list, stats, stream)
│   │   ├── routes_alerts.py          # /alerts/* endpoints (CRUD, resolve, summary)
│   │   └── routes_reports.py         # /reports/* (CSV and PDF export)
│   │
│   └── utils/
│       ├── geoip.py                  # ip-api.com lookup with LRU cache
│       └── logger.py                 # Structured logging with consistent format
│
├── frontend/
│   └── dashboard.py                  # Streamlit SOC dashboard (5 pages)
│
├── data/
│   ├── sample_apache.log             # Apache access log with attack patterns
│   ├── sample_ssh.log                # SSH auth log with brute-force sequences
│   └── sample_syslog.log             # Syslog with privilege escalation events
│
├── reports/                          # Generated CSV / PDF exports (auto-created)
├── soc_alerts.db                     # SQLite database (auto-created on first run)
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | ≥ 3.11 | 3.12 recommended |
| pip | ≥ 23.0 | Comes with Python |
| Git | Any | For cloning |

### 1 · Clone the Repository

```bash
git clone https://github.com/your-org/soc-log-analyzer.git
cd soc-log-analyzer
```

### 2 · Create a Virtual Environment

```bash
# macOS / Linux
python -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3 · Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `reportlab` is required for PDF export. If you only need CSV, it can be omitted — the report endpoint gracefully falls back to a `.txt` file.

### 4 · Start the Backend API

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

On startup you will see:

```
INFO  backend.main: SOC Log Analyzer API started. DB initialised.
INFO  Uvicorn running on http://0.0.0.0:8000
```

Visit **[http://localhost:8000/docs](http://localhost:8000/docs)** for the interactive Swagger UI.

### 5 · Start the Dashboard

Open a second terminal (with the virtual environment activated):

```bash
streamlit run frontend/dashboard.py
```

Visit **[http://localhost:8501](http://localhost:8501)** for the SOC dashboard.

### 6 · Load Sample Data

**Via the Dashboard:**
Navigate to **📤 Upload Logs** and click one of the three sample dataset buttons:
- 🌐 Apache Logs
- 🔑 SSH Logs
- ⚙️ Syslog

**Via cURL:**
```bash
# Upload Apache log
curl -X POST "http://localhost:8000/logs/upload" \
  -F "file=@data/sample_apache.log" \
  -F "log_type=apache"

# Upload SSH log
curl -X POST "http://localhost:8000/logs/upload" \
  -F "file=@data/sample_ssh.log" \
  -F "log_type=ssh"

# Upload Syslog
curl -X POST "http://localhost:8000/logs/upload" \
  -F "file=@data/sample_syslog.log" \
  -F "log_type=syslog"
```

**Expected output for sample Apache log:**
```json
{
  "filename": "sample_apache.log",
  "log_type": "apache",
  "lines_parsed": 38,
  "entries_saved": 38,
  "alerts_generated": 9,
  "alert_summary": {
    "HIGH": 5,
    "MEDIUM": 4,
    "LOW": 0
  }
}
```

---

## 🔍 Detection Engine

### Rule-Based Detectors

All rule-based detectors use a **sliding time-window** algorithm. For each unique source IP, events are sorted chronologically and a window of fixed duration is advanced through the timeline. If the event count within any window meets or exceeds the threshold, an alert is generated.

#### Brute-Force Login Detection

Monitors for rapid sequences of authentication failures from a single IP, covering both SSH (`Failed password`, `Invalid user`) and HTTP (`POST /login` returning `401`).

| Parameter | Default | Description |
|---|---|---|
| `BRUTE_FORCE_THRESHOLD` | `5` | Minimum failed logins to trigger |
| `BRUTE_FORCE_WINDOW_SECS` | `60` | Rolling time window in seconds |
| Base Risk Score | `70 + (count × 2)` | Capped at 100 |

**Example trigger:**
```
10.0.0.45 - [13:55:40] "POST /login" 401
10.0.0.45 - [13:55:41] "POST /login" 401
10.0.0.45 - [13:55:42] "POST /login" 401   ← 3
10.0.0.45 - [13:55:43] "POST /login" 401
10.0.0.45 - [13:55:44] "POST /login" 401   ← 5  →  BRUTE_FORCE HIGH (score: 80)
```

---

#### DDoS / Flood Detection

Detects abnormally high HTTP request rates from a single source within a very short window, indicating automated flood attacks.

| Parameter | Default | Description |
|---|---|---|
| `DDOS_THRESHOLD` | `10` | Requests per window to trigger |
| `DDOS_WINDOW_SECS` | `2` | Rolling time window in seconds |
| Base Risk Score | `60 + (count × 3)` | Capped at 100 |

---

#### HTTP Status Code Spike

Identifies IPs generating repeated 4xx or 5xx error responses, indicative of directory traversal scans, credential stuffing, or misconfigured attack tools.

| Parameter | Default | Description |
|---|---|---|
| `STATUS_SPIKE_THRESHOLD` | `5` | Same status code per window |
| `STATUS_SPIKE_WINDOW_SECS` | `60` | Rolling time window in seconds |
| Base Risk Score | `50 + (count × 5)` | Capped at 100 |

---

#### Suspicious Request Path Detection

Scans every HTTP request URI against a library of known-dangerous patterns. Matches are alerted immediately (no windowing required).

```
Detected Patterns
─────────────────
.env             → Exposed environment file probe
wp-admin         → WordPress admin panel scan
phpmyadmin       → Database admin interface probe
/.git/           → Source code repository exposure
/etc/passwd      → Unix credential file traversal
/etc/shadow      → Shadow password file traversal
UNION SELECT     → SQL injection attempt
<script>         → Cross-site scripting (XSS) payload
eval(            → Remote code execution attempt
/bin/bash        → Shell injection attempt
cmd.exe          → Windows shell injection
```

---

#### Syslog Anomaly Detection

Parses system logs for high-risk OS-level events that indicate post-compromise activity or insider threats.

| Syslog Action | Risk Score | Threat Description |
|---|---|---|
| `USER_CREATED` | 85 (+15 if UID=0) | New privileged account creation |
| `SUSPICIOUS_CRON` | 80 | Cron executing from `/tmp` (malware persistence) |
| `DANGEROUS_SUDO` | 75 | `sudo` running `/etc/shadow`, `chmod 777 /etc/passwd` |
| `PASSWORD_CHANGE` | 60 | Unexpected credential modification |
| `OOM_KILL` | 50 | Memory exhaustion, possible resource abuse |

---

### Machine Learning Detection — Isolation Forest

Rule-based systems detect *known* attack signatures. The ML engine detects *unknown* behavioral anomalies — IPs acting in ways that are statistically unusual compared to all other IPs, even if they don't match any explicit rule.

#### Algorithm

The [Isolation Forest](https://ieeexplore.ieee.org/document/4781136) (Liu et al., 2008) is an unsupervised ensemble method that isolates observations by randomly selecting a feature and a split value. Anomalies require fewer splits to isolate (shorter path lengths in trees), yielding a high anomaly score.

#### Feature Vector (7 dimensions per IP)

For each unique source IP, behavioral features are extracted over a 5-minute rolling window:

```
Feature               Type        Description
──────────────────────────────────────────────────────────────────────
request_count         Integer     Total events from this IP
error_4xx_count       Integer     Client error responses (HTTP 4xx)
error_5xx_count       Integer     Server error responses (HTTP 5xx)
unique_paths          Integer     Distinct URI paths accessed
failed_logins         Integer     SSH + HTTP 401 authentication failures
bytes_sent_mean       Float       Mean payload size in bytes
time_spread_secs      Float       Seconds between first and last event
```

#### Model Configuration

```python
IsolationForest(
    contamination = 0.1,    # 10% of IPs expected to be anomalous
    n_estimators  = 100,    # 100 isolation trees
    random_state  = 42,     # Reproducible results
)
```

#### Score Mapping

The raw `decision_function()` output (range ≈ `[-0.5, +0.5]`) is linearly mapped to a `[0, 100]` risk scale:

```
risk_score = (0.5 - raw_score) × 100

  raw_score = -0.5  →  risk = 100  (extreme anomaly)
  raw_score =  0.0  →  risk =  50  (borderline)
  raw_score = +0.5  →  risk =   0  (highly normal)
```

---

### Risk Scoring Summary

```
Risk Score   Severity   Color    Typical Triggers
──────────────────────────────────────────────────────────────────────
  0 – 33     LOW        🟢       Single suspicious request, low-rate probe
 34 – 66     MEDIUM     🟡       Status spike, suspicious path scan, ML outlier
 67 – 100    HIGH       🔴       Brute-force burst, DDoS flood, UID=0 creation
```

---

## 📊 Dashboard

The Streamlit dashboard provides a 5-page analyst interface:

### Page 1 · 📊 Dashboard — Overview

The primary SOC command view, loading automatically with:

- **KPI Row:** Total logs ingested · Total alerts · HIGH / MEDIUM / LOW counts
- **Alerts by Type** — horizontal bar chart, color-scaled by count
- **Top Source IPs** — horizontal bar chart, highlights heavy hitters
- **HTTP Status Distribution** — donut chart, color-coded by status class
- **Detection Engine Split** — donut chart, Rule vs. ML engine attribution
- **Recent Alerts** — live feed of the 5 most recent alerts with inline severity badges

### Page 2 · 🚨 Alerts — Triage Interface

Full alert management panel with:

- Filterable by **Severity**, **Resolution Status**, and **Source IP**
- Expandable alert cards showing: risk score, detection engine, country, full description
- One-click **Resolve** button per alert

### Page 3 · 📋 Log Explorer

Paginated, filterable log entry viewer:

- Filter by **Log Type** (apache / ssh / syslog) and **Source IP**
- Sortable data table with color-coded HTTP status column
- **Log Timeline** chart: requests-per-minute grouped by log type

### Page 4 · 📤 Upload Logs

Log ingestion interface:

- Drag-and-drop file upload (`.log`, `.txt`)
- Manual log type selection or **Auto-detect**
- Toggle for **GeoIP Enrichment**
- One-click **sample dataset loaders** (Apache / SSH / Syslog)
- Post-analysis summary with parsed lines, saved entries, and alert breakdown

### Page 5 · 📈 Reports & Export

Export and API reference page:

- Download Alerts as **CSV** or **PDF**
- Download Log Entries as **CSV**
- Full REST API endpoint reference table
- **Live Log Stream Preview** — replays the last 50 log entries via SSE

---

## 🌐 API Reference

The FastAPI backend auto-generates an OpenAPI specification. Visit **`/docs`** for the interactive Swagger UI or **`/redoc`** for ReDoc documentation.

### Logs

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/logs/upload` | Upload a log file for parsing and detection |
| `GET` | `/logs/` | List log entries (paginated, filterable) |
| `GET` | `/logs/stats` | Aggregate statistics: top IPs, status distribution, type breakdown |
| `GET` | `/logs/stream` | Server-Sent Events stream of recent log entries |

**Upload Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `file` | `UploadFile` | required | Log file (`.log`, `.txt`) |
| `log_type` | `string` | auto-detect | `apache` \| `ssh` \| `syslog` |
| `enrich_geo` | `bool` | `false` | Enable GeoIP enrichment |

### Alerts

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/alerts/` | List all alerts with optional filters |
| `GET` | `/alerts/summary` | Counts by severity, type, and engine |
| `GET` | `/alerts/{id}` | Get a single alert by ID |
| `PATCH` | `/alerts/{id}/resolve` | Mark an alert as resolved |
| `DELETE` | `/alerts/{id}` | Delete an alert |

**Alert List Filters:**

| Parameter | Type | Description |
|---|---|---|
| `severity` | `string` | `HIGH` \| `MEDIUM` \| `LOW` |
| `resolved` | `bool` | `true` \| `false` |
| `source_ip` | `string` | Exact IP address match |
| `limit` | `int` | Max results (default: 100, max: 500) |
| `offset` | `int` | Pagination offset |

### Reports

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/reports/alerts/csv` | Stream all alerts as a downloadable CSV |
| `GET` | `/reports/alerts/pdf` | Generate and return a PDF alert report |
| `GET` | `/reports/logs/csv` | Stream last 5,000 log entries as CSV |

### Health

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health check |
| `GET` | `/` | Root — returns service info and doc links |

---

## ⚙️ Configuration

All detection thresholds and system settings are centralized in `backend/config.py`. Every value can be overridden via environment variables.

### Detection Thresholds

```python
# Brute-Force
BRUTE_FORCE_THRESHOLD    = 5     # failed logins from same IP within window
BRUTE_FORCE_WINDOW_SECS  = 60    # rolling window in seconds

# DDoS
DDOS_THRESHOLD           = 10    # HTTP requests from same IP within window
DDOS_WINDOW_SECS         = 2     # rolling window in seconds

# Status Code Spike
STATUS_SPIKE_THRESHOLD   = 5     # same 4xx/5xx code from IP within window
STATUS_SPIKE_WINDOW_SECS = 60    # rolling window in seconds

# ML Engine
ISOLATION_FOREST_CONTAMINATION = 0.1   # fraction of IPs expected to be anomalous
ML_FEATURE_WINDOW_SECS         = 300   # 5-minute feature aggregation window
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./soc_alerts.db` | Any SQLAlchemy-compatible connection string |
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API port |
| `API_RELOAD` | `true` | Enable auto-reload in development |
| `REPORTS_DIR` | `./reports` | Output directory for exported reports |

### Example: Production `.env`

```env
DATABASE_URL=sqlite:///./prod_soc.db
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=false
REPORTS_DIR=/var/soc/reports
BRUTE_FORCE_THRESHOLD=3
DDOS_THRESHOLD=20
```

---

## 🗄️ Database Schema

### `log_entries`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment primary key |
| `timestamp` | DATETIME | Log event timestamp (indexed) |
| `source_ip` | VARCHAR(45) | IPv4 or IPv6 source address (indexed) |
| `action` | VARCHAR(16) | HTTP method or event action |
| `path` | TEXT | Request URI or log message |
| `status` | INTEGER | HTTP status code or synthetic status |
| `bytes_sent` | INTEGER | Response size in bytes |
| `log_type` | VARCHAR(16) | `apache` \| `ssh` \| `syslog` |
| `raw` | TEXT | Original unparsed log line |
| `country` | VARCHAR(64) | GeoIP country (nullable) |
| `city` | VARCHAR(64) | GeoIP city (nullable) |
| `created_at` | DATETIME | Record creation timestamp |

### `alerts`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment primary key |
| `timestamp` | DATETIME | Alert generation timestamp (indexed) |
| `source_ip` | VARCHAR(45) | Offending IP address (indexed) |
| `alert_type` | VARCHAR(64) | `BRUTE_FORCE`, `DDOS_SUSPECT`, `ML_ANOMALY`… |
| `description` | TEXT | Human-readable alert detail |
| `severity` | VARCHAR(8) | `LOW` \| `MEDIUM` \| `HIGH` |
| `risk_score` | FLOAT | Numeric score 0.0 – 100.0 |
| `engine` | VARCHAR(8) | `RULE` \| `ML` |
| `resolved` | BOOLEAN | Analyst resolution status |
| `country` | VARCHAR(64) | GeoIP country (nullable) |
| `created_at` | DATETIME | Record creation timestamp |

---

## 📦 Technology Stack

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **API Framework** | FastAPI | 0.111.0 | Async REST API, auto-generated OpenAPI docs |
| **ASGI Server** | Uvicorn | 0.29.0 | Production ASGI server with hot-reload |
| **ORM** | SQLAlchemy | 2.0.30 | Database abstraction, schema management |
| **Database** | SQLite | (stdlib) | Zero-config embedded relational database |
| **ML** | scikit-learn | 1.4.2 | Isolation Forest anomaly detection |
| **Numerics** | NumPy | 1.26.4 | Feature matrix operations |
| **Data** | Pandas | 2.2.2 | Log aggregation and timeline analysis |
| **Dashboard** | Streamlit | 1.35.0 | Interactive SOC analyst interface |
| **Charts** | Plotly | 5.22.0 | Dark-themed interactive visualizations |
| **HTTP Client** | Requests | 2.32.2 | Dashboard → API communication |
| **PDF Export** | ReportLab | 4.2.0 | Professional PDF report generation |
| **GeoIP** | ip-api.com | (free) | Country/city/ISP enrichment |

---

## 🧪 Running Tests

```bash
# Install test dependencies
pip install pytest httpx

# Run all tests
pytest tests/ -v

# Run with coverage report
pip install pytest-cov
pytest tests/ --cov=backend --cov-report=term-missing
```

---

## 🔒 Security Considerations

- **GeoIP data** is fetched over HTTP from ip-api.com. In air-gapped environments, disable GeoIP enrichment (`enrich_geo=false`) or substitute a local MaxMind GeoLite2 database.
- **CORS** is configured to allow all origins (`"*"`) for development convenience. In production, restrict this to the specific dashboard origin in `backend/main.py`.
- **SQLite** is suitable for single-node deployments processing up to tens of millions of log entries. For high-throughput production use, migrate to **PostgreSQL** by changing `DATABASE_URL`.
- **API authentication** is not included by default. Add OAuth2 / API key middleware via FastAPI's dependency injection system before exposing the API to untrusted networks.

---

## 🗺️ Roadmap

- [ ] **PostgreSQL / MySQL support** — swap connection string, zero code changes
- [ ] **MITRE ATT&CK mapping** — tag each alert with the corresponding technique ID
- [ ] **Webhook alerting** — Slack / PagerDuty / Teams notifications on HIGH alerts
- [ ] **Log rotation ingestion** — watch a directory and auto-ingest rotated log files
- [ ] **CIDR / ASN blocking** — one-click firewall rule generation from alert IPs
- [ ] **Transformer-based log embedding** — replace regex parsers with an LLM log tokenizer
- [ ] **Docker Compose** — containerized one-command deployment
- [ ] **Grafana integration** — expose Prometheus metrics endpoint

---

## 📜 License

```
MIT License

Copyright (c) 2025 SOC Log Analyzer Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgements

- [Isolation Forest — Liu, Ting & Zhou (2008)](https://ieeexplore.ieee.org/document/4781136) — the ML algorithm powering anomaly detection
- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) — benchmark intrusion detection dataset
- [MITRE ATT&CK Framework](https://attack.mitre.org/) — threat taxonomy reference
- [OWASP Top Ten](https://owasp.org/Top10/) — suspicious path pattern library
- [FastAPI](https://fastapi.tiangolo.com/) · [Streamlit](https://streamlit.io/) · [scikit-learn](https://scikit-learn.org/) — the open-source stack that made this possible

---

<div align="center">

**Built for security engineers who believe in open, auditable threat detection.**

⭐ Star this repository if it helped you · 🐛 [Report a Bug](../../issues) · 💡 [Request a Feature](../../issues)

</div>
