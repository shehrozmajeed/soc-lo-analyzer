"""
config.py - Central configuration for SOC Log Analyzer
"""
import os

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./soc_alerts.db")

# ── Detection Thresholds ──────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 5    # failed logins from same IP in window
BRUTE_FORCE_WINDOW_SECS = 60   # rolling window in seconds

DDOS_THRESHOLD          = 10   # requests from same IP in window
DDOS_WINDOW_SECS        = 2    # rolling window in seconds

STATUS_SPIKE_THRESHOLD  = 5    # same 4xx/5xx code from IP in window
STATUS_SPIKE_WINDOW_SECS = 60

PORT_SCAN_THRESHOLD     = 5    # distinct ports from same IP in window
PORT_SCAN_WINDOW_SECS   = 30

# ── ML Engine ─────────────────────────────────────────────────────────────────
ISOLATION_FOREST_CONTAMINATION = 0.1   # expected fraction of anomalies
ML_FEATURE_WINDOW_SECS         = 300   # 5-minute aggregation window

# ── Risk Score Bands ──────────────────────────────────────────────────────────
RISK_LOW    = (0, 33)
RISK_MEDIUM = (34, 66)
RISK_HIGH   = (67, 100)

# ── API ───────────────────────────────────────────────────────────────────────
API_HOST    = os.getenv("API_HOST", "0.0.0.0")
API_PORT    = int(os.getenv("API_PORT", 8000))
API_RELOAD  = os.getenv("API_RELOAD", "true").lower() == "true"

# ── Reports ───────────────────────────────────────────────────────────────────
REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")

# ── Suspicious Patterns ───────────────────────────────────────────────────────
SUSPICIOUS_UA_PATTERNS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "curl/", "wget/", "go-http-client",
    "dirbuster", "hydra", "medusa",
]
SUSPICIOUS_PATH_PATTERNS = [
    ".env", "wp-admin", "phpmyadmin", "/.git/",
    "/etc/passwd", "/etc/shadow", "UNION SELECT",
    "<script>", "alert(", "eval(",
    "/bin/bash", "/bin/sh", "cmd.exe",
]

# ── GeoIP ─────────────────────────────────────────────────────────────────────
# Private ranges that skip GeoIP lookup
PRIVATE_IP_RANGES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1",
]
