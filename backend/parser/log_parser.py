"""
parser/log_parser.py - Parse raw log lines into structured LogEntry dicts.

Supported formats
─────────────────
• Apache Combined/Common access log
• OpenSSH auth log (auth.log / secure)
• Generic syslog (RFC 3164)
"""
import re
from datetime import datetime
from typing import Optional
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Regex Patterns ────────────────────────────────────────────────────────────

# Apache Combined Log Format
_APACHE_RE = re.compile(
    r'(?P<ip>\S+)'            # client IP
    r'\s+\S+\s+\S+'          # ident / authuser (ignored)
    r'\s+\[(?P<ts>[^\]]+)\]' # [timestamp]
    r'\s+"(?P<method>\S+)'   # "METHOD
    r'\s+(?P<path>\S+)'      # /path
    r'\s+\S+"'               # HTTP/x.x"
    r'\s+(?P<status>\d{3})'  # status code
    r'\s+(?P<bytes>\S+)'     # bytes sent
    r'(?:\s+"[^"]*")?'       # optional referer
    r'(?:\s+"(?P<ua>[^"]*)")?'  # optional user-agent
)

# SSH log line (OpenSSH syslog output)
_SSH_FAILED_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
    r'.*?(?:Failed password|Invalid user|Connection closed|authentication failure)'
    r'.*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE,
)
_SSH_SUCCESS_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
    r'.*?Accepted (?:password|publickey)'
    r'.*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE,
)

# Generic syslog
_SYSLOG_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
    r'\s+\S+'                            # hostname
    r'\s+(?P<process>[^\[:\s]+)'         # process name
    r'(?:\[\d+\])?'                      # optional PID
    r':\s+(?P<message>.+)',              # message body
)

# IP extractor for syslog messages
_IP_IN_MSG_RE = re.compile(r'(?:SRC=|from\s+|addr=)(\d+\.\d+\.\d+\.\d+)')

_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"
_SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


# ── Public API ────────────────────────────────────────────────────────────────

def parse_line(line: str, log_type: str) -> Optional[dict]:
    """
    Parse a single raw log line.

    Parameters
    ----------
    line     : raw log line (may contain trailing newline)
    log_type : "apache" | "ssh" | "syslog"

    Returns
    -------
    dict with keys:
        timestamp, source_ip, action, path, status,
        bytes_sent, log_type, raw
    or None if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    try:
        if log_type == "apache":
            return _parse_apache(line)
        elif log_type == "ssh":
            return _parse_ssh(line)
        elif log_type == "syslog":
            return _parse_syslog(line)
        else:
            logger.warning("Unknown log_type: %s", log_type)
            return None
    except Exception as exc:
        logger.debug("Parse error [%s]: %s | line: %.80s", log_type, exc, line)
        return None


def detect_log_type(content: str) -> str:
    """
    Heuristically detect log type from a sample of content.

    Returns "apache", "ssh", or "syslog".
    """
    sample = content[:2000]
    if _APACHE_RE.search(sample):
        return "apache"
    if re.search(r"sshd\[\d+\]", sample):
        return "ssh"
    return "syslog"


# ── Private Parsers ───────────────────────────────────────────────────────────

def _parse_apache(line: str) -> Optional[dict]:
    m = _APACHE_RE.match(line)
    if not m:
        return None

    ts = datetime.strptime(m.group("ts"), _APACHE_TS_FMT).replace(tzinfo=None)
    bytes_raw = m.group("bytes")
    bytes_sent = int(bytes_raw) if bytes_raw.isdigit() else 0

    return {
        "timestamp":  ts,
        "source_ip":  m.group("ip"),
        "action":     m.group("method"),
        "path":       m.group("path"),
        "status":     int(m.group("status")),
        "bytes_sent": bytes_sent,
        "log_type":   "apache",
        "raw":        line,
    }


def _parse_ssh(line: str) -> Optional[dict]:
    # Try success first
    m = _SSH_SUCCESS_RE.search(line)
    if m:
        return {
            "timestamp":  _syslog_ts(m),
            "source_ip":  m.group("ip"),
            "action":     "SSH_LOGIN_SUCCESS",
            "path":       None,
            "status":     200,
            "bytes_sent": 0,
            "log_type":   "ssh",
            "raw":        line,
        }

    m = _SSH_FAILED_RE.search(line)
    if m:
        action = "SSH_LOGIN_FAILED"
        if "Invalid user" in line:
            action = "SSH_INVALID_USER"
        elif "Connection closed" in line:
            action = "SSH_CONNECTION_CLOSED"

        return {
            "timestamp":  _syslog_ts(m),
            "source_ip":  m.group("ip"),
            "action":     action,
            "path":       None,
            "status":     401,
            "bytes_sent": 0,
            "log_type":   "ssh",
            "raw":        line,
        }

    return None


def _parse_syslog(line: str) -> Optional[dict]:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None

    msg = m.group("message")
    ip_m = _IP_IN_MSG_RE.search(msg)
    source_ip = ip_m.group(1) if ip_m else "0.0.0.0"

    # Derive action from common keywords
    action = _classify_syslog_action(msg)

    return {
        "timestamp":  _syslog_ts(m),
        "source_ip":  source_ip,
        "action":     action,
        "path":       msg[:256],
        "status":     None,
        "bytes_sent": 0,
        "log_type":   "syslog",
        "raw":        line,
    }


def _syslog_ts(m: re.Match) -> datetime:
    month = _SYSLOG_MONTHS.get(m.group("month"), 1)
    day   = int(m.group("day"))
    time_parts = m.group("time").split(":")
    return datetime(
        datetime.utcnow().year, month, day,
        int(time_parts[0]), int(time_parts[1]), int(time_parts[2]),
    )


def _classify_syslog_action(msg: str) -> str:
    msg_lower = msg.lower()
    if "firewall" in msg_lower or "dropped" in msg_lower:
        return "FIREWALL_DROP"
    if "failed" in msg_lower or "failure" in msg_lower:
        return "AUTH_FAILURE"
    if "sudo" in msg_lower:
        return "SUDO_EXEC"
    if "useradd" in msg_lower or "new user" in msg_lower:
        return "USER_CREATED"
    if "passwd" in msg_lower:
        return "PASSWORD_CHANGE"
    if "cron" in msg_lower:
        return "CRON_JOB"
    if "out of memory" in msg_lower or "oom" in msg_lower:
        return "OOM_KILL"
    return "SYSLOG_EVENT"
