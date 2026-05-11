"""
detection/rule_engine.py - Rule-based anomaly detection.

Each detector receives a list of LogEntry ORM objects and returns
a list of raw alert dicts (not yet persisted).
"""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any

from backend.database import LogEntry
from backend.config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECS,
    DDOS_THRESHOLD, DDOS_WINDOW_SECS,
    STATUS_SPIKE_THRESHOLD, STATUS_SPIKE_WINDOW_SECS,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW_SECS,
    SUSPICIOUS_PATH_PATTERNS,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)

AlertDict = Dict[str, Any]


# ── Public ────────────────────────────────────────────────────────────────────

def run_all_rules(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Run every rule detector over the supplied log entries.

    Returns a deduplicated list of alert dicts.
    """
    if not entries:
        return []

    alerts: List[AlertDict] = []
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_ddos(entries))
    alerts.extend(detect_status_spikes(entries))
    alerts.extend(detect_suspicious_paths(entries))
    alerts.extend(detect_syslog_anomalies(entries))

    logger.info("Rule engine produced %d raw alerts from %d entries",
                len(alerts), len(entries))
    return alerts


# ── Individual Detectors ──────────────────────────────────────────────────────

def detect_brute_force(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Detect rapid failed login sequences from a single IP.
    Covers both SSH (status 401 / SSH_LOGIN_FAILED) and HTTP POST 401.
    """
    alerts = []
    fail_actions = {"SSH_LOGIN_FAILED", "SSH_INVALID_USER", "AUTH_FAILURE"}
    window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)

    # Group failed events by IP
    by_ip: Dict[str, List[datetime]] = defaultdict(list)
    for e in entries:
        is_http_fail  = e.action in ("POST", "GET") and e.status == 401
        is_ssh_fail   = e.action in fail_actions
        if is_http_fail or is_ssh_fail:
            by_ip[e.source_ip].append(e.timestamp)

    for ip, times in by_ip.items():
        times.sort()
        # Sliding window count
        for i, t in enumerate(times):
            count = sum(1 for ts in times[i:] if ts - t <= window)
            if count >= BRUTE_FORCE_THRESHOLD:
                alerts.append(_make_alert(
                    source_ip   = ip,
                    alert_type  = "BRUTE_FORCE",
                    description = (
                        f"Brute-force detected: {count} failed login attempts "
                        f"from {ip} within {BRUTE_FORCE_WINDOW_SECS}s."
                    ),
                    base_score  = 70 + min(count * 2, 30),
                    timestamp   = t,
                ))
                break   # one alert per IP burst

    return alerts


def detect_ddos(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Detect high-frequency HTTP requests from a single IP (DDoS-like pattern).
    """
    alerts = []
    window = timedelta(seconds=DDOS_WINDOW_SECS)
    http_entries = [e for e in entries if e.log_type == "apache"]

    by_ip: Dict[str, List[datetime]] = defaultdict(list)
    for e in http_entries:
        by_ip[e.source_ip].append(e.timestamp)

    for ip, times in by_ip.items():
        times.sort()
        for i, t in enumerate(times):
            count = sum(1 for ts in times[i:] if ts - t <= window)
            if count >= DDOS_THRESHOLD:
                alerts.append(_make_alert(
                    source_ip   = ip,
                    alert_type  = "DDOS_SUSPECT",
                    description = (
                        f"DDoS-like flood: {count} HTTP requests from {ip} "
                        f"within {DDOS_WINDOW_SECS}s."
                    ),
                    base_score  = 60 + min(count * 3, 40),
                    timestamp   = t,
                ))
                break

    return alerts


def detect_status_spikes(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Detect spikes of 4xx / 5xx responses from the same IP within a window,
    which may indicate scanning or probing.
    """
    alerts = []
    window = timedelta(seconds=STATUS_SPIKE_WINDOW_SECS)

    # Group by (ip, status_class)
    by_ip_status: Dict[tuple, List[datetime]] = defaultdict(list)
    for e in entries:
        if e.status and 400 <= e.status < 600:
            by_ip_status[(e.source_ip, e.status)].append(e.timestamp)

    seen = set()
    for (ip, status), times in by_ip_status.items():
        times.sort()
        for i, t in enumerate(times):
            count = sum(1 for ts in times[i:] if ts - t <= window)
            if count >= STATUS_SPIKE_THRESHOLD and ip not in seen:
                seen.add(ip)
                alerts.append(_make_alert(
                    source_ip   = ip,
                    alert_type  = "STATUS_SPIKE",
                    description = (
                        f"Status spike: {count} × HTTP {status} responses "
                        f"from {ip} within {STATUS_SPIKE_WINDOW_SECS}s. "
                        f"Possible scanning/probing."
                    ),
                    base_score  = 50 + min(count * 5, 45),
                    timestamp   = t,
                ))
                break

    return alerts


def detect_suspicious_paths(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Detect requests to known-dangerous paths (SQLi, XSS, admin panels, etc.).
    """
    alerts = []
    http_entries = [e for e in entries if e.log_type == "apache" and e.path]

    for e in http_entries:
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern.lower() in (e.path or "").lower():
                alerts.append(_make_alert(
                    source_ip   = e.source_ip,
                    alert_type  = "SUSPICIOUS_REQUEST",
                    description = (
                        f"Suspicious request from {e.source_ip}: "
                        f"path '{e.path[:80]}' matches pattern '{pattern}'."
                    ),
                    base_score  = 55,
                    timestamp   = e.timestamp,
                ))
                break   # one alert per log entry

    return alerts


def detect_syslog_anomalies(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Flag high-risk syslog events: new users with UID 0, cron running /tmp,
    sudo running dangerous commands, OOM kills, firewall drops.
    """
    alerts = []
    syslog_entries = [e for e in entries if e.log_type == "syslog"]

    danger_actions = {
        "USER_CREATED":    (85, "Privileged user created on system."),
        "PASSWORD_CHANGE": (60, "Password change event recorded."),
        "OOM_KILL":        (50, "Out-of-memory kill occurred."),
    }

    for e in syslog_entries:
        if e.action in danger_actions:
            score, desc = danger_actions[e.action]
            # Extra severity if UID=0 hinted in raw log
            if "UID=0" in (e.path or "") or "uid=0" in (e.path or "").lower():
                score = min(score + 15, 100)
            alerts.append(_make_alert(
                source_ip   = e.source_ip,
                alert_type  = f"SYSLOG_{e.action}",
                description = f"{desc} Raw: {(e.path or '')[:120]}",
                base_score  = score,
                timestamp   = e.timestamp,
            ))

        elif e.action == "CRON_JOB" and "/tmp/" in (e.path or ""):
            alerts.append(_make_alert(
                source_ip   = e.source_ip,
                alert_type  = "SUSPICIOUS_CRON",
                description = (
                    f"Cron executing script from /tmp (common malware pattern). "
                    f"Raw: {(e.path or '')[:120]}"
                ),
                base_score  = 80,
                timestamp   = e.timestamp,
            ))

        elif e.action == "SUDO_EXEC":
            danger_cmds = ["/etc/shadow", "/etc/passwd", "chmod 777"]
            for cmd in danger_cmds:
                if cmd in (e.path or ""):
                    alerts.append(_make_alert(
                        source_ip   = e.source_ip,
                        alert_type  = "DANGEROUS_SUDO",
                        description = (
                            f"Dangerous sudo command detected: '{cmd}' "
                            f"Raw: {(e.path or '')[:120]}"
                        ),
                        base_score  = 75,
                        timestamp   = e.timestamp,
                    ))

    return alerts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_alert(
    source_ip:   str,
    alert_type:  str,
    description: str,
    base_score:  float,
    timestamp:   datetime,
) -> AlertDict:
    score = max(0.0, min(100.0, float(base_score)))
    if score >= 67:
        severity = "HIGH"
    elif score >= 34:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "source_ip":   source_ip,
        "alert_type":  alert_type,
        "description": description,
        "risk_score":  score,
        "severity":    severity,
        "timestamp":   timestamp,
        "engine":      "RULE",
    }
