"""
detection/ml_engine.py - ML-based anomaly detection.

Strategy
────────
1. Aggregate log entries into per-IP feature vectors over a rolling window.
2. Train an Isolation Forest on those vectors.
3. Flag outlier IPs and generate alert dicts with a risk score derived
   from the anomaly score returned by the model.

Features used
─────────────
• request_count     – total requests from IP in window
• error_4xx_count   – 4xx responses
• error_5xx_count   – 5xx responses
• unique_paths      – number of distinct paths hit
• failed_logins     – SSH/HTTP 401 events
• bytes_sent_mean   – mean payload size
• time_spread_secs  – time span between first and last event
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

import numpy as np

from backend.database import LogEntry
from backend.config import ML_FEATURE_WINDOW_SECS, ISOLATION_FOREST_CONTAMINATION
from backend.utils.logger import get_logger

logger = get_logger(__name__)

AlertDict = Dict[str, Any]

# Lazy import so scikit-learn is optional at import time
def _get_isolation_forest():
    from sklearn.ensemble import IsolationForest
    return IsolationForest


def run_ml_detection(entries: List[LogEntry]) -> List[AlertDict]:
    """
    Run Isolation Forest over a per-IP feature matrix.

    Returns a list of alert dicts for anomalous IPs.
    Requires scikit-learn. If unavailable, returns an empty list.
    """
    if not entries:
        return []

    try:
        IsolationForest = _get_isolation_forest()
    except ImportError:
        logger.warning("scikit-learn not installed – ML detection skipped.")
        return []

    feature_rows, ip_list, ts_list = _build_feature_matrix(entries)

    if len(feature_rows) < 3:
        logger.info("Too few IPs for ML detection (need ≥3). Skipping.")
        return []

    X = np.array(feature_rows, dtype=float)

    # Fit & predict (-1 = anomaly, 1 = normal)
    clf = IsolationForest(
        contamination=ISOLATION_FOREST_CONTAMINATION,
        random_state=42,
        n_estimators=100,
    )
    labels = clf.fit_predict(X)
    scores = clf.decision_function(X)   # higher = more normal

    alerts = []
    for idx, (label, raw_score) in enumerate(zip(labels, scores)):
        if label == -1:
            ip   = ip_list[idx]
            ts   = ts_list[idx]
            feat = feature_rows[idx]

            # Convert isolation score to 0-100 risk (more negative = higher risk)
            risk = _iso_score_to_risk(raw_score)
            desc = _describe_anomaly(ip, feat)

            severity = "HIGH" if risk >= 67 else "MEDIUM" if risk >= 34 else "LOW"
            alerts.append({
                "source_ip":   ip,
                "alert_type":  "ML_ANOMALY",
                "description": desc,
                "risk_score":  risk,
                "severity":    severity,
                "timestamp":   ts,
                "engine":      "ML",
            })

    logger.info("ML engine flagged %d / %d IPs as anomalous",
                len(alerts), len(ip_list))
    return alerts


# ── Feature Engineering ───────────────────────────────────────────────────────

def _build_feature_matrix(entries: List[LogEntry]):
    """
    Aggregate log entries by IP into a numeric feature matrix.

    Returns (feature_rows, ip_list, ts_list).
    """
    window = timedelta(seconds=ML_FEATURE_WINDOW_SECS)

    # Group entries by IP
    by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in entries:
        by_ip[e.source_ip].append(e)

    feature_rows = []
    ip_list      = []
    ts_list      = []

    for ip, evts in by_ip.items():
        evts.sort(key=lambda e: e.timestamp)
        ts_start = evts[0].timestamp

        # Slide a window and pick the busiest window per IP
        best_count  = 0
        best_feats  = None
        best_ts     = ts_start

        i = 0
        while i < len(evts):
            window_evts = [e for e in evts[i:] if e.timestamp - evts[i].timestamp <= window]
            if len(window_evts) > best_count:
                best_count = len(window_evts)
                best_feats = _compute_features(window_evts)
                best_ts    = evts[i].timestamp
            i += max(1, len(window_evts))

        if best_feats is not None:
            feature_rows.append(best_feats)
            ip_list.append(ip)
            ts_list.append(best_ts)

    return feature_rows, ip_list, ts_list


def _compute_features(evts: List[LogEntry]) -> List[float]:
    """Compute the 7-dimensional feature vector for a list of log entries."""
    statuses    = [e.status or 0 for e in evts]
    paths       = {e.path for e in evts if e.path}
    fail_acts   = {"SSH_LOGIN_FAILED", "SSH_INVALID_USER", "AUTH_FAILURE"}
    bytes_list  = [e.bytes_sent or 0 for e in evts]
    timestamps  = [e.timestamp for e in evts]

    t_spread = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0.0
    failed   = sum(
        1 for e in evts
        if e.action in fail_acts or (e.action in ("POST", "GET") and e.status == 401)
    )

    return [
        float(len(evts)),                                       # request_count
        float(sum(1 for s in statuses if 400 <= s < 500)),     # error_4xx
        float(sum(1 for s in statuses if 500 <= s < 600)),     # error_5xx
        float(len(paths)),                                      # unique_paths
        float(failed),                                          # failed_logins
        float(np.mean(bytes_list)) if bytes_list else 0.0,     # bytes_sent_mean
        float(t_spread),                                        # time_spread_secs
    ]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iso_score_to_risk(score: float) -> float:
    """
    Map Isolation Forest decision_function score to 0-100 risk.
    Scores are in roughly [-0.5, 0.5]; more negative = more anomalous.
    """
    # Clamp and invert: score=-0.5 → risk=100, score=0.5 → risk=0
    clamped = max(-0.5, min(0.5, score))
    return round((0.5 - clamped) * 100, 1)


def _describe_anomaly(ip: str, features: List[float]) -> str:
    req, e4xx, e5xx, paths, fails, bps, spread = features
    parts = [f"ML anomaly detected for {ip}:"]
    parts.append(f"{int(req)} requests")
    if e4xx:
        parts.append(f"{int(e4xx)} 4xx errors")
    if e5xx:
        parts.append(f"{int(e5xx)} 5xx errors")
    if fails:
        parts.append(f"{int(fails)} failed logins")
    if paths > 5:
        parts.append(f"{int(paths)} unique paths accessed")
    return " | ".join(parts) + "."
