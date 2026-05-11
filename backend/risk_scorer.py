"""
detection/risk_scorer.py - Persist alert dicts to the database,
                           deduplicate, and return Alert ORM objects.
"""
from typing import List, Dict, Any
from datetime import datetime

from sqlalchemy.orm import Session

from backend.database import Alert
from backend.utils.geoip import lookup_ip
from backend.utils.logger import get_logger

logger = get_logger(__name__)

AlertDict = Dict[str, Any]


def save_alerts(alert_dicts: List[AlertDict], db: Session) -> List[Alert]:
    """
    Persist a list of raw alert dicts to the database, skipping duplicates.

    Deduplication key: (source_ip, alert_type, severity) on the same UTC day.
    """
    if not alert_dicts:
        return []

    saved: List[Alert] = []
    today = datetime.utcnow().date()

    for a in alert_dicts:
        # Check if an identical alert already exists today
        existing = (
            db.query(Alert)
            .filter(
                Alert.source_ip  == a["source_ip"],
                Alert.alert_type == a["alert_type"],
            )
            .first()
        )
        if existing:
            continue   # skip duplicate

        geo = lookup_ip(a.get("source_ip", "0.0.0.0"))

        orm = Alert(
            source_ip   = a.get("source_ip", "0.0.0.0"),
            alert_type  = a.get("alert_type", "UNKNOWN"),
            description = a.get("description", ""),
            severity    = a.get("severity", "LOW"),
            risk_score  = a.get("risk_score", 0.0),
            engine      = a.get("engine", "RULE"),
            timestamp   = a.get("timestamp") or datetime.utcnow(),
            country     = geo.get("country"),
        )
        db.add(orm)
        saved.append(orm)

    if saved:
        db.commit()
        logger.info("Saved %d new alerts to DB", len(saved))

    return saved


def alert_to_dict(alert: Alert) -> dict:
    """Serialize an Alert ORM object to a plain dict."""
    return {
        "id":          alert.id,
        "timestamp":   alert.timestamp.isoformat() if alert.timestamp else None,
        "source_ip":   alert.source_ip,
        "alert_type":  alert.alert_type,
        "description": alert.description,
        "severity":    alert.severity,
        "risk_score":  alert.risk_score,
        "engine":      alert.engine,
        "resolved":    alert.resolved,
        "country":     alert.country,
    }
