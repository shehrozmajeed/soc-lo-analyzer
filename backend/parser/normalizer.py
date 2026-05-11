"""
parser/normalizer.py - Convert parsed log dicts to LogEntry ORM instances,
                       apply GeoIP enrichment, and bulk-save to the database.
"""
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from backend.database import LogEntry
from backend.utils.geoip import lookup_ip
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def normalize_and_save(
    parsed_entries: List[dict],
    db: Session,
    enrich_geo: bool = True,
) -> List[LogEntry]:
    """
    Convert a list of parsed log dicts to LogEntry rows and persist them.

    Parameters
    ----------
    parsed_entries : list of dicts from log_parser.parse_line()
    db             : SQLAlchemy session
    enrich_geo     : whether to call GeoIP lookup (can be slow for large batches)

    Returns
    -------
    List of persisted LogEntry objects.
    """
    orm_entries: List[LogEntry] = []

    for entry in parsed_entries:
        if entry is None:
            continue

        geo = {}
        if enrich_geo and entry.get("source_ip"):
            geo = lookup_ip(entry["source_ip"])

        orm = LogEntry(
            timestamp  = entry.get("timestamp") or datetime.utcnow(),
            source_ip  = entry.get("source_ip", "0.0.0.0"),
            action     = (entry.get("action") or "UNKNOWN")[:16],
            path       = entry.get("path"),
            status     = entry.get("status"),
            bytes_sent = entry.get("bytes_sent", 0),
            log_type   = entry.get("log_type", "unknown"),
            raw        = entry.get("raw"),
            country    = geo.get("country"),
            city       = geo.get("city"),
        )
        orm_entries.append(orm)

    if orm_entries:
        db.bulk_save_objects(orm_entries)
        db.commit()
        logger.info("Saved %d log entries to DB", len(orm_entries))

    return orm_entries


def entry_to_dict(entry: LogEntry) -> dict:
    """Serialize a LogEntry ORM object to a plain dict (for API responses)."""
    return {
        "id":         entry.id,
        "timestamp":  entry.timestamp.isoformat() if entry.timestamp else None,
        "source_ip":  entry.source_ip,
        "action":     entry.action,
        "path":       entry.path,
        "status":     entry.status,
        "bytes_sent": entry.bytes_sent,
        "log_type":   entry.log_type,
        "country":    entry.country,
        "city":       entry.city,
    }
