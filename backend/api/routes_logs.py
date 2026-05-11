"""
api/routes_logs.py - Endpoints for uploading log files and streaming simulation.
"""
import io
import asyncio
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import get_db, LogEntry
from backend.parser.log_parser import parse_line, detect_log_type
from backend.parser.normalizer import normalize_and_save, entry_to_dict
from backend.detection.rule_engine import run_all_rules
from backend.detection.ml_engine import run_ml_detection
from backend.detection.risk_scorer import save_alerts
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post("/upload", summary="Upload a log file for analysis")
async def upload_log(
    file: UploadFile = File(...),
    log_type: Optional[str] = Query(None, description="apache | ssh | syslog (auto-detected if omitted)"),
    enrich_geo: bool = Query(False, description="Enable GeoIP enrichment (slower)"),
    db: Session = Depends(get_db),
):
    """
    Upload a log file. The backend will:
    1. Auto-detect or use the supplied log_type.
    2. Parse every line into a structured LogEntry.
    3. Run rule-based and ML detection.
    4. Persist log entries and alerts.
    5. Return a summary.
    """
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    content = raw_bytes.decode(errors="replace")
    detected_type = log_type or detect_log_type(content)
    logger.info("Processing upload: %s (type=%s, %d bytes)",
                file.filename, detected_type, len(raw_bytes))

    # ── Parse ──────────────────────────────────────────────────────────────
    parsed = []
    for line in content.splitlines():
        result = parse_line(line, detected_type)
        if result:
            parsed.append(result)

    if not parsed:
        raise HTTPException(
            status_code=422,
            detail=f"No parseable lines found. Detected type: {detected_type}",
        )

    # ── Normalize & save entries ───────────────────────────────────────────
    orm_entries = normalize_and_save(parsed, db, enrich_geo=enrich_geo)

    # ── Detection ──────────────────────────────────────────────────────────
    rule_alerts = run_all_rules(orm_entries)
    ml_alerts   = run_ml_detection(orm_entries)
    all_alerts  = rule_alerts + ml_alerts

    saved_alerts = save_alerts(all_alerts, db)

    return {
        "filename":      file.filename,
        "log_type":      detected_type,
        "lines_parsed":  len(parsed),
        "entries_saved": len(orm_entries),
        "alerts_generated": len(saved_alerts),
        "alert_summary": {
            "HIGH":   sum(1 for a in saved_alerts if a.severity == "HIGH"),
            "MEDIUM": sum(1 for a in saved_alerts if a.severity == "MEDIUM"),
            "LOW":    sum(1 for a in saved_alerts if a.severity == "LOW"),
        },
    }


@router.get("/", summary="List stored log entries")
def list_logs(
    limit:    int = Query(100, le=1000),
    offset:   int = Query(0),
    source_ip: Optional[str] = Query(None),
    log_type:  Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Return paginated log entries with optional filters."""
    q = db.query(LogEntry).order_by(LogEntry.timestamp.desc())
    if source_ip:
        q = q.filter(LogEntry.source_ip == source_ip)
    if log_type:
        q = q.filter(LogEntry.log_type == log_type)
    total = q.count()
    entries = q.offset(offset).limit(limit).all()
    return {
        "total": total,
        "entries": [entry_to_dict(e) for e in entries],
    }


@router.get("/stream", summary="Simulate real-time log streaming (SSE)")
async def stream_logs(db: Session = Depends(get_db)):
    """
    Server-Sent Events endpoint that replays the most recent 50 log entries
    one-by-one with a short delay, simulating live log tailing.
    """
    entries = (
        db.query(LogEntry)
        .order_by(LogEntry.timestamp.desc())
        .limit(50)
        .all()
    )
    entries.reverse()   # oldest first for replay

    async def event_generator():
        for e in entries:
            import json
            data = json.dumps(entry_to_dict(e))
            yield f"data: {data}\n\n"
            await asyncio.sleep(0.15)
        yield "data: {\"event\": \"end\"}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/stats", summary="Aggregate statistics for the dashboard")
def log_stats(db: Session = Depends(get_db)):
    """Return top IPs, status code distribution, request counts, and activity timeline."""
    top_ips = (
        db.query(LogEntry.source_ip, func.count(LogEntry.id).label("count"))
        .group_by(LogEntry.source_ip)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
        .all()
    )

    status_dist = (
        db.query(LogEntry.status, func.count(LogEntry.id).label("count"))
        .filter(LogEntry.status.isnot(None))
        .group_by(LogEntry.status)
        .order_by(func.count(LogEntry.id).desc())
        .limit(15)
        .all()
    )

    type_dist = (
        db.query(LogEntry.log_type, func.count(LogEntry.id).label("count"))
        .group_by(LogEntry.log_type)
        .all()
    )

    action_dist = (
        db.query(LogEntry.action, func.count(LogEntry.id).label("count"))
        .group_by(LogEntry.action)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
        .all()
    )

    # Activity timeline: events per hour for trend chart
    activity_timeline = (
        db.query(
            func.strftime("%Y-%m-%d %H:00", LogEntry.timestamp).label("hour"),
            LogEntry.log_type,
            func.count(LogEntry.id).label("count"),
        )
        .group_by(func.strftime("%Y-%m-%d %H:00", LogEntry.timestamp), LogEntry.log_type)
        .order_by(func.strftime("%Y-%m-%d %H:00", LogEntry.timestamp))
        .all()
    )

    # Country distribution
    country_dist = (
        db.query(LogEntry.country, func.count(LogEntry.id).label("count"))
        .filter(LogEntry.country.isnot(None))
        .group_by(LogEntry.country)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
        .all()
    )

    return {
        "top_ips":        [{  "ip": r.source_ip, "count": r.count} for r in top_ips],
        "status_dist":    [{"status": r.status, "count": r.count} for r in status_dist],
        "type_dist":      [{"type": r.log_type, "count": r.count} for r in type_dist],
        "action_dist":    [{"action": r.action, "count": r.count} for r in action_dist],
        "activity_timeline": [{"hour": r.hour, "type": r.log_type, "count": r.count} for r in activity_timeline],
        "country_dist":   [{"country": r.country, "count": r.count} for r in country_dist],
        "total_entries":  db.query(func.count(LogEntry.id)).scalar() or 0,
    }
