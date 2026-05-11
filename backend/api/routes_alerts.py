"""
api/routes_alerts.py - CRUD endpoints for security alerts.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import get_db, Alert
from backend.detection.risk_scorer import alert_to_dict
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/", summary="List all alerts")
def list_alerts(
    limit:     int = Query(100, le=500),
    offset:    int = Query(0),
    severity:  Optional[str] = Query(None, description="HIGH | MEDIUM | LOW"),
    resolved:  Optional[bool] = Query(None),
    source_ip: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Return paginated alerts with optional filters."""
    q = db.query(Alert).order_by(Alert.timestamp.desc())
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    if resolved is not None:
        q = q.filter(Alert.resolved == resolved)
    if source_ip:
        q = q.filter(Alert.source_ip == source_ip)
    total = q.count()
    alerts = q.offset(offset).limit(limit).all()
    return {
        "total":  total,
        "alerts": [alert_to_dict(a) for a in alerts],
    }


@router.get("/summary", summary="Alert counts by severity and type")
def alert_summary(db: Session = Depends(get_db)):
    """Aggregate alert statistics for the dashboard."""
    severity_counts = (
        db.query(Alert.severity, func.count(Alert.id).label("count"))
        .group_by(Alert.severity)
        .all()
    )
    type_counts = (
        db.query(Alert.alert_type, func.count(Alert.id).label("count"))
        .group_by(Alert.alert_type)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    engine_counts = (
        db.query(Alert.engine, func.count(Alert.id).label("count"))
        .group_by(Alert.engine)
        .all()
    )
    recent = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(10)
        .all()
    )

    total_count = db.query(func.count(Alert.id)).scalar() or 0
    unresolved_count = (
        db.query(func.count(Alert.id))
        .filter(Alert.resolved == False)
        .scalar() or 0
    )

    # Alert timeline: count per day per severity for trend charts
    timeline_raw = (
        db.query(
            func.date(Alert.timestamp).label("day"),
            Alert.severity,
            func.count(Alert.id).label("count"),
        )
        .group_by(func.date(Alert.timestamp), Alert.severity)
        .order_by(func.date(Alert.timestamp))
        .all()
    )

    # Top attacked IPs
    top_attacked_ips = (
        db.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )

    return {
        "total":          total_count,
        "unresolved":     unresolved_count,
        "by_severity":    {r.severity: r.count for r in severity_counts},
        "by_type":        [{"type": r.alert_type, "count": r.count} for r in type_counts],
        "by_engine":      {r.engine: r.count for r in engine_counts},
        "recent_alerts":  [alert_to_dict(a) for a in recent],
        "timeline":       [{"day": r.day, "severity": r.severity, "count": r.count} for r in timeline_raw],
        "top_attacked_ips": [{"ip": r.source_ip, "count": r.count} for r in top_attacked_ips],
    }


@router.get("/{alert_id}", summary="Get a single alert by ID")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


@router.patch("/{alert_id}/resolve", summary="Mark an alert as resolved")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    db.commit()
    logger.info("Alert %d resolved", alert_id)
    return {"message": "Alert resolved", "id": alert_id}


@router.delete("/{alert_id}", summary="Delete an alert")
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted", "id": alert_id}
