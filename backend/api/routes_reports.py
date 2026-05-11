"""
api/routes_reports.py - Export alerts and log stats as CSV or PDF.
"""
import csv
import io
import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session

from backend.database import get_db, Alert, LogEntry
from backend.config import REPORTS_DIR
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])

os.makedirs(REPORTS_DIR, exist_ok=True)


# ── CSV Export ────────────────────────────────────────────────────────────────

@router.get("/alerts/csv", summary="Export all alerts as CSV")
def export_alerts_csv(db: Session = Depends(get_db)):
    """Stream all alerts as a downloadable CSV file."""
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()

    def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "timestamp", "source_ip", "alert_type",
            "severity", "risk_score", "engine", "resolved",
            "country", "description",
        ])
        yield buf.getvalue()
        buf.seek(0); buf.truncate()

        for a in alerts:
            writer.writerow([
                a.id,
                a.timestamp.isoformat() if a.timestamp else "",
                a.source_ip,
                a.alert_type,
                a.severity,
                a.risk_score,
                a.engine,
                a.resolved,
                a.country or "",
                (a.description or "").replace("\n", " "),
            ])
            yield buf.getvalue()
            buf.seek(0); buf.truncate()

    filename = f"soc_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/logs/csv", summary="Export recent log entries as CSV")
def export_logs_csv(db: Session = Depends(get_db)):
    """Stream the last 5,000 log entries as a downloadable CSV file."""
    entries = (
        db.query(LogEntry)
        .order_by(LogEntry.timestamp.desc())
        .limit(5000)
        .all()
    )

    def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "timestamp", "source_ip", "action",
            "path", "status", "bytes_sent", "log_type",
            "country", "city",
        ])
        yield buf.getvalue()
        buf.seek(0); buf.truncate()

        for e in entries:
            writer.writerow([
                e.id,
                e.timestamp.isoformat() if e.timestamp else "",
                e.source_ip,
                e.action,
                e.path or "",
                e.status or "",
                e.bytes_sent or 0,
                e.log_type,
                e.country or "",
                e.city or "",
            ])
            yield buf.getvalue()
            buf.seek(0); buf.truncate()

    filename = f"soc_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── PDF Export ────────────────────────────────────────────────────────────────

@router.get("/alerts/pdf", summary="Export alert summary as PDF")
def export_alerts_pdf(db: Session = Depends(get_db)):
    """
    Generate a PDF report of all alerts.
    Requires the 'reportlab' package. Falls back to a plain-text file if absent.
    """
    alerts = db.query(Alert).order_by(Alert.severity, Alert.timestamp.desc()).all()
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(REPORTS_DIR, f"soc_report_{timestamp_str}.pdf")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        )
        from reportlab.lib.styles import getSampleStyleSheet

        doc    = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story  = []

        story.append(Paragraph("SOC Log Analyzer – Alert Report", styles["Title"]))
        story.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}   "
            f"Total alerts: {len(alerts)}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 12))

        table_data = [["ID", "Timestamp", "IP", "Type", "Severity", "Score", "Engine"]]
        for a in alerts:
            table_data.append([
                str(a.id),
                a.timestamp.strftime("%Y-%m-%d %H:%M") if a.timestamp else "",
                a.source_ip,
                a.alert_type,
                a.severity,
                str(round(a.risk_score, 1)),
                a.engine,
            ])

        tbl = Table(table_data, repeatRows=1)
        severity_colors = {"HIGH": colors.red, "MEDIUM": colors.orange, "LOW": colors.green}
        style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ])
        # Colour severity column
        for i, a in enumerate(alerts, start=1):
            c = severity_colors.get(a.severity, colors.grey)
            style.add("TEXTCOLOR", (4, i), (4, i), c)
            style.add("FONTNAME", (4, i), (4, i), "Helvetica-Bold")
        tbl.setStyle(style)
        story.append(tbl)

        doc.build(story)
        logger.info("PDF report generated: %s", pdf_path)
        return FileResponse(pdf_path, media_type="application/pdf",
                            filename=os.path.basename(pdf_path))

    except ImportError:
        # Fallback: plain-text report
        txt_path = pdf_path.replace(".pdf", ".txt")
        with open(txt_path, "w") as f:
            f.write("SOC Log Analyzer – Alert Report\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}\n\n")
            for a in alerts:
                f.write(
                    f"[{a.severity}] {a.alert_type} | {a.source_ip} | "
                    f"{a.timestamp} | Score={a.risk_score}\n"
                    f"  {a.description}\n\n"
                )
        return FileResponse(txt_path, media_type="text/plain",
                            filename=os.path.basename(txt_path))
