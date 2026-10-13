"""Forensic report generation: JSON content + PDF bytes, both SHA-256 hashed.

Reports are immutable versions per incident (unique incident+version).
PDFs live under reports/ (gitignored, never overwritten); JSON content is
stored in the DB row. No legal-admissibility claim anywhere in the output.
"""
import hashlib
import io
import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import (
    CustodyRecord,
    Detection,
    Endpoint,
    Evidence,
    ForensicReport,
    Incident,
    User,
)
from app.services.chain_verify import verify_telemetry_chain
from app.services.evidence import verify_custody_chain
from app.services.timeline import build_incident_timeline

logger = logging.getLogger("weblock.reports")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "..", "reports")
MAX_PDF_BYTES = 5 * 1024 * 1024

LIMITATIONS = [
    "No memory forensics, disk imaging, kernel acquisition, packet capture, "
    "malware sandbox, or legal evidence certification.",
    "Integrity verification covers telemetry recorded by WebLock only; "
    "deletion of trailing rows and retention gaps are outside detection.",
    "Pre-Phase-7 telemetry rows use linkage-only legacy hashes.",
    "Correlation references survive cluster cleanup via snapshots; deleted "
    "source rows are flagged, not reconstructed.",
]


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def build_report_content(db: Session, incident: Incident,
                         generated_by: str) -> dict:
    from app.api.v1.incidents import _correlation_block, _risk_block
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == incident.endpoint_id).first() \
        if incident.endpoint_id else None
    user = db.query(User).filter(User.id == incident.user_id).first() \
        if incident.user_id else None
    corr = _correlation_block(db, incident)
    risk = _risk_block(db, incident)
    timeline = build_incident_timeline(db, incident)
    ev_rows = (
        db.query(Evidence)
        .filter(Evidence.org_id == incident.org_id,
                Evidence.incident_id == incident.id)
        .order_by(Evidence.id.asc())
        .limit(200)
        .all()
    )
    inventory = []
    for ev in ev_rows:
        ok, problems = verify_custody_chain(db, ev.id)
        inventory.append({
            "evidence_id": ev.id, "source_type": ev.source_type,
            "source_id": ev.source_id, "sha256": ev.sha256,
            "integrity_status": ev.integrity_status,
            "collected_at": ev.collected_at.isoformat()
            if ev.collected_at else None,
            "collected_by": ev.collected_by,
            "description": ev.description,
            "custody_valid": ok, "custody_problems": problems,
        })
    # Integrity over the incident's endpoint window (bounded by cluster span).
    integrity = None
    if incident.endpoint_id is not None and corr and not corr.get("missing"):
        integrity = verify_telemetry_chain(
            db, org_id=incident.org_id, endpoint_id=incident.endpoint_id,
            start=None, end=None, limit=2000)
        # Bound: only the incident's own event refs are in scope for the
        # report; full-chain verification stays on the dedicated endpoint API.
        integrity["note"] = ("Endpoint-wide chain state at report time; use "
                             "POST /v1/endpoints/{id}/integrity/verify for "
                             "bounded re-verification.")
    mitre = sorted({t for d in (corr or {}).get("detections", [])
                    for t in (d.get("mitre") or [])})
    return {
        "report": "WebLock Forensic Report (engineering record; "
                  "no legal-admissibility claim)",
        "incident": {
            "id": incident.id, "incident_key": incident.incident_key,
            "title": incident.title, "severity": incident.severity,
            "risk_score": incident.risk_score, "status": incident.status,
            "summary": incident.summary,
            "created_at": incident.created_at.isoformat()
            if incident.created_at else None,
        },
        "endpoint": {"id": endpoint.id if endpoint else None,
                     "hostname": endpoint.hostname if endpoint else None,
                     "os": endpoint.os_name if endpoint else None,
                     "agent_id": endpoint.agent_id if endpoint else None},
        "user": {"id": user.id if user else None,
                 "email": user.email if user else None,
                 "note": "user_id is null until identity binding exists"}
        if user or incident.user_id is None else {"id": incident.user_id},
        "risk": risk,
        "correlation": corr,
        "timeline": timeline,
        "evidence_inventory": inventory,
        "integrity": integrity,
        "mitre": mitre,
        "limitations": LIMITATIONS,
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def render_pdf(content: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm,
                            rightMargin=15 * mm)
    styles = getSampleStyleSheet()
    story = []
    inc = content["incident"]
    story.append(Paragraph(
        f"WebLock Forensic Report — {inc['incident_key']}", styles["Title"]))
    story.append(Paragraph(
        f"Severity {inc['severity'].upper()} | Risk {inc['risk_score']} | "
        f"Status {inc['status']} | Generated {content['generated_at']} by "
        f"{content['generated_by']}", styles["Normal"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(Paragraph((inc.get("summary") or "")[:2000], styles["Normal"]))
    story.append(Paragraph("Timeline", styles["Heading2"]))
    rows = [["Time", "Kind", "Detail"]]
    for item in content["timeline"][:200]:
        rows.append([item["timestamp"] or "", item["kind"],
                     item["title"][:110]])
    story.append(Table(rows, colWidths=[42 * mm, 28 * mm, 100 * mm]))
    story.append(Paragraph("Evidence inventory", styles["Heading2"]))
    erows = [["ID", "Source", "SHA-256 (prefix)", "Integrity"]]
    for ev in content["evidence_inventory"]:
        erows.append([str(ev["evidence_id"]), ev["source_type"],
                      (ev["sha256"] or "")[:16], ev["integrity_status"]])
    story.append(Table(erows, colWidths=[15 * mm, 40 * mm, 55 * mm, 30 * mm]))
    integ = content.get("integrity") or {}
    story.append(Paragraph("Integrity", styles["Heading2"]))
    story.append(Paragraph(
        f"Chain valid: {integ.get('valid')} | events checked: "
        f"{integ.get('events_checked')} | violations: "
        f"{len(integ.get('violations', []))}", styles["Normal"]))
    story.append(Paragraph("MITRE ATT&CK", styles["Heading2"]))
    story.append(Paragraph(", ".join(content.get("mitre") or ["none mapped"]),
                           styles["Normal"]))
    story.append(Paragraph("Limitations", styles["Heading2"]))
    for line in content["limitations"]:
        story.append(Paragraph(f"- {line}", styles["Normal"]))
    story.append(Paragraph(
        "Engineering record only; no legal-admissibility claim.",
        styles["Italic"]))
    doc.build(story)
    data = buf.getvalue()
    if len(data) > MAX_PDF_BYTES:
        raise ValueError("Report exceeds size limit")
    return data


def export_report(db: Session, *, org_id: int, incident_id: int,
                  generated_by_user_id: int | None,
                  generated_by_name: str, format: str) -> ForensicReport:
    from app.db.models import Incident
    if format not in ("json", "pdf"):
        raise ValueError("format must be json or pdf")
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.org_id == org_id).first()
    if incident is None:
        raise LookupError("Incident not found")
    existing = (
        db.query(ForensicReport)
        .filter(ForensicReport.incident_id == incident_id)
        .order_by(ForensicReport.version.desc())
        .first()
    )
    version = (existing.version + 1) if existing else 1
    content = build_report_content(db, incident, generated_by_name)
    content["report_version"] = version
    if format == "json":
        raw = _canonical(content).encode()
        file_path = ""
    else:
        raw = render_pdf(content)
        os.makedirs(REPORTS_DIR, exist_ok=True)
        file_path = os.path.join(
            REPORTS_DIR, f"incident-{incident_id}-v{version}.pdf")
        if os.path.exists(file_path):
            raise FileExistsError("Report file already exists (immutable)")
        with open(file_path, "wb") as f:
            f.write(raw)
    digest = hashlib.sha256(raw).hexdigest()
    row = ForensicReport(
        org_id=org_id, incident_id=incident_id, version=version,
        format=format, sha256=digest, size_bytes=len(raw),
        generated_by=generated_by_user_id, file_path=file_path,
        content=content if format == "json" else {
            "incident_key": incident.incident_key, "version": version,
            "timeline_items": len(content["timeline"]),
            "evidence_items": len(content["evidence_inventory"])})
    db.add(row)
    db.flush()
    return row


def verify_report(db: Session, *, org_id: int, report_id: int) -> dict:
    row = db.query(ForensicReport).filter(
        ForensicReport.id == report_id, ForensicReport.org_id == org_id
    ).first()
    if row is None:
        raise LookupError("Report not found")
    if row.format == "json":
        actual = hashlib.sha256(
            _canonical(row.content).encode()).hexdigest()
    else:
        try:
            with open(row.file_path, "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            return {"report_id": row.id, "valid": False,
                    "reason": "report file missing from disk"}
    return {"report_id": row.id, "valid": actual == row.sha256,
            "expected": row.sha256, "actual": actual}
