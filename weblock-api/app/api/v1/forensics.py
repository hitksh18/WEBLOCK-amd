"""Phase 7 forensic APIs (org-scoped, RBAC-gated, bounded).

Read (viewer+): timeline, evidence list/detail, custody, integrity,
report content/download.
Write (investigator/analyst/admin): collect, snapshot, verify, export.
"""
from datetime import datetime
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import CustodyRecord, Evidence, EvidenceSnapshot, User
from app.services.evidence import (
    CUSTODY_ACTIONS,
    SOURCE_TYPES,
    add_custody,
    collect_evidence,
    create_snapshot,
    verify_custody_chain,
    verify_evidence,
)

router = APIRouter(tags=["forensics"])
MAX_LIMIT = 200
forensic_write = require_role("admin", "analyst", "investigator")


def _ev_out(ev: Evidence) -> dict:
    return {
        "id": ev.id, "incident_id": ev.incident_id,
        "correlation_id": ev.correlation_id,
        "source": ev.source, "source_type": ev.source_type,
        "source_id": ev.source_id, "sha256": ev.sha256,
        "integrity_status": ev.integrity_status,
        "collector": ev.collector, "collected_by": ev.collected_by,
        "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
        "description": ev.description, "content": ev.content,
    }


def _incident_or_404(db: Session, org_id: int, incident_id: int):
    from app.db.models import Incident
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.org_id == org_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/incidents/{incident_id}/timeline")
def incident_timeline(
    incident_id: int,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.timeline import MAX_ITEMS, build_incident_timeline
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    items = build_incident_timeline(db, incident, limit=MAX_ITEMS)
    page = items[offset:offset + limit]
    return {"incident_id": incident_id, "total": len(items),
            "limit": limit, "offset": offset, "timeline": page}


@router.get("/incidents/{incident_id}/evidence")
def incident_evidence(
    incident_id: int,
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _incident_or_404(db, current_user.org_id, incident_id)
    q = db.query(Evidence).filter(
        Evidence.org_id == current_user.org_id,
        Evidence.incident_id == incident_id).order_by(Evidence.id.asc())
    total = q.count()
    return {"incident_id": incident_id, "total": total,
            "evidence": [_ev_out(e) for e in q.offset(offset).limit(limit)]}


@router.post("/incidents/{incident_id}/evidence/collect")
def evidence_collect(
    incident_id: int, payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(forensic_write),
):
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    source_type = (payload.get("source_type") or "")
    if source_type not in SOURCE_TYPES:
        raise HTTPException(status_code=422, detail="Unsupported source_type")
    try:
        source_id = int(payload.get("source_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="source_id must be an integer")
    try:
        row = collect_evidence(
            db, org_id=current_user.org_id, source_type=source_type,
            source_id=source_id, incident_id=incident.id,
            correlation_id=incident.correlation_id,
            actor_user_id=current_user.id, actor_name=current_user.email,
            description=str(payload.get("description", ""))[:2000])
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    db.commit()
    return _ev_out(row)


@router.post("/incidents/{incident_id}/snapshot")
def incident_snapshot(
    incident_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(forensic_write),
):
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    try:
        snap = create_snapshot(db, org_id=current_user.org_id,
                               incident_id=incident.id,
                               actor_user_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    db.commit()
    return {"id": snap.id, "incident_id": incident_id,
            "evidence_ids": snap.evidence_ids,
            "snapshot_hash": snap.snapshot_hash,
            "created_at": snap.created_at.isoformat() if snap.created_at else None}


@router.get("/evidence/{evidence_id}")
def evidence_detail(
    evidence_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.db.models import AuditLog
    row = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="evidence.viewed", target=f"evidence:{row.id}",
                    meta_data={"source_type": row.source_type}))
    db.commit()
    return _ev_out(row)


@router.post("/evidence/{evidence_id}/verify")
def evidence_verify(
    evidence_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(forensic_write),
):
    try:
        row, ok = verify_evidence(db, org_id=current_user.org_id,
                                  evidence_id=evidence_id,
                                  actor_user_id=current_user.id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.commit()
    return {"id": row.id, "integrity_status": row.integrity_status,
            "valid": ok}


@router.get("/evidence/{evidence_id}/custody")
def evidence_custody(
    evidence_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    records = (
        db.query(CustodyRecord)
        .filter(CustodyRecord.evidence_id == evidence_id)
        .order_by(CustodyRecord.id.asc())
        .limit(MAX_LIMIT)
        .all()
    )
    valid, problems = verify_custody_chain(db, evidence_id)
    return {"evidence_id": evidence_id, "chain_valid": valid,
            "problems": problems,
            "records": [{
                "id": r.id, "action": r.action,
                "actor_user_id": r.actor_user_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "reason": r.reason, "prev_hash": r.prev_hash,
                "record_hash": r.record_hash} for r in records]}


@router.get("/incidents/{incident_id}/integrity")
def incident_integrity(
    incident_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.chain_verify import verify_telemetry_chain
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    if incident.endpoint_id is None:
        return {"incident_id": incident_id, "scope": "none",
                "detail": "Incident has no endpoint telemetry scope"}
    result = verify_telemetry_chain(
        db, org_id=current_user.org_id, endpoint_id=incident.endpoint_id,
        limit=2000)
    result["incident_id"] = incident_id
    return result


@router.post("/endpoints/{endpoint_id}/integrity/verify")
def endpoint_integrity_verify(
    endpoint_id: int, payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(forensic_write),
):
    from app.services.chain_verify import MAX_VERIFY_ROWS, verify_telemetry_chain
    try:
        start = datetime.fromisoformat(payload["start"]) if payload.get("start") else None
        end = datetime.fromisoformat(payload["end"]) if payload.get("end") else None
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="start/end must be ISO-8601")
    if start is not None and end is not None and (end - start).days > 7:
        raise HTTPException(status_code=422,
                            detail="Verification window limited to 7 days")
    limit = min(int(payload.get("limit", 2000)), MAX_VERIFY_ROWS)
    try:
        return verify_telemetry_chain(
            db, org_id=current_user.org_id, endpoint_id=endpoint_id,
            start=start, end=end, limit=limit)
    except LookupError:
        raise HTTPException(status_code=404, detail="Endpoint not found")


@router.post("/incidents/{incident_id}/report/export")
def report_export(
    incident_id: int, payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(forensic_write),
):
    from app.db.models import AuditLog
    from app.services.reports import export_report
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    fmt = (payload.get("format") or "json").lower()
    if fmt not in ("json", "pdf"):
        raise HTTPException(status_code=422, detail="format must be json or pdf")
    try:
        row = export_report(db, org_id=current_user.org_id,
                            incident_id=incident.id,
                            generated_by_user_id=current_user.id,
                            generated_by_name=current_user.email, format=fmt)
    except (ValueError, FileExistsError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="evidence.exported",
                    target=f"report:{row.id}",
                    meta_data={"incident_id": incident.id, "format": fmt,
                               "version": row.version}))
    db.commit()
    return {"id": row.id, "incident_id": incident_id, "version": row.version,
            "format": row.format, "sha256": row.sha256,
            "size_bytes": row.size_bytes,
            "generated_at": row.generated_at.isoformat()
            if row.generated_at else None}


@router.get("/incidents/{incident_id}/report")
def report_latest(
    incident_id: int, version: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.db.models import ForensicReport
    _incident_or_404(db, current_user.org_id, incident_id)
    q = db.query(ForensicReport).filter(
        ForensicReport.org_id == current_user.org_id,
        ForensicReport.incident_id == incident_id)
    if version is not None:
        q = q.filter(ForensicReport.version == version)
    row = q.order_by(ForensicReport.version.desc()).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No report found")
    body: dict = {"id": row.id, "incident_id": incident_id,
                  "version": row.version, "format": row.format,
                  "sha256": row.sha256, "size_bytes": row.size_bytes,
                  "generated_at": row.generated_at.isoformat()
                  if row.generated_at else None}
    if row.format == "json":
        body["content"] = row.content
    else:
        body["download"] = f"/v1/reports/{row.id}/download"
    return body


@router.get("/reports/{report_id}/download")
def report_download(
    report_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.db.models import AuditLog, ForensicReport
    row = db.query(ForensicReport).filter(
        ForensicReport.id == report_id,
        ForensicReport.org_id == current_user.org_id).first()
    if row is None or row.format != "pdf" or not row.file_path:
        raise HTTPException(status_code=404, detail="PDF report not found")
    # No arbitrary paths: file must live under the managed reports dir.
    from app.services.reports import REPORTS_DIR
    if os.path.dirname(os.path.abspath(row.file_path)) != os.path.abspath(REPORTS_DIR):
        raise HTTPException(status_code=404, detail="PDF report not found")
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="evidence.exported",
                    target=f"report:{row.id}",
                    meta_data={"download": True}))
    db.commit()
    return FileResponse(row.file_path, media_type="application/pdf",
                        filename=f"weblock-incident-{row.incident_id}-v{row.version}.pdf")


@router.post("/reports/{report_id}/verify")
def report_verify(
    report_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.reports import verify_report
    try:
        return verify_report(db, org_id=current_user.org_id,
                             report_id=report_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Report not found")
