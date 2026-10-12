"""Endpoint enrollment, heartbeat, config, listing, revocation.

- POST /v1/admin/enrollment-tokens   (admin, user JWT) -> one-time token
- POST /v1/endpoints/enroll          (public, one-time token) -> agent creds
- POST /v1/endpoints/{id}/heartbeat  (agent key; path id must match key)
- GET  /v1/endpoints/{id}/config     (agent key)
- GET  /v1/endpoints + /{id}         (user JWT, org-scoped)
- POST /v1/admin/endpoints/{id}/revoke, PUT /v1/admin/endpoints/{id}/config
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.agent_auth import get_current_endpoint
from app.core.dependencies import get_current_user, require_role
from app.core.timeutil import as_utc
from app.db.database import get_db
from app.db.models import (
    AgentCredential,
    AuditLog,
    Endpoint,
    EnrollmentToken,
    User,
)
from app.schemas.telemetry import HeartbeatIn, EnrollIn, merge_config

router = APIRouter(tags=["endpoints"])


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _presence(endpoint: Endpoint) -> str:
    if endpoint.status in ("revoked", "isolated"):
        return endpoint.status
    if not endpoint.last_seen:
        return "never-seen"
    interval = (endpoint.config or {}).get("heartbeat_interval", 60)
    try:
        interval = int(interval)
    except (TypeError, ValueError):
        interval = 60
    age = (datetime.now(timezone.utc) - as_utc(endpoint.last_seen)).total_seconds()
    if age > max(3 * interval, 180):
        return "offline"
    return endpoint.status


def _endpoint_out(endpoint: Endpoint) -> dict:
    return {
        "id": endpoint.id,
        "agent_id": endpoint.agent_id,
        "name": endpoint.name,
        "hostname": endpoint.hostname,
        "os": endpoint.os_name,
        "ip": endpoint.ip_address,
        "agent_version": endpoint.agent_version,
        "status": endpoint.status,
        "presence": _presence(endpoint),
        "risk_score": endpoint.risk_score,
        "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
    }


@router.post("/admin/enrollment-tokens")
def create_enrollment_token(
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    raw = "wle_" + secrets.token_hex(16)
    label = ((payload or {}).get("label") or "")[:255]
    db.add(EnrollmentToken(
        org_id=current_user.org_id,
        token_hash=_sha(raw),
        label=label,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        created_by=current_user.id,
    ))
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="enrollment_token.created", target=label or "enrollment-token"))
    db.commit()
    return {"enroll_token": raw, "expires_in_hours": 24}  # shown ONCE


@router.post("/endpoints/enroll")
def enroll(payload: EnrollIn, db: Session = Depends(get_db)):
    if not payload.enroll_token.startswith("wle_"):
        raise HTTPException(status_code=401, detail="Invalid enrollment token")
    token = (
        db.query(EnrollmentToken)
        .filter(EnrollmentToken.token_hash == _sha(payload.enroll_token),
                EnrollmentToken.used.is_(False))
        .first()
    )
    if not token:
        raise HTTPException(status_code=401, detail="Unknown or used token")
    if as_utc(token.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Enrollment token expired")

    device = payload.device or {}
    agent_id = f"agent-{secrets.token_hex(6)}"
    hostname = str(device.get("hostname") or "")[:255]
    endpoint = Endpoint(
        org_id=token.org_id,
        agent_id=agent_id,
        name=hostname or agent_id,
        hostname=hostname,
        os_name=str(device.get("os") or "")[:100],
        ip_address=str(device.get("ip") or "")[:45],
        mac_address=str(device.get("mac") or "")[:50],
        fingerprint=str(device.get("fingerprint") or "")[:1024],
        agent_version=str(device.get("agent_version") or "")[:50],
        status="healthy",
        last_seen=datetime.now(timezone.utc),
    )
    db.add(endpoint)
    db.flush()
    raw_key = "wlk_" + secrets.token_hex(16)
    db.add(AgentCredential(endpoint_id=endpoint.id, key_hash=_sha(raw_key)))
    token.used = True
    db.add(AuditLog(org_id=token.org_id, actor_id=token.created_by,
                    action="endpoint.enrolled", target=agent_id,
                    meta_data={"hostname": hostname}))
    db.commit()
    # api_key shown ONCE — never returned again.
    return {"agent_id": agent_id, "endpoint_id": endpoint.id,
            "api_key": raw_key, "org_id": token.org_id}


@router.post("/endpoints/{endpoint_id}/heartbeat")
def heartbeat(endpoint_id: int, payload: HeartbeatIn,
              db: Session = Depends(get_db),
              endpoint: Endpoint = Depends(get_current_endpoint)):
    if endpoint.id != endpoint_id:
        # One endpoint may never report for another.
        raise HTTPException(status_code=403, detail="endpoint_id mismatch")
    endpoint.last_seen = datetime.now(timezone.utc)
    if payload.hostname:
        endpoint.hostname = payload.hostname
        if not endpoint.name:
            endpoint.name = payload.hostname
    if payload.os:
        endpoint.os_name = payload.os
    if payload.ip:
        endpoint.ip_address = payload.ip
    if payload.agent_version:
        endpoint.agent_version = payload.agent_version
    if endpoint.status not in ("isolated", "revoked"):
        endpoint.status = "healthy"
    db.commit()
    return {"ok": True, "endpoint_id": endpoint.id,
            "status": endpoint.status, "last_seen": endpoint.last_seen.isoformat()}


@router.get("/endpoints/{endpoint_id}/config")
def agent_config(endpoint_id: int, db: Session = Depends(get_db),
                 endpoint: Endpoint = Depends(get_current_endpoint)):
    if endpoint.id != endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint_id mismatch")
    db.refresh(endpoint)
    return merge_config(endpoint.config)


@router.get("/endpoints")
def list_endpoints(db: Session = Depends(get_db),
                   current_user: User = Depends(get_current_user)):
    rows = (
        db.query(Endpoint)
        .filter(Endpoint.org_id == current_user.org_id)
        .order_by(Endpoint.id.desc())
        .limit(200)
        .all()
    )
    return [_endpoint_out(r) for r in rows]


@router.get("/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: int, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    row = (
        db.query(Endpoint)
        .filter(Endpoint.id == endpoint_id,
                Endpoint.org_id == current_user.org_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _endpoint_out(row)


class ConfigPut(BaseModel):
    config: dict = Field(default_factory=dict)


@router.put("/admin/endpoints/{endpoint_id}/config")
def set_endpoint_config(
    endpoint_id: int, payload: ConfigPut, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    row = (
        db.query(Endpoint)
        .filter(Endpoint.id == endpoint_id,
                Endpoint.org_id == current_user.org_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    try:
        merged = merge_config({**(row.config or {}), **payload.config})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    row.config = merged
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="endpoint.config_updated", target=row.agent_id,
                    meta_data={"config": payload.config}))
    db.commit()
    return merged


@router.post("/admin/endpoints/{endpoint_id}/revoke")
def revoke_endpoint(
    endpoint_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    row = (
        db.query(Endpoint)
        .filter(Endpoint.id == endpoint_id,
                Endpoint.org_id == current_user.org_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    cred = db.query(AgentCredential).filter(
        AgentCredential.endpoint_id == row.id).first()
    if cred:
        cred.revoked = True
    row.status = "revoked"
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="endpoint.revoked", target=row.agent_id))
    db.commit()
    return {"endpoint_id": row.id, "status": "revoked"}
