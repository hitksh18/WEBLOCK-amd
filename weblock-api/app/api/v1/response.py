"""Phase 8 response APIs.

User JWT (RBAC): request/list/get/cancel/retry response actions.
Agent key: pending command pull + result posts (existing trust channel).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.agent_auth import get_current_endpoint
from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import Endpoint, Incident, ResponseAction, User
from app.services import response as response_service

router = APIRouter(tags=["response"])
MAX_LIMIT = 200


class ActionRequest(BaseModel):
    action_type: str = Field(max_length=32)
    target: dict = Field(default_factory=dict)
    reason: str = Field(default="", max_length=1000)
    execution_mode: str = Field(default="SIMULATION", max_length=16)
    ttl_seconds: int = Field(default=600, ge=60, le=3600)


class ResultPost(BaseModel):
    status: str = Field(max_length=16)
    result: dict = Field(default_factory=dict)
    error_code: str = Field(default="", max_length=64)
    error_message: str = Field(default="", max_length=1000)


def _action_out(a: ResponseAction) -> dict:
    return {
        "id": a.id, "incident_id": a.incident_id, "endpoint_id": a.endpoint_id,
        "action_type": a.action_type, "target": a.target,
        "execution_mode": a.execution_mode, "status": a.status,
        "policy_decision": a.policy_decision, "attempt": a.attempt,
        "result": a.result, "error_code": a.error_code,
        "error_message": a.error_message,
        "requested_by": a.requested_by,
        "requested_at": a.requested_at.isoformat() if a.requested_at else None,
        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
    }


def _scoped_incident_endpoint(db: Session, user: User, incident_id: int,
                              endpoint_id: int | None = None):
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.org_id == user.org_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    query = db.query(Endpoint).filter(Endpoint.org_id == user.org_id)
    endpoint = None
    if endpoint_id is not None:
        endpoint = query.filter(Endpoint.id == endpoint_id).first()
        if endpoint is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")
    elif incident.endpoint_id is not None:
        endpoint = query.filter(Endpoint.id == incident.endpoint_id).first()
    if endpoint is None:
        raise HTTPException(
            status_code=422,
            detail="Incident has no linked endpoint; pass endpoint_id")
    return incident, endpoint


@router.post("/incidents/{incident_id}/response-actions")
def request_response_action(
    incident_id: int, payload: ActionRequest,
    endpoint_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst",
                                              "investigator")),
):
    incident, endpoint = _scoped_incident_endpoint(
        db, current_user, incident_id, endpoint_id)
    try:
        row = response_service.request_action(
            db, user=current_user, incident=incident, endpoint=endpoint,
            action_type=payload.action_type, target=payload.target,
            reason=payload.reason, mode=payload.execution_mode.upper(),
            ttl_seconds=payload.ttl_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _action_out(row)


@router.get("/incidents/{incident_id}/response-actions")
def list_response_actions(
    incident_id: int,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.org_id == current_user.org_id
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    q = db.query(ResponseAction).filter(
        ResponseAction.org_id == current_user.org_id,
        ResponseAction.incident_id == incident_id)
    if status:
        q = q.filter(ResponseAction.status == status)
    total = q.count()
    rows = q.order_by(ResponseAction.id.desc()).offset(offset).limit(limit).all()
    return {"total": total, "actions": [_action_out(a) for a in rows]}


@router.get("/response-actions/{action_id}")
def get_response_action(
    action_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = db.query(ResponseAction).filter(
        ResponseAction.id == action_id,
        ResponseAction.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    return _action_out(row)


@router.post("/response-actions/{action_id}/cancel")
def cancel_response_action(
    action_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst",
                                              "investigator")),
):
    row = db.query(ResponseAction).filter(
        ResponseAction.id == action_id,
        ResponseAction.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    try:
        row = response_service.cancel_action(db, user=current_user, action=row)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _action_out(row)


@router.post("/response-actions/{action_id}/retry")
def retry_response_action(
    action_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
):
    row = db.query(ResponseAction).filter(
        ResponseAction.id == action_id,
        ResponseAction.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    try:
        row = response_service.retry_action(db, user=current_user, action=row)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _action_out(row)


@router.get("/endpoints/{endpoint_id}/capabilities")
def endpoint_capabilities(
    endpoint_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == endpoint_id,
        Endpoint.org_id == current_user.org_id).first()
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"endpoint_id": endpoint.id, "agent_id": endpoint.agent_id,
            "agent_version": endpoint.agent_version,
            "capabilities": endpoint.capabilities or {}}


# ------------------------------------------------------- agent command plane
@router.get("/endpoints/{endpoint_id}/commands/pending")
def pending_commands(
    endpoint_id: int, db: Session = Depends(get_db),
    endpoint: Endpoint = Depends(get_current_endpoint),
):
    if endpoint.id != endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint_id mismatch")
    return {"endpoint_id": endpoint.id,
            "commands": response_service.pending_commands(db, endpoint)}


@router.post("/endpoints/{endpoint_id}/commands/{command_id}/result")
def command_result(
    endpoint_id: int, command_id: str, payload: ResultPost,
    db: Session = Depends(get_db),
    endpoint: Endpoint = Depends(get_current_endpoint),
):
    if endpoint.id != endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint_id mismatch")
    try:
        action = response_service.submit_result(
            db, endpoint=endpoint, command_id=command_id,
            status=payload.status.upper(), result=payload.result,
            error_code=payload.error_code,
            error_message=payload.error_message)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _action_out(action)
