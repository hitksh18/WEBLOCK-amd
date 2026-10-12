"""Admin endpoints (admin role only, org-scoped, audited)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.dependencies import require_role
from app.db.database import get_db
from app.db.models import AuditLog, Incident, LoginEvent, User
from app.db.models import Session as UserSession
from app.db.models import User as UserModel

router = APIRouter(prefix="/admin", tags=["admin"])
admin_only = require_role("admin")


@router.get("/metrics")
def metrics(db: Session = Depends(get_db), current_user: UserModel = Depends(admin_only)):
    org = current_user.org_id
    return {
        "org_id": org,
        "total_logins": db.query(func.count(LoginEvent.id))
        .filter(LoginEvent.org_id == org).scalar(),
        "intruder_attempts": db.query(func.count(LoginEvent.id))
        .filter(LoginEvent.org_id == org,
                LoginEvent.classification == "Intruder").scalar(),
        "suspicious_attempts": db.query(func.count(LoginEvent.id))
        .filter(LoginEvent.org_id == org,
                LoginEvent.classification == "Suspicious").scalar(),
        "active_sessions": db.query(func.count(UserSession.id))
        .filter(UserSession.org_id == org,
                UserSession.status == "active").scalar(),
        "open_incidents": db.query(func.count(Incident.id))
        .filter(Incident.org_id == org, Incident.status == "open").scalar(),
        "blocked_users": db.query(func.count(User.id))
        .filter(User.org_id == org, User.is_blocked.is_(True)).scalar(),
    }


@router.post("/unblock-user/{user_id}")
def unblock_user(user_id: int, db: Session = Depends(get_db),
                 current_user: UserModel = Depends(admin_only)):
    target = (
        db.query(User)
        .filter(User.id == user_id, User.org_id == current_user.org_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found in organization")
    target.is_blocked = False
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="user.unblocked", target=target.email))
    db.commit()
    return {"message": f"User {user_id} unblocked"}


@router.get("/audit")
def audit_logs(limit: int = 50, db: Session = Depends(get_db),
               current_user: UserModel = Depends(admin_only)):
    limit = max(1, min(limit, 200))
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == current_user.org_id)
        .order_by(AuditLog.id.desc())
        .limit(limit)
        .all()
    )
    return [
        {"id": r.id, "action": r.action, "actor_id": r.actor_id,
         "target": r.target, "metadata": r.meta_data,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]
