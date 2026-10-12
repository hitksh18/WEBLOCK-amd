"""POST /v1/analyze-login - temporary compatibility adapter.

Flow: validate -> resolve user (org-scoped) -> load DB policy -> calculate risk
-> store login event + risk assessment -> incident + evidence when required
-> audit. Deterministic, no fake data.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import (
    AuditLog,
    Evidence,
    Incident,
    LoginEvent,
    RiskAssessment,
    Session as UserSession,
    User,
)
from app.schemas.common import AnalyzeLoginRequest, AnalyzeLoginResponse
from app.services.risk_engine import calculate_risk

logger = logging.getLogger("weblock.login")
router = APIRouter(tags=["login"])

_SEVERITY_BY_CLASS = {"Suspicious": "medium", "Intruder": "high"}


def _incident_key(db: Session, org_id: int) -> str:
    year = datetime.now(timezone.utc).year
    count = db.query(Incident).filter(Incident.org_id == org_id).count() + 1
    return f"INC-{year}-{count:04d}"


@router.post("/analyze-login", response_model=AnalyzeLoginResponse)
def analyze_login(
    payload: AnalyzeLoginRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Resolve target user within caller's org (org isolation).
    target: User | None = None
    if payload.user_id is not None:
        target = (
            db.query(User)
            .filter(User.id == payload.user_id, User.org_id == current_user.org_id)
            .first()
        )
    elif payload.user_email is not None:
        target = (
            db.query(User)
            .filter(User.email == payload.user_email.lower(),
                    User.org_id == current_user.org_id)
            .first()
        )
    if target is None:
        raise HTTPException(status_code=404, detail="User not found in organization")
    if target.is_blocked:
        raise HTTPException(status_code=403, detail="Account is blocked")

    # Policy role: per-user override in org_policies.user_overrides, else default.
    from app.db.models import OrgPolicy as _OrgPolicy

    _pol = db.query(_OrgPolicy).filter(_OrgPolicy.org_id == target.org_id).first()
    _role_name = ((_pol.user_overrides or {}).get(str(target.id)) or {}).get(
        "role", "day_shift"
    )
    result = calculate_risk(
        db,
        org_id=target.org_id,
        user_id=target.id,
        ip_address=payload.ip_address,
        mac_address=payload.mac_address,
        device_fingerprint=payload.device_fingerprint,
        geo_location=payload.geo_location,
        baseline_mac=target.baseline_mac,
        baseline_country=target.baseline_country,
        role_name=_role_name,
    )

    try:
        event = LoginEvent(
            org_id=target.org_id,
            user_id=target.id,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            device_fingerprint=payload.device_fingerprint,
            geo_location=payload.geo_location,
            risk_score=int(result["risk_score"]),
            classification=result["classification"],
        )
        db.add(event)
        db.flush()  # event.id

        db.add(
            RiskAssessment(
                org_id=target.org_id,
                event_id=event.id,
                anomaly_score=float(result["risk_score"]),
                model_confidence=float(result.get("confidence", 1.0)),
                explanation=result["explanation"],
                model_version=result.get("model_version", "v4-policy-engine-db"),
                factors={"factors": result.get("factors", [])},
            )
        )

        incident_id: int | None = None
        incident_key: str | None = None

        if result["classification"] == "Genuine":
            db.add(UserSession(org_id=target.org_id, user_id=target.id,
                               status="active"))
        elif result["classification"] in ("Suspicious", "Intruder"):
            if result["classification"] == "Intruder":
                target.is_blocked = True
            incident_key = _incident_key(db, target.org_id)
            incident = Incident(
                org_id=target.org_id,
                incident_key=incident_key,
                title=f"{result['classification']} Login Detected",
                severity=_SEVERITY_BY_CLASS[result["classification"]],
                risk_score=int(result["risk_score"]),
                status="open",
                user_id=target.id,
                event_id=event.id,
                summary=result["explanation"],
            )
            db.add(incident)
            db.flush()
            incident_id = incident.id

            content = {
                "ip_address": payload.ip_address,
                "mac_address": payload.mac_address,
                "device_fingerprint": payload.device_fingerprint,
                "geo_location": payload.geo_location,
                "risk_score": result["risk_score"],
                "classification": result["classification"],
                "event_id": event.id,
            }
            digest = hashlib.sha256(
                json.dumps(content, sort_keys=True, default=str).encode()
            ).hexdigest()
            db.add(
                Evidence(
                    org_id=target.org_id,
                    incident_id=incident.id,
                    source="login",
                    content=content,
                    sha256=digest,
                    collector="weblock-server",
                    chain_of_custody={
                        "collected_by": f"user:{current_user.id}",
                        "event_id": event.id,
                    },
                )
            )
            db.add(
                AuditLog(
                    org_id=target.org_id,
                    actor_id=current_user.id,
                    action="incident.created",
                    target=incident_key,
                    meta_data={"classification": result["classification"]},
                )
            )
            # Auto-escalation: 3+ Suspicious in 5 min -> block (preserved semantics).
            if result["classification"] == "Suspicious":
                from datetime import timedelta

                from app.core.timeutil import as_utc

                cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                recent = (
                    db.query(LoginEvent)
                    .filter(LoginEvent.user_id == target.id)
                    .order_by(LoginEvent.id.desc())
                    .limit(10)
                    .all()
                )
                recent_susp = sum(
                    1 for e in recent
                    if e.classification == "Suspicious"
                    and e.created_at
                    and as_utc(e.created_at) > cutoff
                )
                if recent_susp >= 3:
                    target.is_blocked = True
                    db.add(
                        AuditLog(
                            org_id=target.org_id,
                            actor_id=current_user.id,
                            action="user.auto_blocked",
                            target=target.email,
                            meta_data={                            "reason": "3+ suspicious in 5 min"},
                        )
                    )

        db.add(
            AuditLog(
                org_id=target.org_id,
                actor_id=current_user.id,
                action="login.analyzed",
                target=target.email,
                meta_data={"classification": result["classification"],
                           "risk": result["risk_score"]},
            )
        )
        db.commit()
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("analyze-login failed")
        raise HTTPException(status_code=500, detail="Analysis failed")

    return AnalyzeLoginResponse(
        event_id=event.id,
        incident_id=incident_id,
        incident_key=incident_key,
        risk_score=result["risk_score"],
        classification=result["classification"],
        confidence=result.get("confidence", 1.0),
        explanation=result["explanation"],
        factors=result.get("factors", []),
    )
