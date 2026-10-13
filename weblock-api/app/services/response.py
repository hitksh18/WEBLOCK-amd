"""Phase 8 response lifecycle: request -> policy -> queue -> dispatch ->
agent result -> terminal state. Simulation completes server-side with an
explicit simulated result and never creates a command row.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import (
    AgentCommand,
    AuditLog,
    Endpoint,
    Incident,
    ResponseAction,
    User,
)
from app.services.response_policy import evaluate_policy, idempotency_key

logger = logging.getLogger("weblock.response")

COMMAND_TTL_SECONDS = 600
RESULT_MAX_BYTES = 16 * 1024
TERMINAL = ("SUCCEEDED", "FAILED", "EXPIRED", "CANCELLED", "POLICY_DENIED")


def _audit(db: Session, *, org_id: int, actor_id: int | None, action: str,
           action_row: ResponseAction | None = None,
           extra: dict | None = None) -> None:
    meta = {"action_id": action_row.id if action_row else None,
            "incident_id": action_row.incident_id if action_row else None,
            "endpoint_id": action_row.endpoint_id if action_row else None,
            "action_type": action_row.action_type if action_row else None,
            "status": action_row.status if action_row else None}
    if extra:
        meta.update(extra)
    db.add(AuditLog(
        org_id=org_id, actor_id=actor_id, action=action,
        target=f"response-action:{action_row.id}" if action_row else "response",
        meta_data=meta))


def _transition(db: Session, row: ResponseAction, status: str,
                *, user: User, error_code: str = "",
                error_message: str = "") -> None:
    row.status = status
    if error_code:
        row.error_code = error_code[:64]
    if error_message:
        row.error_message = error_message[:1000]
    db.flush()
    _audit(db, org_id=row.org_id, actor_id=user.id if user else None,
           action=f"response.{status.lower()}", action_row=row)


def request_action(db: Session, *, user: User, incident: Incident,
                   endpoint: Endpoint, action_type: str, target: dict,
                   reason: str = "", mode: str = "SIMULATION",
                   ttl_seconds: int = COMMAND_TTL_SECONDS) -> ResponseAction:
    """Full request path: validate -> policy -> persist -> (simulate|queue)."""
    if not 60 <= int(ttl_seconds) <= 3600:
        raise ValueError("ttl_seconds must be 60-3600")
    allowed, normalized, decision = evaluate_policy(
        db, user=user, incident=incident, endpoint=endpoint,
        action_type=action_type, target=target, mode=mode)
    key = idempotency_key(user.org_id, incident.id, endpoint.id,
                          action_type, normalized, mode)
    # Idempotent replay: same non-terminal request returns the existing row.
    existing = (
        db.query(ResponseAction)
        .filter(ResponseAction.org_id == user.org_id,
                ResponseAction.idempotency_key == key,
                ResponseAction.status.notin_(TERMINAL))
        .order_by(ResponseAction.id.desc())
        .first()
    )
    if existing is not None:
        logger.info("response replay -> action %s", existing.id)
        return existing

    row = ResponseAction(
        org_id=user.org_id, incident_id=incident.id,
        endpoint_id=endpoint.id, action_type=action_type,
        requested_by=user.id, target=normalized, reason=(reason or "")[:1000],
        execution_mode=mode, status="REQUESTED", policy_decision=decision,
        idempotency_key=key,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=int(ttl_seconds)))
    db.add(row)
    db.flush()
    _audit(db, org_id=user.org_id, actor_id=user.id,
           action="response.requested", action_row=row,
           extra={"mode": mode, "reason": (reason or "")[:200]})

    if not allowed:
        failed = next((c for c in decision["checks"] if not c["ok"]), {})
        _transition(db, row, "POLICY_DENIED", user=user,
                    error_code=failed.get("code", "POLICY_DENIED"),
                    error_message=f"Policy denied: {failed.get('name', '?')}")
        db.commit()
        return row

    if mode == "SIMULATION":
        row.result = {
            "simulated": True,
            "executed_on_endpoint": False,
            "would_execute": {
                "action_type": action_type, "target": normalized,
                "endpoint_id": endpoint.id, "agent_id": endpoint.agent_id},
            "note": "Simulation only: full policy evaluated, "
                    "no endpoint action executed.",
        }
        _transition(db, row, "SUCCEEDED", user=user)
        db.commit()
        return row

    # LIVE: queue + dispatch command row.
    _transition(db, row, "QUEUED", user=user)
    command = AgentCommand(
        org_id=user.org_id, response_action_id=row.id,
        command_id=uuid.uuid4().hex, endpoint_id=endpoint.id,
        action_type=action_type, target=normalized, execution_mode="LIVE",
        status="PENDING",
        expires_at=min(row.expires_at,
                       datetime.now(timezone.utc) + timedelta(
                           seconds=COMMAND_TTL_SECONDS)))
    db.add(command)
    db.flush()
    _audit(db, org_id=user.org_id, actor_id=user.id,
           action="response.dispatched", action_row=row,
           extra={"command_id": command.command_id})
    db.commit()
    return row


def pending_commands(db: Session, endpoint: Endpoint,
                     limit: int = 5, mark: bool = True) -> list[dict]:
    """Agent pull: unexpired PENDING commands.

    mark=True (explicit pull): rows become DELIVERED and their actions
    ACCEPTED. mark=False (heartbeat peek): read-only list so heartbeats
    never consume commands the agent has not actually picked up.
    """
    expire_stale(db, endpoint.org_id)
    # PENDING (never picked up) + DELIVERED without result (pickup never
    # completed, e.g. agent died mid-execution). Re-delivery is safe: the
    # agent ledger dedups by command_id and re-reports stored outcomes.
    rows = (
        db.query(AgentCommand)
        .filter(AgentCommand.endpoint_id == endpoint.id,
                AgentCommand.status.in_(("PENDING", "DELIVERED")),
                AgentCommand.expires_at > datetime.now(timezone.utc))
        .order_by(AgentCommand.id.asc())
        .limit(limit)
        .all()
    )
    out = []
    for cmd in rows:
        if mark:
            cmd.status = "DELIVERED"
            action = db.query(ResponseAction).filter(
                ResponseAction.id == cmd.response_action_id).first()
            if action is not None and action.status == "QUEUED":
                action.status = "ACCEPTED"
                _audit(db, org_id=cmd.org_id, actor_id=None,
                       action="response.accepted", action_row=action,
                       extra={"command_id": cmd.command_id})
        out.append({
            "command_id": cmd.command_id,
            "response_action_id": cmd.response_action_id,
            "action_type": cmd.action_type,
            "target": cmd.target,
            "execution_mode": cmd.execution_mode,
            "issued_at": cmd.issued_at.isoformat() if cmd.issued_at else None,
            "expires_at": cmd.expires_at.isoformat() if cmd.expires_at else None,
        })
    db.commit()
    return out


def submit_result(db: Session, *, endpoint: Endpoint, command_id: str,
                  status: str, result: dict | None = None,
                  error_code: str = "", error_message: str = "") -> ResponseAction:
    """Agent result post: validates ownership/expiry/size, closes the loop."""
    import json as _json
    if status not in ("SUCCEEDED", "FAILED"):
        raise ValueError("result status must be SUCCEEDED or FAILED")
    if result is not None and len(_json.dumps(result, default=str).encode()) > RESULT_MAX_BYTES:
        raise ValueError("result payload too large")
    cmd = (
        db.query(AgentCommand)
        .filter(AgentCommand.command_id == command_id,
                AgentCommand.endpoint_id == endpoint.id)
        .first()
    )
    if cmd is None:
        raise LookupError("Unknown command for this endpoint")
    if cmd.status == "RESULT_RECEIVED":
        # Duplicate delivery: return current action state (idempotent).
        action = db.query(ResponseAction).filter(
            ResponseAction.id == cmd.response_action_id).first()
        return action
    if as_utc(cmd.expires_at) < datetime.now(timezone.utc):
        cmd.status = "EXPIRED"
        action = db.query(ResponseAction).filter(
            ResponseAction.id == cmd.response_action_id).first()
        if action is not None and action.status not in TERMINAL:
            action.status = "EXPIRED"
            _audit(db, org_id=cmd.org_id, actor_id=None,
                   action="response.expired", action_row=action)
        db.commit()
        raise ValueError("Command expired")
    cmd.status = "RESULT_RECEIVED"
    cmd.result = result or {}
    action = db.query(ResponseAction).filter(
        ResponseAction.id == cmd.response_action_id).first()
    action.status = status
    action.result = {"agent_reported": dict(result or {}),
                     "command_id": command_id}
    if error_code:
        action.error_code = error_code[:64]
    if error_message:
        action.error_message = error_message[:1000]
    _audit(db, org_id=cmd.org_id, actor_id=None,
           action=f"response.{status.lower()}", action_row=action,
           extra={"command_id": command_id})
    _apply_effects(db, action, cmd)
    db.commit()
    return action


def _apply_effects(db: Session, action: ResponseAction,
                   cmd: AgentCommand) -> None:
    """Server-side effects of terminal results (no endpoint I/O here)."""
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == action.endpoint_id).first()
    if endpoint is None or action.status != "SUCCEEDED":
        return
    if action.action_type == "ISOLATE_ENDPOINT":
        endpoint.status = "isolated"
    elif action.action_type == "RESTORE_ISOLATION":
        if endpoint.status == "isolated":
            endpoint.status = "healthy"
    elif action.action_type == "COLLECT_EVIDENCE":
        _link_collected_evidence(db, action)


def _link_collected_evidence(db: Session, action: ResponseAction) -> None:
    """Turn a COLLECT result summary into a Phase 7 evidence reference."""
    from app.services.evidence import add_custody, collect_evidence
    summary = (action.result or {}).get("agent_reported", {})
    if not isinstance(summary, dict) or not summary.get("collected"):
        return
    try:
        row = EvidenceRef.create(
            db, org_id=action.org_id, incident_id=action.incident_id,
            correlation_id=None, source_type="RESPONSE_RESULT",
            content_ref={"response_action_id": action.id,
                         "command_id": action.result.get("command_id"),
                         "collection": summary},
            actor_name="weblock-server",
            description=f"Response collection {action.action_type}")
    except (LookupError, ValueError):
        logger.exception("collect-evidence linkage failed")
        return
    add_custody(db, org_id=action.org_id, evidence_id=row.id,
                action="COLLECTED", actor_user_id=action.requested_by,
                meta={"response_action_id": action.id})


class EvidenceRef:
    """Tiny adapter: build an Evidence row without a live source record."""

    @staticmethod
    def create(db: Session, *, org_id: int, incident_id: int,
               correlation_id, source_type: str, content_ref: dict,
               actor_name: str, description: str):
        import hashlib as _hl
        import json as _json
        from app.db.models import Evidence, Incident
        incident = db.query(Incident).filter(
            Incident.id == incident_id, Incident.org_id == org_id).first()
        if incident is None:
            raise LookupError("Incident not found")
        content = {"source_type": source_type, "reference": content_ref}
        digest = _hl.sha256(_json.dumps(
            content, sort_keys=True, separators=(",", ":"),
            default=str).encode()).hexdigest()
        row = Evidence(org_id=org_id, incident_id=incident_id,
                       correlation_id=correlation_id, source="response",
                       source_type=source_type, source_id=None,
                       content=content, sha256=digest,
                       collector="weblock-server", collected_by=actor_name,
                       chain_of_custody={"collected_by": actor_name},
                       integrity_status="UNVERIFIED", description=description,
                       meta={})
        db.add(row)
        db.flush()
        return row


def cancel_action(db: Session, *, user: User,
                  action: ResponseAction) -> ResponseAction:
    if action.status not in ("QUEUED", "ACCEPTED", "REQUESTED"):
        raise ValueError("Only queued/accepted actions can be cancelled")
    action.status = "CANCELLED"
    _audit(db, org_id=action.org_id, actor_id=user.id,
           action="response.cancelled", action_row=action)
    db.commit()
    return action


def retry_action(db: Session, *, user: User,
                 action: ResponseAction) -> ResponseAction:
    """New command attempt on the same action (bounded)."""
    from app.db.models import Incident as IncidentModel
    if action.status not in ("FAILED", "EXPIRED"):
        raise ValueError("Only failed/expired actions can be retried")
    if action.execution_mode != "LIVE":
        raise ValueError("Only LIVE actions can be retried")
    if action.attempt + 1 >= action.max_attempts:
        raise ValueError("Retry budget exhausted")
    incident = db.query(IncidentModel).filter(
        IncidentModel.id == action.incident_id).first()
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == action.endpoint_id).first()
    allowed, _norm, decision = evaluate_policy(
        db, user=user, incident=incident, endpoint=endpoint,
        action_type=action.action_type, target=action.target, mode="LIVE")
    action.policy_decision = decision
    if not allowed:
        action.status = "POLICY_DENIED"
        _audit(db, org_id=action.org_id, actor_id=user.id,
               action="response.denied", action_row=action)
        db.commit()
        return action
    action.attempt += 1
    action.status = "QUEUED"
    action.error_code = ""
    action.error_message = ""
    command = AgentCommand(
        org_id=action.org_id, response_action_id=action.id,
        command_id=uuid.uuid4().hex,
        endpoint_id=action.endpoint_id, action_type=action.action_type,
        target=action.target, execution_mode="LIVE", status="PENDING",
        expires_at=datetime.now(timezone.utc) + timedelta(
            seconds=COMMAND_TTL_SECONDS))
    db.add(command)
    db.flush()
    _audit(db, org_id=action.org_id, actor_id=user.id,
           action="response.retried", action_row=action,
           extra={"command_id": command.command_id, "attempt": action.attempt})
    db.commit()
    return action


def expire_stale(db: Session, org_id: int) -> int:
    """Mark QUEUED/ACCEPTED actions and PENDING commands past expiry."""
    now = datetime.now(timezone.utc)
    n = 0
    for action in (
        db.query(ResponseAction)
        .filter(ResponseAction.org_id == org_id,
                ResponseAction.status.in_(("QUEUED", "ACCEPTED")),
                ResponseAction.expires_at < now)
        .all()
    ):
        action.status = "EXPIRED"
        _audit(db, org_id=org_id, actor_id=None,
               action="response.expired", action_row=action)
        n += 1
    for cmd in (
        db.query(AgentCommand)
        .filter(AgentCommand.org_id == org_id,
                AgentCommand.status.in_(("PENDING", "DELIVERED")),
                AgentCommand.expires_at < now)
        .all()
    ):
        cmd.status = "EXPIRED"
        n += 1
    if n:
        db.commit()
    return n
