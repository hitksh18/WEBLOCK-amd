"""Phase 8 policy engine: deterministic, server-side, fail-closed.

Role matrix (existing RBAC names):
  admin:        all actions, SIMULATION + LIVE
  analyst:      SIMULATION all; LIVE all except DISABLE_SESSION
  investigator: SIMULATION all; LIVE COLLECT_EVIDENCE only
  viewer:       nothing (read APIs only)

LIVE additionally requires: endpoint owned + enrolled + credential valid +
fresh heartbeat (<5 min) + advertised capability + valid target + limits.
SIMULATION runs full policy but never touches the endpoint.
"""
import hashlib
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import AgentCredential, Endpoint, Incident, User

logger = logging.getLogger("weblock.policy")

ACTION_TYPES = ("ISOLATE_ENDPOINT", "RESTORE_ISOLATION", "TERMINATE_PROCESS",
                "BLOCK_NETWORK_DESTINATION", "UNBLOCK_NETWORK_DESTINATION",
                "DISABLE_SESSION", "COLLECT_EVIDENCE")
COLLECTION_TYPES = ("PROCESS_LIST", "NETWORK_CONNECTIONS",
                    "WINDOWS_SECURITY_EVENTS", "SYSTEM_INFO", "USB_DEVICES")
HEARTBEAT_FRESH_SECONDS = 300
MAX_OPEN_PER_INCIDENT = 20
MAX_QUEUED_PER_ENDPOINT = 5

# action -> capability key the agent must advertise (None = always routable;
# DISABLE_SESSION has no live implementation -> capability false by design).
ACTION_CAPABILITY = {
    "ISOLATE_ENDPOINT": "isolate_endpoint",
    "RESTORE_ISOLATION": "restore_isolation",
    "TERMINATE_PROCESS": "terminate_process",
    "BLOCK_NETWORK_DESTINATION": "block_network_destination",
    "UNBLOCK_NETWORK_DESTINATION": "block_network_destination",
    "DISABLE_SESSION": "disable_session",
    "COLLECT_EVIDENCE": "collect_evidence",
}

LIVE_ALLOW = {
    "admin": set(ACTION_TYPES),
    "analyst": set(ACTION_TYPES) - {"DISABLE_SESSION"},
    "investigator": {"COLLECT_EVIDENCE"},
    "viewer": set(),
}


def _canonical_target(action_type: str, target: dict) -> dict:
    """Validate + normalize target. Raises ValueError with safe reason."""
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    if action_type in ("ISOLATE_ENDPOINT", "RESTORE_ISOLATION"):
        if target:
            raise ValueError("this action takes no target")
        return {}
    if action_type == "TERMINATE_PROCESS":
        pid = target.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ValueError("target.pid must be a positive integer")
        name = target.get("name", "")
        if name is not None and not isinstance(name, str):
            raise ValueError("target.name must be a string")
        if len(name) > 260:
            raise ValueError("target.name too long")
        return {"pid": pid, "name": (name or "")[:260]}
    if action_type in ("BLOCK_NETWORK_DESTINATION",
                       "UNBLOCK_NETWORK_DESTINATION"):
        ip = target.get("ip")
        if not isinstance(ip, str):
            raise ValueError("target.ip must be a string")
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise ValueError("target.ip is not a valid IPv4/IPv6 address")
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            raise ValueError("target.ip must be a routable address")
        port = target.get("port")
        if port is not None and (
                not isinstance(port, int) or isinstance(port, bool)
                or not 1 <= port <= 65535):
            raise ValueError("target.port must be 1-65535")
        out = {"ip": str(addr)}
        if port is not None:
            out["port"] = port
        return out
    if action_type == "DISABLE_SESSION":
        username = target.get("username")
        if not isinstance(username, str) or not username.strip():
            raise ValueError("target.username must be a non-empty string")
        if len(username) > 256:
            raise ValueError("target.username too long")
        return {"username": username.strip()[:256]}
    if action_type == "COLLECT_EVIDENCE":
        ctype = target.get("collection_type")
        if ctype not in COLLECTION_TYPES:
            raise ValueError(
                f"collection_type must be one of {', '.join(COLLECTION_TYPES)}")
        return {"collection_type": ctype}
    raise ValueError(f"Unsupported action_type: {action_type}")


def idempotency_key(org_id: int, incident_id: int, endpoint_id: int,
                    action_type: str, target: dict, mode: str) -> str:
    canonical = json.dumps({"o": org_id, "i": incident_id, "e": endpoint_id,
                            "a": action_type, "t": target, "m": mode},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def evaluate_policy(db: Session, *, user: User, incident: Incident,
                    endpoint: Endpoint, action_type: str, target: dict,
                    mode: str) -> tuple[bool, dict, dict]:
    """Return (allowed, normalized_target, decision).

    decision = {allowed, checks: [{name, ok, code}], evaluated_at}.
    Never raises on policy grounds (target schema errors raise ValueError).
    """
    checks: list[dict] = []

    def check(name: str, ok: bool, code: str) -> bool:
        checks.append({"name": name, "ok": ok, "code": code if not ok else "OK"})
        return ok

    if action_type not in ACTION_TYPES:
        raise ValueError(f"Unsupported action_type: {action_type}")
    if mode not in ("SIMULATION", "LIVE"):
        raise ValueError("execution_mode must be SIMULATION or LIVE")
    normalized = _canonical_target(action_type, target)

    role_ok = action_type in LIVE_ALLOW.get(user.role, set())
    # SIMULATION is harmless: any non-viewer role may simulate anything.
    if mode == "SIMULATION":
        role_ok = user.role in ("admin", "analyst", "investigator")
    check("role", role_ok,
          f"role '{user.role}' may not request {action_type} in {mode} mode")
    check("incident_org", incident.org_id == user.org_id, "INCIDENT_ORG_MISMATCH")
    check("endpoint_org", endpoint.org_id == user.org_id, "ENDPOINT_ORG_MISMATCH")
    check("incident_endpoint",
          incident.endpoint_id is not None and
          incident.endpoint_id == endpoint.id,
          "INCIDENT_ENDPOINT_MISMATCH")
    check("incident_open", incident.status not in ("closed", "resolved"),
          "INCIDENT_CLOSED")

    if mode == "LIVE":
        cred = db.query(AgentCredential).filter(
            AgentCredential.endpoint_id == endpoint.id,
            AgentCredential.revoked.is_(False)).first()
        check("endpoint_enrolled", cred is not None, "NO_VALID_CREDENTIAL")
        check("endpoint_not_revoked", endpoint.status != "revoked",
              "ENDPOINT_REVOKED")
        fresh = (endpoint.last_seen is not None
                 and (datetime.now(timezone.utc)
                      - as_utc(endpoint.last_seen)).total_seconds()
                 <= HEARTBEAT_FRESH_SECONDS)
        check("endpoint_fresh", fresh, "HEARTBEAT_STALE")
        cap_key = ACTION_CAPABILITY.get(action_type)
        caps = endpoint.capabilities or {}
        check("capability", bool(cap_key and caps.get(cap_key) is True),
              "CAPABILITY_UNSUPPORTED")
        from app.db.models import ResponseAction
        open_inc = db.query(ResponseAction).filter(
            ResponseAction.org_id == user.org_id,
            ResponseAction.incident_id == incident.id,
            ResponseAction.status.notin_(
                ("SUCCEEDED", "FAILED", "EXPIRED", "CANCELLED",
                 "POLICY_DENIED"))).count()
        check("incident_limit", open_inc < MAX_OPEN_PER_INCIDENT,
              "TOO_MANY_OPEN_ACTIONS")
        queued_ep = db.query(ResponseAction).filter(
            ResponseAction.org_id == user.org_id,
            ResponseAction.endpoint_id == endpoint.id,
            ResponseAction.status.in_(("QUEUED", "ACCEPTED"))).count()
        check("endpoint_limit", queued_ep < MAX_QUEUED_PER_ENDPOINT,
              "ENDPOINT_QUEUE_FULL")

    allowed = all(c["ok"] for c in checks)
    decision = {"allowed": allowed, "checks": checks,
                "evaluated_at": datetime.now(timezone.utc).isoformat()}
    return allowed, normalized, decision
