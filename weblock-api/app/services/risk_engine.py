"""WebLock risk engine (Phase 0).

Preserves the scoring semantics of the original
weblock-api/services/risk_engine.py (policy checks + behavioral deltas),
but loads policy from the DB (org_policies) instead of a hardcoded JSON file.

Weights (unchanged from v4-policy-engine):
  disallowed country +40 | country mismatch +20 | unregistered device +35
  outside hours +30 | IP out of range +30 | new IP +15 | new device +15
  new geo +10 | high frequency (>=3 logins/2min) +20
Classification: <30 Genuine, <threshold Suspicious, >=threshold Intruder.
"""
import ipaddress
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db.models import LoginEvent, OrgPolicy

MODEL_VERSION = "v4-policy-engine-db"


def _parse_hhmm(value: str) -> tuple[int, int]:
    h, m = value.split(":")
    return int(h), int(m)


def is_within_allowed_hours(start: str, end: str, now: datetime) -> bool:
    sh, sm = _parse_hhmm(start)
    eh, em = _parse_hhmm(end)
    now_min = now.hour * 60 + now.minute
    s_min, e_min = sh * 60 + sm, eh * 60 + em
    if s_min <= e_min:
        return s_min <= now_min <= e_min
    return now_min >= s_min or now_min <= e_min


def ip_in_allowed_ranges(ip: str, ranges: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in ranges:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def get_policy(db: Session, org_id: int) -> OrgPolicy | None:
    return db.query(OrgPolicy).filter(OrgPolicy.org_id == org_id).first()


def calculate_risk(
    db: Session,
    *,
    org_id: int,
    user_id: int,
    ip_address: str,
    mac_address: str | None,
    device_fingerprint: str | None,
    geo_location: str | None,
    baseline_mac: str | None,
    baseline_country: str | None,
    role_name: str = "day_shift",
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    risk = 0
    factors: list[str] = []

    policy = get_policy(db, org_id)
    if policy is None:
        return {
            "risk_score": 100,
            "classification": "Intruder",
            "explanation": "No organization policy configured.",
            "confidence": 0.99,
            "model_version": MODEL_VERSION,
            "factors": ["Missing organization policy."],
        }

    roles: dict = policy.roles or {}
    role_policy: dict = roles.get(role_name, roles.get("day_shift", {}))
    allowed_countries: list[str] = policy.allowed_countries or []
    threshold: int = policy.risk_threshold or 75

    # 1. Country checks
    if geo_location and geo_location not in allowed_countries:
        risk += 40
        factors.append("Login from disallowed country.")
    if geo_location and baseline_country and geo_location != baseline_country:
        risk += 20
        factors.append("Country mismatch from baseline.")

    # 2. Device check
    if role_policy.get("require_registered_device", False):
        if baseline_mac and mac_address and mac_address != baseline_mac:
            risk += 35
            factors.append("Unregistered device detected.")

    # 3. Hours check
    hours = role_policy.get("allowed_hours")
    if hours and not is_within_allowed_hours(hours["start"], hours["end"], now):
        risk += 30
        factors.append("Login outside allowed working hours.")

    # 4. IP range check
    allowed_ranges = role_policy.get("allowed_ip_ranges", [])
    if allowed_ranges and not ip_in_allowed_ranges(ip_address, allowed_ranges):
        risk += 30
        factors.append("IP outside allowed range.")

    # 5. Behavioral deltas (last 5 events)
    history = (
        db.query(LoginEvent)
        .filter(LoginEvent.user_id == user_id, LoginEvent.org_id == org_id)
        .order_by(LoginEvent.id.desc())
        .limit(5)
        .all()
    )
    if history:
        known_ips = {e.ip_address for e in history}
        known_devices = {e.device_fingerprint for e in history}
        known_geos = {e.geo_location for e in history}
        if ip_address not in known_ips:
            risk += 15
            factors.append("New IP detected.")
        if device_fingerprint not in known_devices:
            risk += 15
            factors.append("New device fingerprint detected.")
        if geo_location not in known_geos:
            risk += 10
            factors.append("New location detected.")
        recent = [
            e for e in history
            if e.created_at and e.created_at.replace(tzinfo=timezone.utc)
            > now - timedelta(minutes=2)
        ]
        if len(recent) >= 3:
            risk += 20
            factors.append("High login frequency detected.")

    risk = min(risk, 100)
    if risk < 30:
        classification = "Genuine"
    elif risk < threshold:
        classification = "Suspicious"
    else:
        classification = "Intruder"

    return {
        "risk_score": risk,
        "classification": classification,
        "explanation": " | ".join(factors) if factors else "Normal behavior pattern.",
        "confidence": 0.92,
        "model_version": MODEL_VERSION,
        "factors": factors,
    }
