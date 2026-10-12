"""Login-risk adapter (Phase 2): bridge normalized auth events -> risk engine.

POST /v1/analyze-login is RETAINED as the compatibility endpoint (Phase 0
behavior and risk scores unchanged). This module converts a normalized
AUTHENTICATION security event into the same input shape the risk engine
consumes, so Phase 4/5 can feed agent 4624/4625 telemetry through the
common pipeline instead of a side channel.

What maps today: IP/MAC/fingerprint/geo pass through when the agent payload
carries them; user resolution (actor name -> user row) is intentionally left
to Phase 4 identity work and is documented, not faked.
"""
from app.db.models import SecurityEvent


def auth_event_to_login_input(event: SecurityEvent) -> dict | None:
    """Return risk-engine input dict, or None if the event is not logon-like."""
    if event.category != "AUTHENTICATION":
        return None
    if event.subtype not in ("LOGON_SUCCESS", "LOGON_FAILURE", "SESSION_SNAPSHOT",
                             "LOGON", "LOGOFF"):
        return None
    attrs = event.attributes or {}
    return {
        "user_hint": event.actor or None,  # resolved to a user row in Phase 4
        "ip_address": attrs.get("ip_address"),
        "mac_address": attrs.get("mac_address"),
        "device_fingerprint": attrs.get("device_fingerprint"),
        "geo_location": attrs.get("geo_location"),
        "source_event_id": event.id,
        "source_telemetry_event": event.event_id,
        "subtype": event.subtype,
    }
