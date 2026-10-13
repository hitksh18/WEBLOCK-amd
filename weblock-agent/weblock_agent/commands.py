"""Response command validation + capability advertisement.

Validation is strict and local: unknown types, expired commands, endpoint
mismatch, malformed targets, and duplicates are rejected BEFORE anything
executes. No arbitrary commands exist in this module by construction —
_dispatch() only routes the allowlisted action set.
"""
import ipaddress
import logging
from datetime import datetime, timezone

logger = logging.getLogger("weblock-agent.commands")

SUPPORTED_ACTIONS = ("ISOLATE_ENDPOINT", "RESTORE_ISOLATION",
                     "TERMINATE_PROCESS", "BLOCK_NETWORK_DESTINATION",
                     "UNBLOCK_NETWORK_DESTINATION", "DISABLE_SESSION",
                     "COLLECT_EVIDENCE")
SUPPORTED_COLLECTIONS = ("PROCESS_LIST", "NETWORK_CONNECTIONS",
                         "WINDOWS_SECURITY_EVENTS", "SYSTEM_INFO",
                         "USB_DEVICES")


def advertise_capabilities() -> dict:
    """Real implemented capabilities. disable_session is NOT implemented."""
    import platform
    return {
        "isolate_endpoint": platform.system() == "Windows",
        "restore_isolation": platform.system() == "Windows",
        "terminate_process": True,
        "block_network_destination": platform.system() == "Windows",
        "disable_session": False,  # NOT_AVAILABLE: no safe session primitive
        "collect_evidence": True,
        "response_protocol": "1",
    }


def validate_command(cmd: dict, *, endpoint_id: int,
                     now: datetime | None = None) -> tuple[bool, str, dict]:
    """Return (ok, error_code, normalized_target). Never raises."""
    now = now or datetime.now(timezone.utc)
    if not isinstance(cmd, dict):
        return False, "MALFORMED_COMMAND", {}
    action = cmd.get("action_type")
    if action not in SUPPORTED_ACTIONS:
        return False, "UNKNOWN_ACTION", {}
    if not isinstance(cmd.get("command_id"), str) or not cmd["command_id"]:
        return False, "MALFORMED_COMMAND", {}
    try:
        expires = cmd.get("expires_at")
        exp = datetime.fromisoformat(expires) if expires else None
        if exp is not None:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                return False, "COMMAND_EXPIRED", {}
    except (ValueError, TypeError):
        return False, "MALFORMED_COMMAND", {}
    target = cmd.get("target")
    if not isinstance(target, dict):
        return False, "MALFORMED_TARGET", {}
    norm, err = _validate_target(action, target)
    if err:
        return False, err, {}
    return True, "", norm


def _validate_target(action: str, target: dict) -> tuple[dict, str]:
    if action in ("ISOLATE_ENDPOINT", "RESTORE_ISOLATION"):
        if target:
            return {}, "MALFORMED_TARGET"
        return {}, ""
    if action == "TERMINATE_PROCESS":
        pid = target.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return {}, "MALFORMED_TARGET"
        name = target.get("name", "")
        if not isinstance(name, str) or len(name) > 260:
            return {}, "MALFORMED_TARGET"
        return {"pid": pid, "name": name}, ""
    if action in ("BLOCK_NETWORK_DESTINATION", "UNBLOCK_NETWORK_DESTINATION"):
        ip = target.get("ip")
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except (ValueError, AttributeError):
            return {}, "MALFORMED_TARGET"
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return {}, "MALFORMED_TARGET"
        port = target.get("port")
        if port is not None and (not isinstance(port, int)
                                 or isinstance(port, bool)
                                 or not 1 <= port <= 65535):
            return {}, "MALFORMED_TARGET"
        out = {"ip": str(addr)}
        if port is not None:
            out["port"] = port
        return out, ""
    if action == "DISABLE_SESSION":
        username = target.get("username")
        if not isinstance(username, str) or not username.strip() \
                or len(username) > 256:
            return {}, "MALFORMED_TARGET"
        return {"username": username.strip()}, ""
    if action == "COLLECT_EVIDENCE":
        if target.get("collection_type") not in SUPPORTED_COLLECTIONS:
            return {}, "MALFORMED_TARGET"
        return {"collection_type": target["collection_type"]}, ""
    return {}, "UNKNOWN_ACTION"
