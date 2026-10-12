"""Deterministic normalization: raw telemetry -> SecurityEvent fields.

Same raw event ALWAYS yields the same normalized representation
(norm_version "1"). Unknown kinds fall back to TYPE/RAW_SUBTYPE so no event
is ever silently dropped. Raw payload is never mutated — detail stays in
telemetry_events.payload; queryable facets are extracted here.
"""
from datetime import datetime, timezone

NORM_VERSION = "1"

# Windows Security event IDs -> (category, subtype, severity_hint)
WIN_SECURITY = {
    4624: ("AUTHENTICATION", "LOGON_SUCCESS", "info"),
    4625: ("AUTHENTICATION", "LOGON_FAILURE", "low"),
    4634: ("AUTHENTICATION", "LOGOFF", "info"),
    4647: ("AUTHENTICATION", "LOGOFF", "info"),
    4672: ("AUTHENTICATION", "PRIVILEGED_LOGON", "low"),
    4720: ("IDENTITY", "ACCOUNT_CREATED", "medium"),
}

# (telemetry type, payload kind) -> (category, subtype, severity_hint)
KIND_MAP = {
    ("auth", "session_snapshot"): ("AUTHENTICATION", "SESSION_SNAPSHOT", "info"),
    ("auth", "collector_status"): ("AGENT", "COLLECTOR_STATUS", "info"),
    ("process", "snapshot"): ("PROCESS", "PROCESS_SNAPSHOT", "info"),
    ("network", "snapshot"): ("NETWORK", "CONNECTION_ROLLUP", "info"),
    ("system", "health"): ("SYSTEM", "SYSTEM_STATUS", "info"),
    ("system", "service_snapshot"): ("SYSTEM", "SERVICE_SNAPSHOT", "info"),
    ("usb", "volume_snapshot"): ("USB", "VOLUME_SNAPSHOT", "info"),
    ("usb", "usb_device_seen"): ("USB", "DEVICE_CHANGE", "low"),
    ("heartbeat", "heartbeat"): ("AGENT", "HEARTBEAT", "info"),
}


def _strings(payload: dict, key: str, limit: int = 8) -> list[str]:
    values = payload.get(key)
    if not isinstance(values, list):
        return []
    return [str(v)[:256] for v in values[:limit]]


def normalize(telemetry_type: str, payload: dict, occurred_at: datetime,
              host: str = "") -> dict:
    """Return normalized field dict (no DB access; pure + deterministic)."""
    kind = payload.get("kind", "")
    category, subtype, severity = KIND_MAP.get(
        (telemetry_type, kind), (telemetry_type.upper() or "UNKNOWN", "RAW", "info"))

    out = {
        "category": category,
        "subtype": subtype,
        "severity_hint": severity,
        "actor": "",
        "host": host,
        "proc_name": "",
        "proc_pid": None,
        "proc_exe": "",
        "remote_addr": "",
        "remote_port": None,
        "attributes": {},
    }

    if telemetry_type == "auth" and kind == "windows_security_event":
        try:
            eid = int(payload.get("event_id", 0))
        except (TypeError, ValueError):
            eid = 0
        category, subtype, severity = WIN_SECURITY.get(
            eid, ("AUTHENTICATION", f"WIN_EVENT_{eid}", "info"))
        out.update(category=category, subtype=subtype, severity_hint=severity)
        strings = _strings(payload, "strings", 12)
        out["attributes"] = {
            "windows_event_id": eid,
            "record_number": payload.get("record_number"),
            "event_source": payload.get("source", ""),
            "strings": strings,
        }
        # 4625 strings: [.., account, domain, ..]; 4624 similar. Best-effort:
        if len(strings) >= 2:
            out["actor"] = strings[1][:255] if " " not in strings[1] else ""
    elif telemetry_type == "auth" and kind == "session_snapshot":
        out["actor"] = str(payload.get("user", ""))[:255]
        out["host"] = str(payload.get("host", "") or host)[:255]
    elif telemetry_type == "process":
        procs = payload.get("processes", [])
        names = sorted({str(p.get("name", "")) for p in procs if p.get("name")})
        out["attributes"] = {
            "process_count": len(procs),
            "skipped": payload.get("skipped", 0),
            "process_names": names[:100],
        }
        if names:
            out["proc_name"] = names[0][:255]
    elif telemetry_type == "network":
        conns = payload.get("connections", [])
        remotes = sorted({str(c.get("remote", "")) for c in conns if c.get("remote")})
        out["attributes"] = {
            "connection_count": len(conns),
            "remotes": remotes[:100],
            "truncated": bool(payload.get("truncated", False)),
        }
        externals = [r for r in remotes if r and not r.startswith("listening")]
        if externals:
            host_part = externals[0].rsplit(":", 1)
            out["remote_addr"] = host_part[0][:255]
            try:
                out["remote_port"] = int(host_part[1]) if len(host_part) > 1 else None
            except ValueError:
                out["remote_port"] = None
    elif telemetry_type == "system":
        for key in ("cpu_percent", "mem_percent", "disk_percent",
                    "uptime_seconds", "agent_version"):
            if key in payload:
                out["attributes"][key] = payload[key]
        services = payload.get("services")
        if isinstance(services, list):
            out["attributes"]["service_count"] = len(services)
    elif telemetry_type == "usb":
        if kind == "usb_device_seen":
            dev = payload.get("device", {})
            out["attributes"] = {"device": dev}
            out["host"] = host
        else:
            out["attributes"] = {"removable": payload.get("removable", [])}
    elif kind == "collector_status":
        out["attributes"] = {"collector": payload.get("collector", ""),
                             "error": str(payload.get("error", ""))[:500]}

    out["occurred_at"] = occurred_at
    return out
