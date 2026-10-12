"""Network collector: per-connection telemetry (no packet capture).

One event per cycle with the full connection list (capped): local/remote
addr+port, protocol family, state, pid + process name where permitted.
"""
import logging
import socket

import psutil

from weblock_agent.models.telemetry import make_event

logger = logging.getLogger("weblock-agent.collectors.network")
MAX_CONNS = 500


def _fam_name(family: int) -> str:
    return "tcp" if family == socket.SOCK_STREAM else (
        "udp" if family == socket.SOCK_DGRAM else str(family))


def collect() -> list[dict]:
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        logger.exception("net_connections failed")
        return [make_event("network", {
            "kind": "snapshot", "connections": [], "error": "unavailable",
        }, source="agent:network")]
    out: list[dict] = []
    for c in conns[:MAX_CONNS]:
        try:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            out.append({
                "proto": _fam_name(c.type),
                "local": laddr,
                "remote": raddr,
                "status": c.status,
                "pid": c.pid,
                "process": pname,
            })
        except Exception:
            continue
    return [make_event("network", {
        "kind": "snapshot", "connections": out, "truncated": len(conns) > MAX_CONNS,
    }, source="agent:network")]
