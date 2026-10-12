"""Stable endpoint identity from real machine attributes.

Fingerprint = sha256(hostname | primary MAC | platform | machine guid-ish).
Hostname alone is NOT the identity (it can change/collide); the server-side
agent_id (agent-<hex>) is the canonical endpoint identifier.
"""
import hashlib
import platform
import socket
import uuid

import psutil

from weblock_agent import __version__


def primary_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return "127.0.0.1"


def primary_mac() -> str:
    node = uuid.getnode()
    return ":".join(f"{(node >> i) & 0xFF:02X}" for i in range(40, -1, -8))


def all_ips() -> list[str]:
    found: list[str] = []
    try:
        for _iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    found.append(addr.address)
    except Exception:
        pass
    return sorted(set(found))


def device_fingerprint(hostname: str, mac: str) -> str:
    seed = f"{hostname}|{mac}|{platform.system()}|{platform.machine()}"
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def collect_device_info() -> dict:
    hostname = socket.gethostname()
    mac = primary_mac()
    return {
        "hostname": hostname,
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "arch": platform.machine(),
        "agent_version": __version__,
        "ip": primary_ip(),
        "all_ips": all_ips(),
        "mac": mac,
        "fingerprint": device_fingerprint(hostname, mac),
        "cpu_count": psutil.cpu_count(),
    }
