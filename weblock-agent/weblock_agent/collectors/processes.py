"""Process collector: pid/ppid/name/exe/cmdline/user/create_time + exe hash.

Protected processes (AccessDenied) are SKIPPED, never fatal. exe sha256 is
best-effort (may fail on locked files) and omitted when unavailable.
"""
import hashlib
import logging
import os

import psutil

from weblock_agent.models.telemetry import make_event

logger = logging.getLogger("weblock-agent.collectors.process")
MAX_PROCS = 500
HASH_CAP_BYTES = 32 * 1024 * 1024


def _exe_hash(path: str) -> str | None:
    try:
        if not path or not os.path.isfile(path):
            return None
        if os.path.getsize(path) > HASH_CAP_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def collect(include_hashes: bool = True) -> list[dict]:
    procs: list[dict] = []
    skipped = 0
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    ):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            skipped += 1
            continue
        try:
            entry = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name") or "",
                "exe": info.get("exe") or "",
                "cmdline": " ".join(info.get("cmdline") or [])[:2048],
                "username": info.get("username") or "",
                "create_time": info.get("create_time"),
            }
            if include_hashes:
                entry["exe_sha256"] = _exe_hash(entry["exe"])
            procs.append(entry)
            if len(procs) >= MAX_PROCS:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            skipped += 1
            continue
        except Exception:
            logger.exception("process snapshot failed partway")
            break
    return [make_event("process", {
        "kind": "snapshot", "processes": procs, "skipped": skipped,
    }, source="agent:process")]
