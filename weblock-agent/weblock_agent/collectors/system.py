"""System collector: cpu/mem/disk/uptime (lightweight, polled)."""
import time

import psutil

from weblock_agent import __version__
from weblock_agent.models.telemetry import make_event


def collect() -> list[dict]:
    vm = psutil.virtual_memory()
    du = psutil.disk_usage("/")
    return [make_event("system", {
        "kind": "health",
        "cpu_percent": psutil.cpu_percent(interval=1),
        "mem_percent": vm.percent,
        "mem_total_mb": round(vm.total / 1048576),
        "disk_percent": du.percent,
        "boot_time": psutil.boot_time(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "agent_version": __version__,
    }, source="agent:system")]
