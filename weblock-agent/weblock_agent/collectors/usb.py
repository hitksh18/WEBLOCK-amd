"""USB collector: removable-volume snapshot (poll-based, telemetry only).

Compares against a `usb.seen` state file and emits `usb_device_seen` only
for newly observed removable volumes. No blocking, no driver.
A documented limitation: Windows toast-level insert/remove events between
polls can be missed; the snapshot always reflects current truth.
"""
import logging
import os

import psutil

from weblock_agent.models.telemetry import make_event

logger = logging.getLogger("weblock-agent.collectors.usb")


def _state_path(workdir: str) -> str:
    return os.path.join(workdir, "usb.seen")


def current_removable() -> list[dict]:
    found: list[dict] = []
    try:
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "removable" in opts or "cdrom" in opts:
                found.append({"device": part.device, "mountpoint": part.mountpoint,
                              "fstype": part.fstype, "opts": part.opts})
    except Exception:
        logger.exception("volume enumeration failed")
    return found


def _read_seen(workdir: str) -> set[str]:
    try:
        with open(_state_path(workdir), encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def _write_seen(workdir: str, devices: set[str]) -> None:
    try:
        with open(_state_path(workdir), "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(devices)))
    except OSError:
        logger.warning("cannot persist usb state")


def collect(workdir: str) -> list[dict]:
    removable = current_removable()
    current = {d["device"] for d in removable}
    seen = _read_seen(workdir)
    new_devices = [d for d in removable if d["device"] not in seen]
    _write_seen(workdir, current)
    events = [make_event("usb", {"kind": "volume_snapshot", "removable": removable},
                         source="agent:usb")]
    for dev in new_devices:
        events.append(make_event("usb", {"kind": "usb_device_seen", "device": dev},
                                 source="agent:usb"))
    return events
