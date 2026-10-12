"""Agent runtime configuration (local file + server-pulled overlay).

Precedence: server config (pulled) > local agent.json > defaults.
Server may only set known keys (validated client-side too).
"""
import json
import os
from dataclasses import asdict, dataclass, field

DEFAULTS: dict = {
    "server_url": "http://localhost:8000",
    "workdir": os.path.join(os.path.expanduser("~"), ".weblock-agent"),
    "enroll_token": "",
    "heartbeat_interval": 60,
    "batch_interval": 60,
    "collectors": {
        "identity": True,
        "process": True,
        "network": True,
        "eventlog": True,
        "system": True,
        "usb": True,
    },
    "log_level": "INFO",
    "retention_days": 7,
    "max_batch_events": 500,
    "verify_tls": True,
}

KNOWN_COLLECTORS = set(DEFAULTS["collectors"])


@dataclass
class AgentConfig:
    server_url: str = DEFAULTS["server_url"]
    workdir: str = DEFAULTS["workdir"]
    enroll_token: str = ""
    heartbeat_interval: int = 60
    batch_interval: int = 60
    collectors: dict = field(default_factory=lambda: dict(DEFAULTS["collectors"]))
    log_level: str = "INFO"
    retention_days: int = 7
    max_batch_events: int = 500
    verify_tls: bool = True

    @property
    def outbox_path(self) -> str:
        return os.path.join(self.workdir, "outbox.db")

    @property
    def config_path(self) -> str:
        return os.path.join(self.workdir, "agent.json")


def validate_config_dict(data: dict) -> dict:
    """Validate server-pulled or file config. Raises ValueError."""
    if not isinstance(data, dict):
        raise ValueError("config must be an object")
    for key in data:
        if key not in DEFAULTS or key in ("server_url", "workdir", "enroll_token"):
            if key not in ("heartbeat_interval", "batch_interval", "collectors",
                           "log_level", "retention_days", "max_batch_events",
                           "verify_tls"):
                raise ValueError(f"Unknown config key: {key}")
    collectors = data.get("collectors", {})
    if not isinstance(collectors, dict):
        raise ValueError("collectors must be an object")
    for ck, cv in collectors.items():
        if ck not in KNOWN_COLLECTORS:
            raise ValueError(f"Unknown collector: {ck}")
        if not isinstance(cv, bool):
            raise ValueError(f"Collector flag must be bool: {ck}")
    hb = data.get("heartbeat_interval", 60)
    bi = data.get("batch_interval", 60)
    if not isinstance(hb, int) or not 10 <= hb <= 3600:
        raise ValueError("heartbeat_interval must be int in [10, 3600]")
    if not isinstance(bi, int) or not 10 <= bi <= 3600:
        raise ValueError("batch_interval must be int in [10, 3600]")
    if data.get("log_level", "INFO") not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ValueError("bad log_level")
    rd = data.get("retention_days", 7)
    if not isinstance(rd, int) or not 1 <= rd <= 90:
        raise ValueError("retention_days must be int in [1, 90]")
    return data


def load_file_config(workdir: str) -> dict:
    path = os.path.join(workdir, "agent.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return validate_config_dict(data)


def apply_overlay(cfg: AgentConfig, overlay: dict) -> AgentConfig:
    validated = validate_config_dict(overlay)
    for key, value in validated.items():
        if key == "collectors":
            merged = dict(cfg.collectors)
            merged.update(value)
            cfg.collectors = merged
        elif hasattr(cfg, key):
            setattr(cfg, key, value)
    return cfg


def config_to_dict(cfg: AgentConfig) -> dict:
    return asdict(cfg)
