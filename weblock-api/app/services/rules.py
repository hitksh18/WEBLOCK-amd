"""Phase 3 production detection rules (deterministic, evidence-based).

Every rule evaluates ONE normalized SecurityEvent (+ read-only DB history
where the rule semantics require a window/baseline) and returns a
DetectionMatch citing exact event IDs, or None. Rules NEVER execute payload
content, NEVER fabricate events, and NEVER claim ML accuracy — confidence is
a documented rule-match formula.

Honest-scope notes live on each rule: where telemetry cannot support a
stronger claim, the rule implements the supportable subset and says so.
"""
import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import Detection, OrgPolicy, SecurityEvent, TelemetryEvent
from app.services.detection import DetectionMatch, EffectiveConfig

logger = logging.getLogger("weblock.rules")


def _raw_payload(db: Session, event: SecurityEvent) -> dict:
    raw = db.query(TelemetryEvent).filter(
        TelemetryEvent.id == event.telemetry_ref).first()
    return (raw.payload or {}) if raw is not None else {}


# ------------------------------------------------------------------ AUTH-01
class BruteForceRule:
    """AUTH-01: >=threshold LOGON_FAILURE for same endpoint+actor in window.

    Confidence = min(0.95, 0.75 + 0.05*(count-threshold)): more failures past
    the threshold = stronger match. Suppression: an OPEN AUTH-01 for the same
    endpoint+actor detected inside the window blocks repeats; after the window
    (or once resolved) a new occurrence fires again.
    MITRE T1110 (Brute Force): threshold-satisfying repeated failures justify it.
    """

    rule_id = "AUTH-01"
    name = "Brute force / repeated failed logons"
    description = ("5+ failed logons for the same endpoint and user within "
                   "5 minutes (configurable).")
    version = "1"
    severity = "high"
    categories = ("AUTHENTICATION",)
    mitre = ("T1110",)

    def param_schema(self) -> dict[str, str]:
        return {"threshold": "int", "window_seconds": "int"}

    def default_params(self) -> dict:
        return {"threshold": 5, "window_seconds": 300}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype != "LOGON_FAILURE":
            return None  # single failures are never brute force
        threshold = int(cfg.params.get("threshold", 5))
        window = int(cfg.params.get("window_seconds", 300))
        if threshold < 2 or window < 30:
            return None
        now = as_utc(event.occurred_at)
        failures = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.org_id == event.org_id,
                    SecurityEvent.endpoint_id == event.endpoint_id,
                    SecurityEvent.category == "AUTHENTICATION",
                    SecurityEvent.subtype == "LOGON_FAILURE",
                    SecurityEvent.actor == (event.actor or ""),
                    SecurityEvent.occurred_at >= now - timedelta(seconds=window),
                    SecurityEvent.occurred_at <= now)
            .order_by(SecurityEvent.id.desc())
            .limit(threshold + 20)
            .all()
        )
        count = len(failures)
        if count < threshold:
            return None
        # Suppression: same story already open inside this window?
        recent_open = (
            db.query(Detection)
            .filter(Detection.org_id == event.org_id,
                    Detection.rule_id == self.rule_id,
                    Detection.endpoint_id == event.endpoint_id,
                    Detection.status == "open",
                    Detection.detected_at >= datetime.now(timezone.utc)
                    - timedelta(seconds=window),
                    Detection.meta_data.op("->>")("actor") == (event.actor or ""))
            .first()
        )
        if recent_open is not None:
            return None
        related = [f.id for f in failures if f.id != event.id][:20]
        confidence = min(0.95, 0.75 + 0.05 * (count - threshold))
        actor = event.actor or "unknown user"
        return DetectionMatch(
            rule_id=self.rule_id, rule_version=self.version,
            severity=cfg.severity, confidence=round(confidence, 2),
            title=f"Possible brute force against {actor}",
            explanation=(f"{count} failed logons for '{actor}' on endpoint "
                         f"'{event.host or event.endpoint_id}' within {window}s "
                         f"(threshold {threshold}). Latest at "
                         f"{event.occurred_at.isoformat()}."),
            primary_event_id=event.id,
            related_event_ids=related,
            metadata={"actor": event.actor or "", "count": count,
                      "window_seconds": window, "threshold": threshold},
        )


# ------------------------------------------------------------------ AUTH-02
class AbnormalLoginTimeRule:
    """AUTH-02: logon outside the org policy role's allowed hours.

    LIMITATION (documented): baseline is org role hours from org_policies,
    not a per-user learned schedule — user linkage lands in Phase 4. No
    policy/role configured -> no detection (never invent a schedule).
    No MITRE mapping: off-hours alone does not justify a technique.
    """

    rule_id = "AUTH-02"
    name = "Abnormal login time"
    description = "Authentication outside configured allowed hours."
    version = "1"
    severity = "medium"
    categories = ("AUTHENTICATION",)
    mitre: tuple[str, ...] = ()

    def param_schema(self) -> dict[str, str]:
        return {"policy_role": "str"}

    def default_params(self) -> dict:
        return {"policy_role": "day_shift"}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype not in ("LOGON_SUCCESS", "SESSION_SNAPSHOT",
                                 "PRIVILEGED_LOGON"):
            return None
        policy = db.query(OrgPolicy).filter(
            OrgPolicy.org_id == event.org_id).first()
        if policy is None:
            return None
        roles = policy.roles or {}
        role_policy = roles.get(cfg.params.get("policy_role", "day_shift"), {})
        hours = role_policy.get("allowed_hours")
        if not hours or "start" not in hours or "end" not in hours:
            return None
        now_min = as_utc(event.occurred_at).hour * 60 + as_utc(event.occurred_at).minute
        sh, sm = (int(x) for x in hours["start"].split(":"))
        eh, em = (int(x) for x in hours["end"].split(":"))
        s_min, e_min = sh * 60 + sm, eh * 60 + em
        inside = (s_min <= now_min <= e_min) if s_min <= e_min else \
                 (now_min >= s_min or now_min <= e_min)
        if inside:
            return None
        return DetectionMatch(
            rule_id=self.rule_id, rule_version=self.version,
            severity=cfg.severity, confidence=0.7,
            title="Logon outside allowed hours",
            explanation=(f"Authentication ({event.subtype}) by '{event.actor or 'unknown'}' "
                         f"at {as_utc(event.occurred_at).strftime('%H:%M')} UTC is outside "
                         f"allowed hours {hours['start']}-{hours['end']} "
                         f"(policy role '{cfg.params.get('policy_role')}')."),
            primary_event_id=event.id,
            metadata={"allowed_hours": hours},
        )


# ------------------------------------------------------------------- DEV-01
class NewDeviceRule:
    """DEV-01: first authentication ever observed from this endpoint.

    LIMITATION (documented): Phase 2 telemetry has no user<->device binding
    yet, so the supportable signal is endpoint-first-auth, keyed on stable
    endpoint_id (not hostname). Per-user new-device detection needs Phase 4
    identity resolution. No MITRE: first-seen alone does not justify T1078.
    """

    rule_id = "DEV-01"
    name = "New/unseen device authentication"
    description = "First authentication activity observed from an endpoint."
    version = "1"
    severity = "medium"
    categories = ("AUTHENTICATION",)
    mitre: tuple[str, ...] = ()

    def param_schema(self) -> dict[str, str]:
        return {}

    def default_params(self) -> dict:
        return {}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype in ("LOGOFF",):
            return None
        older = (
            db.query(SecurityEvent.id)
            .filter(SecurityEvent.org_id == event.org_id,
                    SecurityEvent.endpoint_id == event.endpoint_id,
                    SecurityEvent.category == "AUTHENTICATION",
                    SecurityEvent.id < event.id)
            .first()
        )
        if older is not None:
            return None
        return DetectionMatch(
            rule_id=self.rule_id, rule_version=self.version,
            severity=cfg.severity, confidence=0.6,
            title="First authentication from this endpoint",
            explanation=(f"First authentication activity ({event.subtype}) observed "
                         f"from endpoint '{event.host or event.endpoint_id}'. No prior "
                         f"auth events exist for this endpoint in this organization."),
            primary_event_id=event.id,
            metadata={},
        )


# ------------------------------------------------------------------ PROC-01
_POWERSHELL_DEFAULT = ["powershell.exe", "pwsh.exe"]
_INDICATOR_DEFAULT = [
    "encodedcommand", "-enc ", "-encoded", "frombase64string",
    "downloadstring", "downloaddata", "invoke-expression", "iex ",
    "-executionpolicy bypass", "-exec bypass", "-windowstyle hidden",
    "-w hidden", "start-process", "new-object net.webclient",
]
# NOTE: "-noprofile" is DELIBERATELY excluded: npm/VS Code/CI launchers use
# it routinely (live-Windows false positive observed). Suspiciousness needs a
# stronger indicator from this list.


def _compile_indicators(patterns: list[str]) -> list[re.Pattern]:
    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            logger.warning("PROC-01 ignoring invalid regex: %r", pat[:80])
    return compiled


_COMPILED_DEFAULT_INDICATORS = _compile_indicators(_INDICATOR_DEFAULT)


class SuspiciousPowerShellRule:
    """PROC-01: PowerShell with suspicious command-line indicators.

    Plain powershell.exe with no indicators -> NO detection (explicitly).
    Explanation names the exact indicator. MITRE T1059.001 justified by
    encoded/download/bypass semantics. Confidence 0.9 (single strong match).
    """

    rule_id = "PROC-01"
    name = "Suspicious PowerShell execution"
    description = "PowerShell/pwsh with encoded/download/bypass indicators."
    version = "1"
    severity = "high"
    categories = ("PROCESS",)
    mitre = ("T1059.001",)

    def param_schema(self) -> dict[str, str]:
        return {"powershell_names": "list", "indicators": "list"}

    def default_params(self) -> dict:
        return {"powershell_names": list(_POWERSHELL_DEFAULT),
                "indicators": list(_INDICATOR_DEFAULT)}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype != "PROCESS_SNAPSHOT":
            return None
        names = {n.lower() for n in cfg.params.get("powershell_names",
                                                   _POWERSHELL_DEFAULT)}
        patterns = cfg.params.get("indicators", _INDICATOR_DEFAULT)
        compiled = (_COMPILED_DEFAULT_INDICATORS
                    if patterns == _INDICATOR_DEFAULT
                    else _compile_indicators(patterns))
        if not compiled:
            return None
        for proc in (_raw_payload(db, event).get("processes") or []):
            pname = str(proc.get("name", "")).lower()
            if pname not in names:
                continue
            cmdline = str(proc.get("cmdline", ""))
            for rx in compiled:
                if rx.search(cmdline):
                    return DetectionMatch(
                        rule_id=self.rule_id, rule_version=self.version,
                        severity=cfg.severity, confidence=0.9,
                        title="Suspicious PowerShell execution",
                        explanation=(f"Process '{proc.get('name')}' (pid "
                                     f"{proc.get('pid')}) matched suspicious "
                                     f"indicator '{rx.pattern}' in command line: "
                                     f"{cmdline[:220]}"),
                        primary_event_id=event.id,
                        metadata={"pid": proc.get("pid"), "name": proc.get("name"),
                                  "indicator": rx.pattern},
                    )
        return None


# ------------------------------------------------------------------ PROC-02
_OFFICE_DEFAULT = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                   "msaccess.exe", "mspub.exe", "visio.exe"]
_SHELL_DEFAULT = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                  "cscript.exe", "mshta.exe"]


def _base(name: str) -> str:
    return str(name or "").lower()


class OfficeShellChainRule:
    """PROC-02: Office application spawning a command shell.

    Uses real pid->parent linkage inside ONE process snapshot (no fabricated
    trees). Chrome->PowerShell and friends do NOT match. MITRE T1059: the
    observable is interpreter execution via an Office parent; T1204.002 also
    arguable, T1059 chosen as the conservative claim (documented).
    """

    rule_id = "PROC-02"
    name = "Office application spawning shell"
    description = "Office parent process (Word/Excel/...) spawned cmd/shell."
    version = "1"
    severity = "high"
    categories = ("PROCESS",)
    mitre = ("T1059",)

    def param_schema(self) -> dict[str, str]:
        return {"office_parents": "list", "shell_children": "list"}

    def default_params(self) -> dict:
        return {"office_parents": list(_OFFICE_DEFAULT),
                "shell_children": list(_SHELL_DEFAULT)}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype != "PROCESS_SNAPSHOT":
            return None
        office = {_base(n) for n in cfg.params.get("office_parents", _OFFICE_DEFAULT)}
        shells = {_base(n) for n in cfg.params.get("shell_children", _SHELL_DEFAULT)}
        procs = _raw_payload(db, event).get("processes") or []
        by_pid = {p.get("pid"): p for p in procs if p.get("pid") is not None}
        for proc in procs:
            if _base(proc.get("name")) not in shells:
                continue
            parent = by_pid.get(proc.get("ppid"))
            if parent is None:
                continue
            if _base(parent.get("name")) in office:
                return DetectionMatch(
                    rule_id=self.rule_id, rule_version=self.version,
                    severity=cfg.severity, confidence=0.9,
                    title="Office application spawned a shell",
                    explanation=(f"'{parent.get('name')}' (pid {parent.get('pid')}) "
                                 f"spawned '{proc.get('name')}' (pid {proc.get('pid')}), "
                                 f"matching the Office-to-shell chain."),
                    primary_event_id=event.id,
                    metadata={"parent": parent.get("name"),
                              "parent_pid": parent.get("pid"),
                              "child": proc.get("name"),
                              "child_pid": proc.get("pid")},
                )
        return None


# ------------------------------------------------------------------- NET-01
_SENSITIVE_PORTS_DEFAULT = [4444, 5555, 6666, 6667, 1337, 31337, 4443, 5550]


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved)


class SuspiciousNetworkRule:
    """NET-01: external connection on a sensitive/rare port.

    Conservative by design: external IP alone is NOT a threat. Requires
    external destination AND port in configured sensitive_ports. No MITRE:
    a rare-port connection does not justify a C2 claim. No ML, no anomaly
    scores — deterministic port+routability check (documented limitation).
    """

    rule_id = "NET-01"
    name = "Suspicious external network connection"
    description = "External destination on a sensitive/rare port."
    version = "1"
    severity = "medium"
    categories = ("NETWORK",)
    mitre: tuple[str, ...] = ()

    def param_schema(self) -> dict[str, str]:
        return {"sensitive_ports": "list", "external_only": "bool"}

    def default_params(self) -> dict:
        return {"sensitive_ports": list(_SENSITIVE_PORTS_DEFAULT),
                "external_only": True}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype != "CONNECTION_ROLLUP":
            return None
        try:
            sensitive = {int(p) for p in cfg.params.get(
                "sensitive_ports", _SENSITIVE_PORTS_DEFAULT)}
        except (TypeError, ValueError):
            return None
        external_only = bool(cfg.params.get("external_only", True))
        for conn in (_raw_payload(db, event).get("connections") or []):
            remote = str(conn.get("remote", ""))
            if not remote or remote == "listening":
                continue
            host_part, _, port_part = remote.rpartition(":")
            try:
                port = int(port_part)
            except ValueError:
                continue
            if port not in sensitive:
                continue
            if external_only and not _is_external(host_part):
                continue
            return DetectionMatch(
                rule_id=self.rule_id, rule_version=self.version,
                severity=cfg.severity, confidence=0.75,
                title="Suspicious external connection",
                explanation=(f"Connection to external {host_part}:{port} "
                             f"(sensitive port) by process "
                             f"'{conn.get('process') or 'unknown'}'."),
                primary_event_id=event.id,
                metadata={"remote": remote,
                          "process": conn.get("process") or ""},
            )
        return None


# ------------------------------------------------------------------- SYS-01
class PrivilegedLogonRule:
    """SYS-01: special-privileges logon (Windows 4672) observed.

    HONEST SUBSET: service-creation (T1543-style) detection needs a service
    baseline that does not exist yet — SERVICE_SNAPSHOT explicitly returns
    None (documented). The supportable signal today is 4672. No MITRE: a
    privileged logon alone does not justify a persistence claim.
    """

    rule_id = "SYS-01"
    name = "Privileged logon observed"
    description = "Windows 4672 special-privileges logon."
    version = "1"
    severity = "medium"
    categories = ("AUTHENTICATION", "SYSTEM")
    mitre: tuple[str, ...] = ()

    def param_schema(self) -> dict[str, str]:
        return {}

    def default_params(self) -> dict:
        return {}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype != "PRIVILEGED_LOGON":
            return None  # incl. SERVICE_SNAPSHOT: no baseline yet
        return DetectionMatch(
            rule_id=self.rule_id, rule_version=self.version,
            severity=cfg.severity, confidence=0.7,
            title="Privileged logon observed",
            explanation=(f"Special-privileges logon (Windows 4672) for "
                         f"'{event.actor or 'unknown'}' on "
                         f"'{event.host or event.endpoint_id}'."),
            primary_event_id=event.id,
            metadata={"actor": event.actor or ""},
        )


# ------------------------------------------------------------------- USB-01
class NewUsbDeviceRule:
    """USB-01: newly observed removable device (first-seen volume).

    Every insertion is NOT malicious: severity LOW by default. No MITRE T1091:
    insertion alone is not replication. Gains meaning via correlation/policy
    in later phases.
    """

    rule_id = "USB-01"
    name = "New removable device observed"
    description = "First-seen removable/USB volume on the endpoint."
    version = "1"
    severity = "low"
    categories = ("USB",)
    mitre: tuple[str, ...] = ()

    def param_schema(self) -> dict[str, str]:
        return {}

    def default_params(self) -> dict:
        return {}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        if event.subtype != "DEVICE_CHANGE":
            return None
        device = (event.attributes or {}).get("device", {})
        return DetectionMatch(
            rule_id=self.rule_id, rule_version=self.version,
            severity=cfg.severity, confidence=0.8,
            title="New removable device observed",
            explanation=(f"New removable device '{device.get('device', 'unknown')}' "
                         f"first seen on endpoint '{event.host or event.endpoint_id}' "
                         f"at {as_utc(event.occurred_at).isoformat()}."),
            primary_event_id=event.id,
            metadata={"device": device},
        )


BUILTIN_RULES = [
    BruteForceRule(),
    AbnormalLoginTimeRule(),
    NewDeviceRule(),
    SuspiciousPowerShellRule(),
    OfficeShellChainRule(),
    SuspiciousNetworkRule(),
    PrivilegedLogonRule(),
    NewUsbDeviceRule(),
]

BUILTIN_RULE_IDS = [r.rule_id for r in BUILTIN_RULES]
