"""Detection engine: rule contract + dispatcher + persistence + lifecycle.

Phase 3 production rules live in app/services/rules.py and are registered in
BUILTIN_RULES there; this module never imports rules at load time (lazy
import inside dispatch) to avoid a hard dependency cycle.

Confidence semantics (deterministic, NOT ML accuracy): each rule documents
its own formula mapping evidence strength -> [0,1]. It answers "how strongly
does the evidence match the rule", never "probability of real attack".

TEST-MARKER is test-only (never seeded in production).
"""
import logging
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Detection, DetectionRule, SecurityEvent

logger = logging.getLogger("weblock.detection")

VALID_STATUSES = ("open", "acknowledged", "resolved", "false_positive")


@dataclass
class DetectionMatch:
    rule_id: str
    rule_version: str
    severity: str
    confidence: float
    title: str
    explanation: str
    primary_event_id: int  # security_events.id
    related_event_ids: list[int] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class EffectiveConfig:
    enabled: bool
    severity: str
    params: dict


class DetectionRuleDef(Protocol):
    rule_id: str
    name: str
    description: str
    version: str
    severity: str
    categories: tuple[str, ...]
    mitre: tuple[str, ...]

    def param_schema(self) -> dict[str, str]:
        """{param_name: type-name} for admin validation. Types: int/str/bool/list."""
        ...

    def default_params(self) -> dict:
        ...

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        ...


class TestMarkerRule:
    """TEST-ONLY rule. Matches normalized events whose attributes carry
    test_marker=true. Never seeded in production."""

    rule_id = "TEST-MARKER"
    name = "[TEST] Marker rule (proves dispatcher path)"
    description = "Test-only marker rule."
    version = "1"
    severity = "info"
    categories = ("AUTHENTICATION", "PROCESS", "NETWORK", "SYSTEM", "USB",
                  "AGENT", "IDENTITY", "UNKNOWN")
    mitre: tuple[str, ...] = ()

    def param_schema(self) -> dict[str, str]:
        return {}

    def default_params(self) -> dict:
        return {}

    def evaluate(self, event: SecurityEvent, db: Session,
                 cfg: EffectiveConfig) -> DetectionMatch | None:
        attrs = event.attributes or {}
        if attrs.get("test_marker") is True:
            return DetectionMatch(
                rule_id=self.rule_id, rule_version=self.version,
                severity=cfg.severity, confidence=1.0,
                title="[TEST] Marked event observed",
                explanation=f"Test marker on security event {event.id} "
                            f"({event.category}/{event.subtype}).",
                primary_event_id=event.id,
                metadata={"test_only": True},
            )
        return None


def _rule_row(db: Session, org_id: int, rule_id: str) -> DetectionRule | None:
    return (
        db.query(DetectionRule)
        .filter(((DetectionRule.org_id == org_id)
                 | (DetectionRule.org_id.is_(None))),
                DetectionRule.rule_id == rule_id)
        .order_by(DetectionRule.org_id.desc().nullslast())
        .first()
    )


def effective_config(db: Session, org_id: int,
                     rule: DetectionRuleDef) -> EffectiveConfig:
    row = _rule_row(db, org_id, rule.rule_id)
    if row is None:
        return EffectiveConfig(enabled=True, severity=rule.severity,
                               params=dict(rule.default_params()))
    merged = dict(rule.default_params())
    if isinstance(row.params, dict):
        merged.update(row.params)
    return EffectiveConfig(enabled=bool(row.enabled),
                           severity=row.severity or rule.severity,
                           params=merged)


def dispatch_event(db: Session, event: SecurityEvent,
                   extra_rules: list[DetectionRuleDef] | None = None,
                   include_builtin: bool = True) -> int:
    """Evaluate applicable rules for one normalized event. Returns # persisted."""
    rules: list[DetectionRuleDef] = []
    if include_builtin:
        from app.services.rules import BUILTIN_RULES  # lazy: no import cycle
        rules.extend(BUILTIN_RULES)
    rules.extend(extra_rules or [])
    persisted = 0
    for rule in rules:
        if event.category not in rule.categories:
            continue
        cfg = effective_config(db, event.org_id, rule)
        if not cfg.enabled:
            continue
        try:
            match = rule.evaluate(event, db, cfg)
        except Exception:
            logger.exception("rule %s crashed on event %s", rule.rule_id, event.id)
            continue
        if match is None:
            continue
        metadata = dict(match.metadata or {})
        metadata.setdefault("mitre", list(rule.mitre))
        metadata.setdefault("rule_name", rule.name)
        stmt = (
            pg_insert(Detection)
            .values(
                org_id=event.org_id,
                endpoint_id=event.endpoint_id,
                rule_id=match.rule_id,
                rule_version=match.rule_version,
                severity=cfg.severity,  # admin override wins
                confidence=match.confidence,
                title=match.title,
                explanation=match.explanation,
                primary_event_id=match.primary_event_id,
                related_event_ids=match.related_event_ids,
                meta_data=metadata,
            )
            .on_conflict_do_nothing(
                constraint="uq_detections_idempotency")
            .returning(Detection.id)
        )
        inserted = db.execute(stmt).scalars().all()
        persisted += len(inserted)
        if inserted:
            logger.info("detection rule=%s event=%s", match.rule_id, event.id)
            # Phase 4 handoff: correlate (never breaks detection on failure).
            try:
                from app.core.config import settings as _settings
                from app.services.correlate import process_detection as _correlate
                det_row = db.query(Detection).filter(
                    Detection.id == inserted[0]).first()
                if det_row is not None:
                    _correlate(db, det_row,
                               window=_settings.CORRELATION_WINDOW_SECONDS)
            except Exception:
                logger.exception("correlation hook failed for detection %s",
                                 inserted[0])
    return persisted


def set_detection_status(db: Session, *, org_id: int, detection_id: int,
                         status: str, actor_id: int | None) -> Detection:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid detection status: {status}")
    det = (
        db.query(Detection)
        .filter(Detection.id == detection_id, Detection.org_id == org_id)
        .first()
    )
    if det is None:
        raise LookupError("Detection not found")
    det.status = status
    db.add(AuditLog(org_id=org_id, actor_id=actor_id,
                    action="detection.status_changed",
                    target=f"{det.rule_id}:{det.id}",
                    meta_data={"status": status}))
    db.commit()
    return det


def reprocess_failed(db: Session, org_id: int, limit: int = 100) -> int:
    """Reset FAILED security events to NORMALIZED for controlled retry."""
    from app.db.models import TelemetryEvent
    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.org_id == org_id,
                SecurityEvent.status == "FAILED")
        .order_by(SecurityEvent.id)
        .limit(limit)
        .all()
    )
    for event in rows:
        event.status = "NORMALIZED"
        event.error = ""
        raw = db.query(TelemetryEvent).filter(
            TelemetryEvent.id == event.telemetry_ref).first()
        if raw is not None:
            raw.processing_status = "RECEIVED"
            raw.processing_error = ""
    db.commit()
    return len(rows)
