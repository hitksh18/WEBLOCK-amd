"""Detection foundation (Phase 2): rule contract + dispatcher + persistence.

Phase 3 adds real production rules. The dispatcher runs enabled rules that
exist BOTH in code (registry) and in the `detection_rules` table; table rows
without code are skipped (logged), code rules without table rows use code
defaults (enabled). Every persisted Detection answers:
  "what rule?" (rule_id + version) and "which events?" (primary + related).

TEST_MARKER is a test-only rule (payload.test_marker == true). It is NEVER
seeded in production and is clearly labeled; it exists to prove the
dispatcher/persistence/idempotency path end to end.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.db.models import Detection, DetectionRule, SecurityEvent

logger = logging.getLogger("weblock.detection")


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


class DetectionRuleDef(Protocol):
    rule_id: str
    name: str
    version: str
    severity: str
    categories: tuple[str, ...]
    mitre: tuple[str, ...]

    def evaluate(self, event: SecurityEvent) -> DetectionMatch | None:
        ...


class TestMarkerRule:
    """TEST-ONLY rule. Matches normalized events whose attributes carry
    test_marker=true. Never enabled in production."""

    rule_id = "TEST-MARKER"
    name = "[TEST] Marker rule (proves dispatcher path)"
    version = "1"
    severity = "info"
    categories = ("AUTHENTICATION", "PROCESS", "NETWORK", "SYSTEM", "USB",
                  "AGENT", "IDENTITY", "UNKNOWN")
    mitre: tuple[str, ...] = ()

    def evaluate(self, event: SecurityEvent) -> DetectionMatch | None:
        attrs = event.attributes or {}
        if attrs.get("test_marker") is True:
            return DetectionMatch(
                rule_id=self.rule_id, rule_version=self.version,
                severity="info", confidence=1.0,
                title="[TEST] Marked event observed",
                explanation=f"Test marker on security event {event.id} "
                            f"({event.category}/{event.subtype}).",
                primary_event_id=event.id,
                metadata={"test_only": True},
            )
        return None


# Production registry: intentionally EMPTY until Phase 3 implements real rules.
BUILTIN_RULES: list[DetectionRuleDef] = []


def _rule_row(db: Session, org_id: int, rule_id: str) -> DetectionRule | None:
    return (
        db.query(DetectionRule)
        .filter(((DetectionRule.org_id == org_id)
                 | (DetectionRule.org_id.is_(None))),
                DetectionRule.rule_id == rule_id)
        .order_by(DetectionRule.org_id.desc().nullslast())
        .first()
    )


def dispatch_event(db: Session, event: SecurityEvent,
                   extra_rules: list[DetectionRuleDef] | None = None) -> int:
    """Evaluate applicable rules for one normalized event. Returns # persisted."""
    rules: list[DetectionRuleDef] = list(BUILTIN_RULES) + list(extra_rules or [])
    persisted = 0
    for rule in rules:
        if event.category not in rule.categories:
            continue
        row = _rule_row(db, event.org_id, rule.rule_id)
        if row is not None and not row.enabled:
            continue
        try:
            match = rule.evaluate(event)
        except Exception:
            logger.exception("rule %s crashed on event %s", rule.rule_id, event.id)
            continue
        if match is None:
            continue
        stmt = (
            pg_insert(Detection)
            .values(
                org_id=event.org_id,
                endpoint_id=event.endpoint_id,
                rule_id=match.rule_id,
                rule_version=match.rule_version,
                severity=match.severity,
                confidence=match.confidence,
                title=match.title,
                explanation=match.explanation,
                primary_event_id=match.primary_event_id,
                related_event_ids=match.related_event_ids,
                meta_data=match.metadata,
            )
            .on_conflict_do_nothing(
                constraint="uq_detections_idempotency")
            .returning(Detection.id)
        )
        inserted = db.execute(stmt).scalars().all()
        persisted += len(inserted)
        if inserted:
            logger.info("detection rule=%s event=%s", match.rule_id, event.id)
    return persisted


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
