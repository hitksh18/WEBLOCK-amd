"""Phase 5 contextual risk engine (endpoint-scoped, evidence-based).

Inputs (all read-only): open correlation clusters, non-false-positive
detections in the lookback window, endpoint age. Every point comes from a
stored row; the explanation cites actual counts/families/rules.

Factor budget (max 100, clamped):
  correlation context .... round(strongest open cluster confidence * 0.4), max 32,
                           plus 4 per additional open cluster (max +8)
  high-severity activity . 9 per HIGH (cap 18); CRITICAL counts as HIGH here
  detection families ..... 5 per family beyond the first (cap 10)
  recency ................ <=15min:10, <=1h:7, <=6h:4, <=24h:2, else 0
  prior activity ......... detections in lookback: 0->0, 1->3, 2->5, >=3->7
  repeated behavior ...... any rule firing >=2x in lookback: +5
  novel endpoint ......... DEV-01 open in lookback OR endpoint first seen
                           within lookback (newly observed endpoint): +4

Severity: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL.

LIMITATION (documented): per-user risk is not computed — Phase 2/4
telemetry has no user<->endpoint binding yet, so risk is endpoint-scoped.
Actor repetition is visible inside inputs but does not move the score.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import CorrelationCluster, Detection, Endpoint, SecurityEvent
from app.services.correlate import family_of

logger = logging.getLogger("weblock.risk")


@dataclass
class RiskResult:
    score: int
    severity: str
    factors: list[dict] = field(default_factory=list)  # [{label, points}]
    explanation: str = ""
    inputs: dict = field(default_factory=dict)


def severity_of(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _recency_points(age_seconds: float) -> tuple[int, str]:
    if age_seconds <= 900:
        return 10, "within the last 15 minutes"
    if age_seconds <= 3600:
        return 7, "within the last hour"
    if age_seconds <= 6 * 3600:
        return 4, "within the last 6 hours"
    if age_seconds <= 24 * 3600:
        return 2, "within the last 24 hours"
    return 0, "older than 24 hours"


def compute_endpoint_risk(db: Session, *, org_id: int, endpoint_id: int,
                          lookback_hours: int = 24,
                          now: datetime | None = None) -> RiskResult:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=lookback_hours)

    endpoint = db.query(Endpoint).filter(
        Endpoint.id == endpoint_id, Endpoint.org_id == org_id).first()
    if endpoint is None:
        raise LookupError("Endpoint not found")
    label = endpoint.hostname or endpoint.agent_id

    dets = (
        db.query(Detection)
        .filter(Detection.org_id == org_id,
                Detection.endpoint_id == endpoint_id,
                Detection.status != "false_positive",
                Detection.detected_at >= cutoff)
        .order_by(Detection.id)
        .all()
    )
    clusters = (
        db.query(CorrelationCluster)
        .filter(CorrelationCluster.org_id == org_id,
                CorrelationCluster.endpoint_id == endpoint_id,
                CorrelationCluster.status == "open")
        .order_by(CorrelationCluster.confidence.desc())
        .all()
    )

    factors: list[dict] = []
    total = 0

    def add(label_: str, points: int) -> None:
        nonlocal total
        if points > 0:
            factors.append({"label": label_, "points": points})
            total += points

    # 1. Correlation context (strongest open cluster + smaller extras).
    if clusters:
        strongest = clusters[0]
        pts = min(32, round(strongest.confidence * 0.4))
        add(f"correlation context (open cluster confidence "
            f"{strongest.confidence})", pts)
        if len(clusters) > 1:
            add(f"{len(clusters) - 1} additional open cluster(s)",
                min(8, 4 * (len(clusters) - 1)))

    # 2. High-severity activity.
    highs = [d for d in dets if d.severity in ("high", "critical")]
    add(f"high-severity activity ({len(highs)} HIGH/CRITICAL detections)",
        min(18, 9 * len(highs)))

    # 3. Detection families.
    fams = sorted({family_of(d) for d in dets})
    add(f"{len(fams)} detection families ({', '.join(f.lower() for f in fams)})"
        if fams else "no detection families",
        min(10, 5 * max(0, len(fams) - 1)))

    # 4. Recency of the latest detection.
    if dets:
        latest = dets[-1]
        sec = db.query(SecurityEvent).filter(
            SecurityEvent.id == latest.primary_event_id).first()
        base = as_utc(sec.occurred_at) if sec and sec.occurred_at else \
            as_utc(latest.detected_at)
        age = (now - base).total_seconds()
        pts, words = _recency_points(age)
        mins = max(1, int(age // 60))
        add(f"most recent activity {mins} minute(s) ago ({words})", pts)

    # 5. Prior activity volume.
    n = len(dets)
    add(f"{n} detections in the last {lookback_hours}h",
        0 if n == 0 else (3 if n == 1 else (5 if n == 2 else 7)))

    # 6. Repeated behavior.
    by_rule: dict[str, int] = {}
    for d in dets:
        by_rule[d.rule_id] = by_rule.get(d.rule_id, 0) + 1
    repeated = sorted(r for r, c in by_rule.items() if c >= 2)
    if repeated:
        add(f"repeated behavior ({repeated[0]} fired "
            f"{by_rule[repeated[0]]}x)", 5)

    # 7. Novel endpoint behavior.
    novel_reason = ""
    if any(d.rule_id == "DEV-01" for d in dets):
        novel_reason = "first-authentication behavior (DEV-01) observed"
    else:
        first_sec = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.org_id == org_id,
                    SecurityEvent.endpoint_id == endpoint_id)
            .order_by(SecurityEvent.occurred_at.asc())
            .first()
        )
        if first_sec is not None and first_sec.occurred_at is not None \
                and as_utc(first_sec.occurred_at) >= cutoff:
            novel_reason = "newly observed endpoint (first telemetry in window)"
    if novel_reason:
        add(novel_reason, 4)

    score = min(100, total)
    severity = severity_of(score)

    if dets:
        top_rules = sorted(by_rule, key=lambda r: (-by_rule[r], r))[:3]
        explanation = (
            f"Risk {score} ({severity.upper()}) for endpoint '{label}': "
            f"{n} detection(s) across {len(fams)} familie(s) "
            f"({', '.join(f.lower() for f in fams)}) in the last "
            f"{lookback_hours}h, led by {', '.join(top_rules)}. "
        )
        if clusters:
            explanation += (
                f"{len(clusters)} open correlation cluster(s); strongest "
                f"confidence {clusters[0].confidence} "
                f"({clusters[0].explanation[:160]}). "
            )
        explanation += ("Score is the sum of the cited factors, each derived "
                        "from stored detections/clusters — no ML involved.")
    else:
        explanation = (f"Risk {score} ({severity.upper()}) for endpoint '{label}': "
                       f"no qualifying security activity in the last "
                       f"{lookback_hours}h.")

    return RiskResult(
        score=score, severity=severity, factors=factors,
        explanation=explanation,
        inputs={
            "detection_ids": [d.id for d in dets],
            "cluster_ids": [c.id for c in clusters],
            "families": fams,
            "rule_counts": by_rule,
            "lookback_hours": lookback_hours,
        },
    )


def snapshot_endpoint_risk(db: Session, *, org_id: int, endpoint_id: int,
                           lookback_hours: int = 24,
                           force: bool = False,
                           now: datetime | None = None) -> tuple[RiskResult, bool]:
    """Compute and persist a snapshot when the score changed (or forced).

    Returns (result, written)."""
    from app.db.models import RiskSnapshot
    result = compute_endpoint_risk(db, org_id=org_id, endpoint_id=endpoint_id,
                                   lookback_hours=lookback_hours, now=now)
    latest = (
        db.query(RiskSnapshot)
        .filter(RiskSnapshot.org_id == org_id,
                RiskSnapshot.endpoint_id == endpoint_id)
        .order_by(RiskSnapshot.id.desc())
        .first()
    )
    if force or latest is None or latest.score != result.score:
        db.add(RiskSnapshot(org_id=org_id, endpoint_id=endpoint_id,
                            score=result.score, severity=result.severity,
                            factors=result.factors, inputs=result.inputs))
        db.commit()
        return result, True
    return result, False
