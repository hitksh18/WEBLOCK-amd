"""Seed production detection rules (global rows, idempotent upsert).

TEST-MARKER is deliberately never seeded.

Usage (from weblock-api/):
    python -m app.seed_rules
"""
from app.db.database import SessionLocal
from app.db.models import DetectionRule
from app.services.rules import BUILTIN_RULES


def seed() -> dict:
    db = SessionLocal()
    try:
        created, updated = 0, 0
        for rule in BUILTIN_RULES:
            row = (
                db.query(DetectionRule)
                .filter(DetectionRule.org_id.is_(None),
                        DetectionRule.rule_id == rule.rule_id)
                .first()
            )
            if row is None:
                db.add(DetectionRule(
                    org_id=None, rule_id=rule.rule_id, name=rule.name,
                    description=rule.description, enabled=True,
                    severity=rule.severity, category=rule.categories[0],
                    version=rule.version, params=dict(rule.default_params()),
                    mitre=list(rule.mitre)))
                created += 1
            else:
                # Refresh code-owned fields; NEVER overwrite admin enable/severity.
                row.name = rule.name
                row.description = rule.description
                row.version = rule.version
                row.mitre = list(rule.mitre)
                updated += 1
        db.commit()
        return {"created": created, "updated": updated,
                "rules": [r.rule_id for r in BUILTIN_RULES]}
    finally:
        db.close()


if __name__ == "__main__":
    print(seed())
