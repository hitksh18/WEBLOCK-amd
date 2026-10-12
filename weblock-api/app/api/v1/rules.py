"""Detection rule administration (RBAC: read any user, write admin only).

Writes NEVER touch global rows: PUT creates/updates the caller's ORG
override row, so one tenant cannot affect another. Rule code (logic) is
never sourced from the database — params/data only, no code execution.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import AuditLog, DetectionRule, User
from app.services.rules import BUILTIN_RULES

router = APIRouter(tags=["rules"])

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
_REGISTRY = {r.rule_id: r for r in BUILTIN_RULES}


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: str | None = None
    params: dict | None = None


def _merged_view(db: Session, org_id: int) -> list[dict]:
    rows = (
        db.query(DetectionRule)
        .filter((DetectionRule.org_id == org_id)
                | (DetectionRule.org_id.is_(None)))
        .all()
    )
    by_rule: dict[str, dict] = {}
    for row in rows:
        key = row.rule_id
        entry = by_rule.get(key, {})
        if row.org_id is None:
            entry.update({"scope": "global", "enabled": row.enabled,
                          "severity": row.severity, "params": row.params,
                          "version": row.version, "mitre": row.mitre,
                          "name": row.name, "description": row.description})
        else:
            entry.update({"scope": "org-override", "enabled": row.enabled,
                          "severity": row.severity, "params": row.params})
        by_rule[key] = entry
    # Include code-known rules even without DB rows (code defaults).
    for rule in BUILTIN_RULES:
        if rule.rule_id not in by_rule:
            by_rule[rule.rule_id] = {
                "scope": "code-default", "enabled": True,
                "severity": rule.severity, "params": rule.default_params(),
                "version": rule.version, "mitre": list(rule.mitre),
                "name": rule.name, "description": rule.description,
            }
    return [{"rule_id": rid, **info} for rid, info in sorted(by_rule.items())]


@router.get("/rules")
def list_rules(db: Session = Depends(get_db),
               current_user: User = Depends(get_current_user)):
    return _merged_view(db, current_user.org_id)


def _check_types(rule, params: dict) -> None:
    schema = rule.param_schema()
    for key, value in params.items():
        if key not in schema:
            raise HTTPException(status_code=422, detail=f"Unknown param: {key}")
        want = schema[key]
        ok = {"int": isinstance(value, int) and not isinstance(value, bool),
              "str": isinstance(value, str),
              "bool": isinstance(value, bool),
              "list": isinstance(value, list)}.get(want, False)
        if not ok:
            raise HTTPException(
                status_code=422, detail=f"Param '{key}' must be {want}")


@router.put("/admin/rules/{rule_id}")
def update_rule(rule_id: str, payload: RuleUpdate,
                db: Session = Depends(get_db),
                current_user: User = Depends(require_role("admin"))):
    rule = _REGISTRY.get(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Unknown rule")
    if payload.severity is not None and payload.severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    if payload.params is not None:
        _check_types(rule, payload.params)
    row = (
        db.query(DetectionRule)
        .filter(DetectionRule.org_id == current_user.org_id,
                DetectionRule.rule_id == rule_id)
        .first()
    )
    if row is None:
        row = DetectionRule(org_id=current_user.org_id, rule_id=rule_id,
                            name=rule.name, description=rule.description,
                            enabled=True, severity=rule.severity,
                            category=rule.categories[0], version=rule.version,
                            params=dict(rule.default_params()),
                            mitre=list(rule.mitre))
        db.add(row)
        db.flush()
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.severity is not None:
        row.severity = payload.severity
    if payload.params is not None:
        merged = dict(rule.default_params())
        merged.update(payload.params)
        row.params = merged
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="detection_rule.updated", target=rule_id,
                    meta_data={"enabled": row.enabled, "severity": row.severity,
                               "params": payload.params or {}}))
    db.commit()
    return {"rule_id": rule_id, "enabled": row.enabled,
            "severity": row.severity, "params": row.params}
