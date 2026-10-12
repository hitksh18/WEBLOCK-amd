"""Seed ABC Corp org + DB policy (from legacy JSON) + admin user.

Usage (from weblock-api/):
    set DATABASE_URL=... & venv python -m app.seed \
        --admin-email admin@abccorp.com --admin-password <secret>

Idempotent: re-running updates policy, skips existing users.
Reads legacy weblock-api/policies/abc_corp_policy.json ONLY as seed input;
runtime source of truth is org_policies table.
"""
import argparse
import getpass
import json
from pathlib import Path

from app.core.security import hash_password
from app.db.database import SessionLocal
from app.db.models import Organization, OrgPolicy, User

LEGACY_POLICY = Path(__file__).resolve().parent.parent / "policies" / "abc_corp_policy.json"


def load_legacy_policy() -> dict:
    with open(LEGACY_POLICY, encoding="utf-8") as f:
        return json.load(f)


def seed(admin_email: str, admin_password: str) -> dict:
    legacy = load_legacy_policy()
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.slug == "abc-corp").first()
        if not org:
            org = Organization(name="ABC Corp", slug="abc-corp")
            db.add(org)
            db.flush()

        policy = db.query(OrgPolicy).filter(OrgPolicy.org_id == org.id).first()
        roles = legacy.get("roles", {})
        users_blob: dict = legacy.get("users", {})
        # Build per-user overrides (role + baselines) keyed by legacy user id.
        overrides = {
            uid: {
                "role": u.get("role", "day_shift"),
                "baseline_country": u.get("baseline_country"),
                "baseline_mac": u.get("baseline_mac"),
                "baseline_device": u.get("baseline_device"),
                "name": u.get("name"),
                "department": u.get("department"),
            }
            for uid, u in users_blob.items()
        }
        if not policy:
            policy = OrgPolicy(
                org_id=org.id,
                allowed_countries=legacy.get("global_policy", {}).get(
                    "allowed_countries", ["India"]),
                risk_threshold=legacy.get("global_policy", {}).get("risk_threshold", 75),
                roles=roles,
                user_overrides=overrides,
            )
            db.add(policy)
        else:
            policy.allowed_countries = legacy.get("global_policy", {}).get(
                "allowed_countries", ["India"])
            policy.risk_threshold = legacy.get("global_policy", {}).get(
                "risk_threshold", 75)
            policy.roles = roles
            policy.user_overrides = overrides

        admin = (
            db.query(User)
            .filter(User.org_id == org.id, User.email == admin_email.lower())
            .first()
        )
        if not admin:
            admin = User(
                org_id=org.id,
                email=admin_email.lower(),
                password_hash=hash_password(admin_password),
                role="admin",
            )
            db.add(admin)
        db.commit()
        return {"org_id": org.id, "org_slug": org.slug, "admin_email": admin_email}
    finally:
        db.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin-email", default="admin@abccorp.com")
    ap.add_argument("--admin-password", default=None)
    args = ap.parse_args()
    pwd = args.admin_password or getpass.getpass("Admin password: ")
    print(seed(args.admin_email, pwd))
