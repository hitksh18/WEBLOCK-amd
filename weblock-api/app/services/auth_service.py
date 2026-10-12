"""Auth service: login / refresh / logout with rate limiting + audit.

Rate limiting is in-memory per (IP, email) — sufficient for Phase 0 single
instance. Replace with Redis in Phase 1 for multi-replica deployments.
"""
import hashlib
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    verify_password,
)
from app.core.timeutil import as_utc
from app.db.models import AuditLog, RefreshToken, User

logger = logging.getLogger("weblock.auth")

# (ip, email) -> deque[timestamps]
_attempts: defaultdict[tuple[str, str], deque] = defaultdict(deque)


def _rate_key(ip: str, email: str) -> tuple[str, str]:
    return (ip, email.lower())


def check_rate_limit(ip: str, email: str) -> None:
    from fastapi import HTTPException

    window = settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS
    max_attempts = settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS
    now = time.time()
    dq = _attempts[_rate_key(ip, email)]
    while dq and now - dq[0] > window:
        dq.popleft()
    if len(dq) >= max_attempts:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
        )


def record_failed_attempt(ip: str, email: str) -> None:
    _attempts[_rate_key(ip, email)].append(time.time())


def clear_attempts(ip: str, email: str) -> None:
    _attempts.pop(_rate_key(ip, email), None)


def _audit(db: Session, org_id: int | None, actor_id: int | None, action: str,
           target: str | None = None, meta: dict | None = None) -> None:
    db.add(AuditLog(org_id=org_id, actor_id=actor_id, action=action,
                    target=target, meta_data=meta or {}))


def authenticate(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email.lower()).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def issue_tokens(db: Session, user: User) -> tuple[str, str]:
    access = create_access_token(
        {"user_id": user.id, "org_id": user.org_id, "role": user.role}
    )
    refresh = create_refresh_token({"user_id": user.id, "org_id": user.org_id})
    token_hash = hashlib.sha256(refresh.encode()).hexdigest()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )
    db.commit()
    return access, refresh


def login_flow(db: Session, email: str, password: str, client_ip: str) -> dict:
    from fastapi import HTTPException

    check_rate_limit(client_ip, email)
    user = authenticate(db, email, password)
    if not user:
        record_failed_attempt(client_ip, email)
        _audit(db, None, None, "auth.login.failed", target=email,
               meta={"ip": client_ip})
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.is_blocked:
        record_failed_attempt(client_ip, email)
        raise HTTPException(status_code=403, detail="Account is blocked")
    clear_attempts(client_ip, email)
    access, refresh = issue_tokens(db, user)
    _audit(db, user.org_id, user.id, "auth.login", target=email,
           meta={"ip": client_ip})
    db.commit()
    logger.info("login ok user_id=%s org_id=%s", user.id, user.org_id)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "role": user.role,
        "org_id": user.org_id,
    }


def refresh_flow(db: Session, refresh_token: str) -> dict:
    from fastapi import HTTPException

    try:
        payload = decode_refresh_token(refresh_token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash,
                RefreshToken.revoked.is_(False))
        .first()
    )
    if not stored:
        raise HTTPException(status_code=401, detail="Refresh token revoked")
    if as_utc(stored.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user or user.is_blocked:
        raise HTTPException(status_code=401, detail="User unavailable")
    # Rotate: revoke old, issue new pair
    stored.revoked = True
    access = create_access_token(
        {"user_id": user.id, "org_id": user.org_id, "role": user.role}
    )
    new_refresh = create_refresh_token({"user_id": user.id, "org_id": user.org_id})
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hashlib.sha256(new_refresh.encode()).hexdigest(),
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )
    _audit(db, user.org_id, user.id, "auth.refresh")
    db.commit()
    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "role": user.role,
        "org_id": user.org_id,
    }


def logout_flow(db: Session, refresh_token: str, user: User) -> None:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    stored = (
        db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    )
    if stored and stored.user_id == user.id:
        stored.revoked = True
    _audit(db, user.org_id, user.id, "auth.logout")
    db.commit()
