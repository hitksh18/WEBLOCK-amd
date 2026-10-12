"""Password hashing + JWT access/refresh tokens. Secrets from config only."""
import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _encode(payload: dict, secret: str, expires: timedelta) -> str:
    to_encode = payload.copy()
    # jti guarantees uniqueness even when two tokens are minted in the same
    # second (JWT exp has 1s resolution). Without it, refresh rotation can
    # produce an identical token string -> refresh_tokens_token_hash_key clash.
    to_encode.update(
        {"exp": datetime.now(timezone.utc) + expires, "jti": uuid.uuid4().hex}
    )
    return jwt.encode(to_encode, secret, algorithm=settings.JWT_ALGORITHM)


def create_access_token(data: dict) -> str:
    return _encode(
        {**data, "type": "access"},
        settings.JWT_SECRET_KEY,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(data: dict) -> str:
    return _encode(
        {**data, "type": "refresh"},
        settings.JWT_REFRESH_SECRET_KEY,
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError as exc:
        raise ValueError("Invalid or expired access token") from exc
    if payload.get("type") != "access":
        raise ValueError("Not an access token")
    return payload


def decode_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError as exc:
        raise ValueError("Invalid or expired refresh token") from exc
    if payload.get("type") != "refresh":
        raise ValueError("Not a refresh token")
    return payload
