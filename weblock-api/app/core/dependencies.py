"""Auth dependencies: JWT verification, RBAC, org isolation. Server-side only."""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.database import get_db
from app.db.models import User

security = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    user = (
        db.query(User)
        .filter(User.id == payload.get("user_id"), User.org_id == payload.get("org_id"))
        .first()
    )
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="Account is blocked")
    return user


def require_role(*allowed_roles: str):
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Not authorized")
        return current_user

    return checker


def org_scoped_query(db: Session, model, user: User):
    """Helper: every org-owned query MUST filter org_id. Use this."""
    return db.query(model).filter(model.org_id == user.org_id)
