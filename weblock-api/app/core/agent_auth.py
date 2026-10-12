"""Agent credential auth — separate from human user JWT.

Agent keys look like `wlk_<32 hex>`; only sha256 is stored server-side.
Header: `Authorization: Bearer wlk_...`. The endpoint row carries org scope.
Revoked keys and revoked endpoints are rejected.
"""
import hashlib

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import AgentCredential, Endpoint

agent_scheme = HTTPBearer(auto_error=True)


def hash_agent_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def get_current_endpoint(
    credentials: HTTPAuthorizationCredentials = Depends(agent_scheme),
    db: Session = Depends(get_db),
) -> Endpoint:
    raw = credentials.credentials
    if not raw.startswith("wlk_"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid agent credential")
    cred = (
        db.query(AgentCredential)
        .filter(AgentCredential.key_hash == hash_agent_key(raw),
                AgentCredential.revoked.is_(False))
        .first()
    )
    if not cred:
        raise HTTPException(status_code=401, detail="Unknown or revoked agent key")
    endpoint = db.query(Endpoint).filter(Endpoint.id == cred.endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=401, detail="Endpoint not found")
    if endpoint.status == "revoked":
        raise HTTPException(status_code=401, detail="Endpoint revoked")
    return endpoint
