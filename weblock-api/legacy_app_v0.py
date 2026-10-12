from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from dotenv import load_dotenv
import os

from database.connection import get_db
from models.login_schema import LoginRequest
from services.risk_engine import calculate_risk
from services.auth import verify_password, create_access_token

# ======================================
# INIT
# ======================================

load_dotenv()
app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
security = HTTPBearer()

# ======================================
# MODELS
# ======================================

class LoginAuthRequest(BaseModel):
    email: str
    password: str


class LogoutRequest(BaseModel):
    user_id: int


# ======================================
# AUTH DEPENDENCIES
# ======================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(allowed_roles: list):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Not authorized")
        return current_user
    return role_checker


# ======================================
# AUTHENTICATION
# ======================================

@app.post("/auth/login")
def login_user(payload: LoginAuthRequest, db: Session = Depends(get_db)):

    user = db.execute(text("""
        SELECT id, email, password_hash, role
        FROM users
        WHERE email = :email
    """), {"email": payload.email}).fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(payload.password, user[2]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({
        "user_id": user[0],
        "role": user[3]
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user[3]
    }


# ======================================
# HEALTH
# ======================================

@app.get("/")
def health_check():
    return {"status": "WebLock API Running"}


@app.get("/db-test")
def db_test(db: Session = Depends(get_db)):
    result = db.execute(text("SELECT 1")).fetchone()
    return {"database_connection": bool(result)}


# ======================================
# CORE ENGINE
# ======================================

@app.post("/analyze-login")
def analyze_login(payload: LoginRequest, db: Session = Depends(get_db)):

    try:
        # Check if blocked
        user_check = db.execute(
            text("SELECT is_blocked FROM users WHERE id = :user_id"),
            {"user_id": payload.user_id}
        ).fetchone()

        if not user_check:
            raise HTTPException(status_code=404, detail="User not found")

        if user_check[0]:
            raise HTTPException(status_code=403, detail="Account is blocked")

        risk_result = calculate_risk(db, payload)

        # Insert login event
        event_id = db.execute(text("""
            INSERT INTO login_events 
            (user_id, ip_address, mac_address, device_fingerprint,
             geo_location, risk_score, classification)
            VALUES 
            (:user_id, :ip_address, :mac_address, :device_fingerprint,
             :geo_location, :risk_score, :classification)
            RETURNING id
        """), {
            "user_id": payload.user_id,
            "ip_address": payload.ip_address,
            "mac_address": payload.mac_address,
            "device_fingerprint": payload.device_fingerprint,
            "geo_location": payload.geo_location,
            "risk_score": int(risk_result["risk_score"]),
            "classification": risk_result["classification"]
        }).scalar()

        # Insert risk assessment
        db.execute(text("""
            INSERT INTO risk_assessments
            (event_id, anomaly_score, model_confidence,
             explanation, model_version)
            VALUES
            (:event_id, :anomaly_score, :model_confidence,
             :explanation, :model_version)
        """), {
            "event_id": event_id,
            "anomaly_score": float(risk_result["risk_score"]),
            "model_confidence": float(risk_result.get("confidence", 1.0)),
            "explanation": risk_result["explanation"],
            "model_version": risk_result.get("model_version", "v3-rule-engine")
        })

        # =============================
        # Genuine → Session
        # =============================
        if risk_result["classification"] == "Genuine":
            db.execute(text("""
                INSERT INTO sessions (user_id, start_time, status)
                VALUES (:user_id, NOW(), 'active')
            """), {"user_id": payload.user_id})

        # =============================
        # Suspicious / Intruder
        # =============================
        if risk_result["classification"] in ["Suspicious", "Intruder"]:

            severity = "HIGH" if risk_result["classification"] == "Intruder" else "MEDIUM"

            # Immediate block if Intruder
            if risk_result["classification"] == "Intruder":
                db.execute(
                    text("UPDATE users SET is_blocked = TRUE WHERE id = :user_id"),
                    {"user_id": payload.user_id}
                )

            # Create incident
            incident_id = db.execute(text("""
                INSERT INTO incidents
                (user_id, event_id, severity, title, description, status)
                VALUES
                (:user_id, :event_id, :severity, :title, :description, 'open')
                RETURNING id
            """), {
                "user_id": payload.user_id,
                "event_id": event_id,
                "severity": severity,
                "title": f"{risk_result['classification']} Login Detected",
                "description": risk_result["explanation"]
            }).scalar()

            # Insert evidence
            db.execute(text("""
                INSERT INTO evidence_logs
                (incident_id, ip_address, mac_address,
                 device_fingerprint, geo_location,
                 risk_score, classification)
                VALUES
                (:incident_id, :ip_address, :mac_address,
                 :device_fingerprint, :geo_location,
                 :risk_score, :classification)
            """), {
                "incident_id": incident_id,
                "ip_address": payload.ip_address,
                "mac_address": payload.mac_address,
                "device_fingerprint": payload.device_fingerprint,
                "geo_location": payload.geo_location,
                "risk_score": risk_result["risk_score"],
                "classification": risk_result["classification"]
            })

            # ======================================
            # AUTO ESCALATION
            # 3 Suspicious in 5 minutes → Block
            # ======================================
            suspicious_count = db.execute(text("""
                SELECT COUNT(*)
                FROM login_events
                WHERE user_id = :user_id
                AND classification = 'Suspicious'
                AND created_at > NOW() - INTERVAL '5 minutes'
            """), {"user_id": payload.user_id}).scalar()

            if suspicious_count >= 3:
                db.execute(
                    text("UPDATE users SET is_blocked = TRUE WHERE id = :user_id"),
                    {"user_id": payload.user_id}
                )

        db.commit()

        return {
            "event_id": event_id,
            "risk_score": risk_result["risk_score"],
            "classification": risk_result["classification"],
            "confidence": risk_result.get("confidence", 1.0),
            "explanation": risk_result["explanation"]
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ======================================
# LOGOUT
# ======================================

@app.post("/logout")
def logout(payload: LogoutRequest, db: Session = Depends(get_db)):

    session = db.execute(text("""
        SELECT id FROM sessions
        WHERE user_id = :user_id AND status = 'active'
        ORDER BY id DESC LIMIT 1
    """), {"user_id": payload.user_id}).fetchone()

    if not session:
        raise HTTPException(status_code=404, detail="No active session found")

    db.execute(text("""
        UPDATE sessions
        SET end_time = NOW(), status = 'terminated'
        WHERE id = :id
    """), {"id": session[0]})

    db.commit()

    return {"message": "Session terminated"}


# ======================================
# ADMIN METRICS
# ======================================

@app.get("/admin/metrics")
def get_security_metrics(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role(["admin"]))
):

    return {
        "total_logins": db.execute(text("SELECT COUNT(*) FROM login_events")).scalar(),
        "intruder_attempts": db.execute(text("SELECT COUNT(*) FROM login_events WHERE classification='Intruder'")).scalar(),
        "suspicious_attempts": db.execute(text("SELECT COUNT(*) FROM login_events WHERE classification='Suspicious'")).scalar(),
        "active_sessions": db.execute(text("SELECT COUNT(*) FROM sessions WHERE status='active'")).scalar(),
        "open_incidents": db.execute(text("SELECT COUNT(*) FROM incidents WHERE status='open'")).scalar(),
        "blocked_users": db.execute(text("SELECT COUNT(*) FROM users WHERE is_blocked=TRUE")).scalar(),
    }


# ======================================
# ADMIN CONTROL
# ======================================

@app.post("/admin/unblock-user/{user_id}")
def unblock_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role(["admin"]))
):
    db.execute(text("UPDATE users SET is_blocked = FALSE WHERE id = :id"), {"id": user_id})
    db.commit()
    return {"message": f"User {user_id} unblocked"}