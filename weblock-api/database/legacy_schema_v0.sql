-- ===============================
-- WEBLOCK CORE DATABASE SCHEMA
-- ===============================

-- USERS TABLE
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    baseline_ip VARCHAR(45),
    baseline_mac VARCHAR(50),
    baseline_fingerprint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- LOGIN EVENTS
CREATE TABLE login_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    mac_address VARCHAR(50),
    device_fingerprint TEXT,
    geo_location TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER,
    classification VARCHAR(50)
);

-- SESSIONS
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status VARCHAR(50)
);

-- RISK ASSESSMENTS
CREATE TABLE risk_assessments (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES login_events(id) ON DELETE CASCADE,
    anomaly_score FLOAT,
    model_confidence FLOAT,
    explanation TEXT,
    model_version VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- FORENSIC REPORTS
CREATE TABLE forensic_reports (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES login_events(id) ON DELETE CASCADE,
    report_hash TEXT,
    report_path TEXT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- EVIDENCE LOGS
CREATE TABLE evidence_logs (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES login_events(id) ON DELETE CASCADE,
    evidence_type VARCHAR(100),
    evidence_value TEXT,
    evidence_hash TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ADMIN AUDIT LOGS
CREATE TABLE admin_audit_logs (
    id SERIAL PRIMARY KEY,
    admin_action TEXT,
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);