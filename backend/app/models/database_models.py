"""SQLite schema shared by startup initialization and standalone SQL tooling."""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Admin', 'Analyst', 'User')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_id_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_hash TEXT NOT NULL,
    attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_client_time
    ON auth_login_attempts(client_hash, attempted_at);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id
    ON password_reset_tokens(user_id, expires_at);
CREATE TABLE IF NOT EXISTS analysis_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL CHECK (module IN ('network', 'phishing')),
    prediction TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    confidence_level TEXT NOT NULL CHECK (confidence_level IN ('low', 'medium', 'high')),
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT CHECK (severity IN ('VERY_LOW', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    model_name TEXT,
    model_version TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_analysis_history_created_at ON analysis_history(created_at DESC);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL,
    host TEXT,
    user TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_port INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    protocol TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    message TEXT,
    raw_event TEXT NOT NULL,
    metadata TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_type_timestamp ON events(source_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity_timestamp ON events(severity, timestamp DESC);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_id INTEGER UNIQUE REFERENCES analysis_history(id) ON DELETE SET NULL,
    owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    module TEXT NOT NULL CHECK (module IN ('network', 'phishing')),
    prediction TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT NOT NULL CHECK (severity IN ('HIGH', 'CRITICAL')),
    status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_incidents_owner_status
    ON incidents(owner_user_id, status, created_at DESC);
CREATE TABLE IF NOT EXISTS incident_status_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    previous_status TEXT CHECK (previous_status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    new_status TEXT NOT NULL CHECK (new_status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_incident_status_events_incident
    ON incident_status_events(incident_id, id);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_id INTEGER REFERENCES analysis_history(id) ON DELETE SET NULL,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    module TEXT NOT NULL CHECK (module IN ('network', 'phishing')),
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN (
        'NEW', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED', 'CLOSED')),
    assignee_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created
    ON alerts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_assignee
    ON alerts(assignee_user_id, status);
CREATE TABLE IF NOT EXISTS alert_status_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    previous_status TEXT CHECK (previous_status IN (
        'NEW', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED', 'CLOSED')),
    new_status TEXT NOT NULL CHECK (new_status IN (
        'NEW', 'INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED', 'CLOSED')),
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_alert_status_events_alert
    ON alert_status_events(alert_id, id);
CREATE TABLE IF NOT EXISTS alert_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_alert_comments_alert
    ON alert_comments(alert_id, id);
CREATE TABLE IF NOT EXISTS alert_tags (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (alert_id, tag)
);
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'hash', 'email')),
    value TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    source TEXT,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
    expires_at TEXT,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status, severity);
CREATE TABLE IF NOT EXISTS ioc_tags (
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (ioc_id, tag)
);
CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    module TEXT NOT NULL CHECK (module IN ('network', 'phishing', 'any')),
    min_severity TEXT NOT NULL CHECK (min_severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
    threshold INTEGER NOT NULL CHECK (threshold BETWEEN 2 AND 100),
    window_minutes INTEGER NOT NULL CHECK (window_minutes BETWEEN 1 AND 1440),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_detection_rules_active ON detection_rules(is_active);
CREATE TABLE IF NOT EXISTS correlation_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    alert_count INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'CLOSED')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_correlation_findings_rule
    ON correlation_findings(rule_id, created_at DESC);
CREATE TABLE IF NOT EXISTS correlation_finding_alerts (
    finding_id INTEGER NOT NULL REFERENCES correlation_findings(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, alert_id)
);
CREATE TABLE IF NOT EXISTS model_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    history_id INTEGER REFERENCES analysis_history(id) ON DELETE SET NULL,
    module TEXT NOT NULL CHECK (module IN ('network', 'phishing')),
    model_name TEXT,
    model_version TEXT,
    verdict TEXT NOT NULL CHECK (verdict IN ('false_positive', 'confirmed')),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_model_feedback_model
    ON model_feedback(model_name, model_version);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'webhook')),
    delivery_status TEXT NOT NULL DEFAULT 'not_configured'
        CHECK (delivery_status IN ('not_configured', 'sent', 'failed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    module TEXT NOT NULL CHECK (module IN ('network', 'phishing', 'any')),
    min_severity TEXT NOT NULL CHECK (min_severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS playbook_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    instruction TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_playbook_steps ON playbook_steps(playbook_id, position);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    action TEXT NOT NULL CHECK (action IN (
        'auth.registered',
        'auth.login.succeeded',
        'auth.login.failed',
        'auth.login.rate_limited',
        'auth.logout',
        'user.provisioned',
        'user.role_changed',
        'user.activated',
        'user.deactivated',
        'user.deleted',
        'user.password_reset',
        'incident.status_changed',
        'alert.status_changed',
        'alert.assigned',
        'alert.comment_added',
        'alert.tag_added',
        'alert.tag_removed',
        'ioc.created',
        'ioc.updated',
        'ioc.deleted',
        'ioc.tag_added',
        'ioc.tag_removed',
        'rule.created',
        'rule.updated',
        'rule.deleted',
        'correlation.run',
        'notification.dispatch',
        'playbook.created',
        'playbook.updated',
        'playbook.deleted'
    )),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    target_type TEXT CHECK (target_type IN (
        'auth', 'user', 'incident', 'alert', 'ioc', 'rule', 'playbook')),
    target_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor
    ON audit_events(actor_user_id, created_at DESC);
CREATE TRIGGER IF NOT EXISTS audit_events_prevent_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
CREATE TRIGGER IF NOT EXISTS audit_events_prevent_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
"""