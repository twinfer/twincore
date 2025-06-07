-- Security Management Queries

-- name: CreateSecurityTables
CREATE TABLE IF NOT EXISTS local_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    roles TEXT NOT NULL,
    email TEXT,
    name TEXT,
    disabled INTEGER DEFAULT 0 CHECK(disabled IN (0, 1)),
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS thing_security_policies (
    thing_id TEXT PRIMARY KEY,
    policy_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_credentials (
    credential_key TEXT PRIMARY KEY,
    credentials_data TEXT NOT NULL,
    encrypted INTEGER DEFAULT 1 CHECK(encrypted IN (0, 1)),
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_templates (
    name TEXT PRIMARY KEY,
    template_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    principal TEXT,
    resources TEXT,
    actions TEXT,
    conditions TEXT,
    enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id TEXT,
    thing_id TEXT,
    operation TEXT,
    resource TEXT,
    success INTEGER CHECK(success IN (0, 1)),
    error TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT
);

-- name: CreateSecurityIndexes
CREATE INDEX IF NOT EXISTS idx_users_email ON local_users(email);
CREATE INDEX IF NOT EXISTS idx_users_updated ON local_users(updated_at);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON user_sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON api_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON security_audit_events(user_id);

-- User Management Queries
-- name: CreateUser
INSERT INTO local_users (username, password_hash, roles, email, name, disabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- name: GetUser
SELECT username, password_hash, roles, email, name, disabled, last_login, created_at, updated_at
FROM local_users
WHERE username = ?;

-- name: GetUserForAuth
SELECT username, password_hash, roles, disabled
FROM local_users
WHERE username = ? AND disabled = 0;

-- name: UpdateUser
UPDATE local_users
SET password_hash = ?, roles = ?, email = ?, name = ?, disabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE username = ?;

-- name: UpdateUserLastLogin
UPDATE local_users
SET last_login = CURRENT_TIMESTAMP
WHERE username = ?;

-- name: DeleteUser
DELETE FROM local_users WHERE username = ?;

-- name: ListUsers
SELECT username, roles, email, name, disabled, last_login, created_at, updated_at
FROM local_users
ORDER BY created_at DESC;

-- name: CountUsers
SELECT COUNT(*) FROM local_users;

-- name: UserExists
SELECT EXISTS(SELECT 1 FROM local_users WHERE username = ?);

-- Session Management Queries
-- name: CreateSession
INSERT INTO user_sessions (id, user_id, username, token, refresh_token, expires_at, created_at, last_activity, ip_address, user_agent)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?);

-- name: GetSession
SELECT id, user_id, username, token, refresh_token, expires_at, created_at, last_activity, ip_address, user_agent
FROM user_sessions
WHERE id = ? AND expires_at > CURRENT_TIMESTAMP;

-- name: GetSessionByToken
SELECT id, user_id, username, token, refresh_token, expires_at, created_at, last_activity, ip_address, user_agent
FROM user_sessions
WHERE token = ? AND expires_at > CURRENT_TIMESTAMP;

-- name: UpdateSessionActivity
UPDATE user_sessions
SET last_activity = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteSession
DELETE FROM user_sessions WHERE id = ?;

-- name: DeleteExpiredSessions
DELETE FROM user_sessions WHERE expires_at <= CURRENT_TIMESTAMP;

-- name: DeleteUserSessions
DELETE FROM user_sessions WHERE username = ?;

-- Security Policy Queries
-- name: CreateThingSecurityPolicy
INSERT INTO thing_security_policies (thing_id, policy_data, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(thing_id) DO UPDATE SET
    policy_data = excluded.policy_data,
    updated_at = excluded.updated_at;

-- name: GetThingSecurityPolicy
SELECT thing_id, policy_data, created_at, updated_at
FROM thing_security_policies
WHERE thing_id = ?;

-- name: DeleteThingSecurityPolicy
DELETE FROM thing_security_policies WHERE thing_id = ?;

-- API Policy Queries
-- name: CreateAPIPolicy
INSERT INTO api_policies (id, name, description, principal, resources, actions, conditions, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- name: GetAPIPolicy
SELECT id, name, description, principal, resources, actions, conditions, enabled, created_at, updated_at
FROM api_policies
WHERE id = ?;

-- name: ListEnabledAPIPolicies
SELECT id, name, description, principal, resources, actions, conditions, enabled, created_at, updated_at
FROM api_policies
WHERE enabled = 1
ORDER BY name;

-- name: UpdateAPIPolicy
UPDATE api_policies
SET name = ?, description = ?, principal = ?, resources = ?, actions = ?, conditions = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteAPIPolicy
DELETE FROM api_policies WHERE id = ?;

-- Audit Log Queries
-- name: CreateAuditEvent
INSERT INTO security_audit_events (id, event_type, timestamp, user_id, thing_id, operation, resource, success, error, ip_address, user_agent, details)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuditEvents
SELECT id, event_type, timestamp, user_id, thing_id, operation, resource, success, error, ip_address, user_agent, details
FROM security_audit_events
WHERE timestamp >= ? AND timestamp <= ?
ORDER BY timestamp DESC
LIMIT ?;

-- name: GetUserAuditEvents
SELECT id, event_type, timestamp, user_id, thing_id, operation, resource, success, error, ip_address, user_agent, details
FROM security_audit_events
WHERE user_id = ? AND timestamp >= ?
ORDER BY timestamp DESC
LIMIT ?;

-- name: DeleteOldAuditEvents
DELETE FROM security_audit_events WHERE timestamp < ?;

-- Device Credentials Queries
-- name: GetDeviceCredentials
SELECT credential_key, credentials_data, encrypted, expires_at, created_at, updated_at
FROM device_credentials
WHERE credential_key = ?;

-- name: SetDeviceCredentials
INSERT INTO device_credentials (credential_key, credentials_data, encrypted, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(credential_key) DO UPDATE SET
    credentials_data = excluded.credentials_data,
    encrypted = excluded.encrypted,
    expires_at = excluded.expires_at,
    updated_at = excluded.updated_at;

-- name: DeleteDeviceCredentials
DELETE FROM device_credentials WHERE credential_key = ?;

-- Security Template Queries
-- name: GetSecurityTemplate
SELECT name, template_data, created_at, updated_at
FROM security_templates
WHERE name = ?;

-- name: SetSecurityTemplate
INSERT INTO security_templates (name, template_data, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(name) DO UPDATE SET
    template_data = excluded.template_data,
    updated_at = excluded.updated_at;

-- name: ListSecurityTemplates
SELECT name, template_data, created_at, updated_at
FROM security_templates
ORDER BY name;

-- name: DeleteSecurityTemplate
DELETE FROM security_templates WHERE name = ?;